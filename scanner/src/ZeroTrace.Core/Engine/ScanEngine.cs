using ZeroTrace.Core.Data;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Modules;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Engine;

/// <summary>
/// Builds the active module set from the options, runs them sequentially while
/// reporting weighted progress, and returns a complete report. Sequential
/// execution keeps disk/IO load predictable and progress meaningful.
/// </summary>
public sealed class ScanEngine
{
    private readonly IndicatorMatcher _matcher;
    private readonly HashWhitelistStore? _whitelist;

    public ScanEngine(IndicatorMatcher matcher, HashWhitelistStore? whitelist = null)
    {
        _matcher = matcher;
        _whitelist = whitelist;
    }

    public Task<ScanReport> RunAsync(
        ScanOptions options,
        IProgress<ScanProgress>? progress,
        CancellationToken ct)
        => RunAsync(options, progress, null, ct);

    /// <summary>
    /// Runs the module pipeline. Each module is isolated: if one module throws,
    /// it is recorded as a low-risk note and the scan continues with the rest, so
    /// a single flaky module can no longer abort the whole scan. Only a
    /// cancellation aborts the run. An optional callback receives findings live.
    /// </summary>
    public async Task<ScanReport> RunAsync(
        ScanOptions options,
        IProgress<ScanProgress>? progress,
        Action<Finding>? onFinding,
        CancellationToken ct)
    {
        var modules = BuildModules(options);
        var context = new ScanContext(options, _matcher, progress);
        if (onFinding is not null) context.FindingAdded += onFinding;

        var report = new ScanReport
        {
            StartedUtc = DateTime.UtcNow,
            Elevated = PrivilegeChecker.IsElevated(),
            Profile = options.Profile,
            System = SystemInfo.Capture(),
            Inventory = options.ScanInventory ? HostInventoryCollector.Collect() : new()
        };
        // Share the inventory with modules so they can append data
        // (e.g. DiscordScanModule writes Inventory.DiscordGuilds).
        context.Inventory = report.Inventory;

        progress?.Report(new ScanProgress
        {
            Phase = ScanPhase.Initializing,
            Message = $"{modules.Count} Module werden ausgefuehrt",
            Percent = 0
        });

        HashUtil.ClearCache();
        SignatureChecker.ClearCache();

        // Boost the scanner process to High priority for the duration of the
        // scan: lets I/O-bound modules get CPU time when the system is busy
        // (game running in background, AC services contesting). This is the
        // same trick Ocean/detect.ac use to keep scans fast without throttling.
        // We restore the original priority in finally so we never leave the
        // scanner running at High when the user exits.
        System.Diagnostics.ProcessPriorityClass? originalPriority = null;
        try
        {
            using var self = System.Diagnostics.Process.GetCurrentProcess();
            originalPriority = self.PriorityClass;
            if (originalPriority != System.Diagnostics.ProcessPriorityClass.High &&
                originalPriority != System.Diagnostics.ProcessPriorityClass.RealTime)
            {
                self.PriorityClass = System.Diagnostics.ProcessPriorityClass.High;
            }
        }
        catch { /* priority set may fail without elevation — ignore */ }

        double totalWeight = modules.Sum(m => m.Weight);
        double consumed = 0;

        try
        {
            // Group sequential (group 0) modules into solo phases and
            // parallel-group modules (group > 0) into bursts that run with
            // bounded concurrency. Order within the original list is kept.
            var phases = BuildPhases(modules);

            foreach (var phase in phases)
            {
                ct.ThrowIfCancellationRequested();
                if (phase.Count == 1)
                {
                    var m = phase[0];
                    context.ModuleBaseline = totalWeight <= 0 ? 0 : consumed / totalWeight;
                    context.ModuleSpan = totalWeight <= 0 ? 1 : m.Weight / totalWeight;
                    await RunModuleAsync(m, context, options, ct).ConfigureAwait(false);
                    consumed += m.Weight;
                }
                else
                {
                    // Parallel burst: every module in this burst shares the
                    // same progress baseline and span (the burst as a whole).
                    // The Findings list is locked inside AddFinding, so the
                    // concurrent emit path is already safe.
                    var phaseWeight = phase.Sum(m => m.Weight);
                    context.ModuleBaseline = totalWeight <= 0 ? 0 : consumed / totalWeight;
                    context.ModuleSpan = totalWeight <= 0 ? 1 : phaseWeight / totalWeight;
                    context.Report(0, $"Parallel: {string.Join(", ", phase.Select(m => m.Name))}");

                    // Most modules are I/O-bound (registry, file reads, P/Invoke into kernel
                    // queries). 3× ProcessorCount keeps CPUs fed during I/O waits — matches
                    // the parallelism Ocean/detect.ac use for fast scan completion. The cap
                    // ensures even an 8-module phase on a 4-core machine runs all 8 at once
                    // (no queueing), since most are blocked on registry/file I/O anyway.
                    var concurrency = Math.Min(phase.Count, Environment.ProcessorCount * 3);
                    using var sem = new SemaphoreSlim(concurrency);
                    var tasks = phase.Select(m => RunOneInParallelAsync(
                        m, context, options, sem, ct)).ToArray();
                    await Task.WhenAll(tasks).ConfigureAwait(false);

                    consumed += phaseWeight;
                }
            }
            report.Result = ScanPhase.Completed;
        }
        catch (OperationCanceledException)
        {
            report.Result = ScanPhase.Cancelled;
        }
        catch (Exception ex)
        {
            report.Result = ScanPhase.Failed;
            context.AddFinding(new Finding
            {
                Module = "Engine",
                Title = "Scan-Fehler",
                Risk = RiskLevel.Low,
                Location = "intern",
                Reason = "Unerwarteter Fehler in der Scan-Engine: " + ex.Message
            });
        }

        // Restore the original process priority so the host doesn't stay at High.
        if (originalPriority.HasValue)
        {
            try
            {
                using var self = System.Diagnostics.Process.GetCurrentProcess();
                if (self.PriorityClass != originalPriority.Value)
                    self.PriorityClass = originalPriority.Value;
            }
            catch { }
        }

        // Release cached process handles held in the snapshot for the duration
        // of the scan. Prevents handle exhaustion across many back-to-back scans.
        context.DisposeProcessSnapshot();

        report.FinishedUtc = DateTime.UtcNow;
        report.FilesScanned = context.FilesScanned;
        report.ProcessesScanned = context.ProcessesScanned;
        report.RegistryKeysScanned = context.RegistryKeysScanned;

        // Filter out any findings whose file hash is on the admin whitelist.
        var allFindings = context.Findings;
        if (_whitelist is not null)
        {
            allFindings = allFindings
                .Where(f => f.Sha256 is null || !_whitelist.IsWhitelisted(f.Sha256))
                .ToList();
        }
        report.Findings = allFindings.OrderByDescending(f => f.Risk).ToList();

        progress?.Report(new ScanProgress
        {
            Phase = report.Result,
            Percent = 100,
            Message = "Scan beendet",
            FilesScanned = report.FilesScanned,
            ProcessesScanned = report.ProcessesScanned,
            RegistryKeysScanned = report.RegistryKeysScanned,
            FindingsCount = report.Findings.Count
        });

        return report;
    }

    /// <summary>
    /// Pack consecutive parallel-group modules into one burst. Mixed phases
    /// or sequential (group 0) modules each become their own one-item phase
    /// so order and progress reporting stay predictable.
    /// </summary>
    private static List<List<IScanModule>> BuildPhases(List<IScanModule> modules)
    {
        var phases = new List<List<IScanModule>>();
        var current = new List<IScanModule>();
        int currentGroup = -1;

        foreach (var m in modules)
        {
            var g = m.ParallelGroup;
            if (g == 0)
            {
                if (current.Count > 0) { phases.Add(current); current = new(); currentGroup = -1; }
                phases.Add(new List<IScanModule> { m });
            }
            else
            {
                if (g != currentGroup && current.Count > 0)
                {
                    phases.Add(current);
                    current = new();
                }
                currentGroup = g;
                current.Add(m);
            }
        }
        if (current.Count > 0) phases.Add(current);
        return phases;
    }

    /// <summary>
    /// Run a single module with its own time budget and isolated error
    /// handling. Caller is responsible for setting
    /// <c>ScanContext.ModuleBaseline</c> and <c>ScanContext.ModuleSpan</c>
    /// before the run.
    /// </summary>
    private static async Task RunModuleAsync(
        IScanModule module,
        ScanContext context,
        ScanOptions options,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        context.CurrentModule = module.Name;

        context.Report(0, $"Starte Modul: {module.Name}");

        using var moduleCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (options.ModuleTimeoutSeconds > 0)
            moduleCts.CancelAfter(TimeSpan.FromSeconds(options.ModuleTimeoutSeconds));

        try
        {
            await module.RunAsync(context, moduleCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            context.AddFinding(new Finding
            {
                Module = module.Name,
                Title = "Modul uebersprungen (Zeitueberschreitung)",
                Risk = RiskLevel.Low,
                Location = "intern",
                Reason = $"Modul '{module.Name}' hat das Zeitlimit von " +
                         $"{options.ModuleTimeoutSeconds}s ueberschritten und wurde uebersprungen."
            });
        }
        catch (Exception ex)
        {
            context.AddFinding(new Finding
            {
                Module = module.Name,
                Title = "Modul uebersprungen (Fehler)",
                Risk = RiskLevel.Low,
                Location = "intern",
                Reason = $"Modul '{module.Name}' wurde wegen eines Fehlers uebersprungen: {ex.Message}"
            });
        }
        context.Report(1, $"Modul abgeschlossen: {module.Name}");
    }

    private static async Task RunOneInParallelAsync(
        IScanModule module,
        ScanContext context,
        ScanOptions options,
        SemaphoreSlim sem,
        CancellationToken ct)
    {
        await sem.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await RunModuleAsync(module, context, options, ct).ConfigureAwait(false);
        }
        finally
        {
            sem.Release();
        }
    }

    private static List<IScanModule> BuildModules(ScanOptions o)
    {
        var modules = new List<IScanModule>();

        // ── Group 2: fast OS-state reads ─────────────────────────────────────
        // Consecutive same-group entries are batched into one parallel burst.
        if (o.ScanAntiAnalysis) modules.Add(new AntiAnalysisScanModule());
        if (o.ScanProcesses) modules.Add(new ProcessScanModule());
        if (o.ScanAutostart) modules.Add(new AutostartScanModule());
        if (o.ScanOverlay) modules.Add(new OverlayScanModule());
        if (o.ScanVirtualMachine) modules.Add(new VirtualMachineScanModule());
        if (o.ScanHypervisor) modules.Add(new HypervisorDetectionScanModule());
        if (o.ScanDmaRisk) modules.Add(new DmaRiskScanModule());
        if (o.ScanNetwork) modules.Add(new NetworkScanModule());
        if (o.ScanNamedResources) modules.Add(new NamedResourceScanModule());
        if (o.ScanSyscallHooks) modules.Add(new SyscallHookScanModule());
        if (o.ScanIatHooks) modules.Add(new IatHookScanModule());
        if (o.ScanDkom) modules.Add(new DkomScanModule());
        if (o.ScanHandles) modules.Add(new HandleScanModule());
        if (o.ScanTokenPrivileges) modules.Add(new TokenPrivilegeScanModule());
        if (o.ScanAntiDebugEvasion) modules.Add(new AntiDebugEvasionScanModule());
        if (o.ScanLoadedKernelModules) modules.Add(new LoadedKernelModuleScanModule());
        if (o.ScanNamedPipes) modules.Add(new NamedPipeScanModule());
        if (o.ScanMemoryMappedFiles) modules.Add(new MemoryMappedFileScanModule());
        if (o.ScanAntiCheatStatus) modules.Add(new AntiCheatStatusScanModule());
        if (o.ScanCryptoMiner) modules.Add(new CryptoMinerScanModule());
        if (o.ScanRemoteAccessTools) modules.Add(new RemoteAccessToolScanModule());
        if (o.ScanKernelObjects) modules.Add(new KernelObjectEnumScanModule());
        if (o.ScanGpuProcesses) modules.Add(new GpuProcessMemoryScanModule());
        if (o.ScanProtectedProcesses) modules.Add(new ProtectedProcessScanModule());
        if (o.ScanAtomBombing) modules.Add(new AtomBombingDetectionScanModule());
        if (o.ScanProcessDoppelganging) modules.Add(new ProcessDoppelgangingScanModule());
        if (o.ScanPpidSpoofing) modules.Add(new PpidSpoofingDetectionScanModule());
        if (o.ScanExternalOverlay) modules.Add(new ExternalOverlayDetectionScanModule());
        if (o.ScanAcBypassTools) modules.Add(new AntiCheatBypassToolsScanModule());
        if (o.ScanSuspiciousChildProcesses) modules.Add(new SuspiciousChildProcessScanModule());
        if (o.ScanGameMemoryReadAccess) modules.Add(new GameMemoryReadAccessScanModule());
        if (o.ScanScreenCaptureBlocking) modules.Add(new ScreenCaptureBlockingScanModule());
        if (o.ScanKernelPoolTags) modules.Add(new KernelPoolTagForensicScanModule());
        if (o.ScanJobObjectRestrictions) modules.Add(new ProcessJobObjectScanModule());
        if (o.ScanDeletedProcessBinary) modules.Add(new DeletedProcessBinaryScanModule());
        if (o.ScanNetworkGameServerSnoop) modules.Add(new NetworkGameServerSnoopScanModule());
        if (o.ScanLoopbackListeners) modules.Add(new SuspiciousLoopbackListenerScanModule());
        if (o.ScanSeDebugPrivilege) modules.Add(new SeDebugPrivilegeActiveScanModule());
        if (o.ScanProcessMitigations) modules.Add(new ProcessMitigationAnomalyScanModule());
        if (o.ScanKnownCheatMutexExt) modules.Add(new KnownCheatMutexExtScanModule());
        if (o.ScanGlobalInputHooks) modules.Add(new GlobalKeyboardMouseHookScanModule());
        if (o.ScanDnsCacheExtended) modules.Add(new DnsClientCacheExtendedScanModule());
        if (o.ScanActiveCheatConnections) modules.Add(new ActiveCheatConnectionScanModule());
        if (o.ScanNamedPipeCheatIpc) modules.Add(new NamedPipeCheatIpcScanModule());
        if (o.ScanSleepMasking) modules.Add(new SleepMaskingDetectionScanModule());
        if (o.ScanDxVtableHooks) modules.Add(new DirectXVtableHookScanModule());
        if (o.ScanAcPriorityAbuse) modules.Add(new AntiCheatProcessPriorityAbuseScanModule());
        if (o.ScanSuspendedAcThreads) modules.Add(new SuspendedAntiCheatThreadScanModule());
        if (o.ScanPebLdrInconsistency) modules.Add(new PebLdrInconsistencyScanModule());
        if (o.ScanDirectInputVtableHooks) modules.Add(new DirectInputVtableHookScanModule());
        if (o.ScanHwndCheatWindows) modules.Add(new HwndCheatWindowScanModule());
        if (o.ScanHandleInheritance) modules.Add(new ProcessHandleInheritanceScanModule());

        // ── Group 3: registry / WMI / driver queries ──────────────────────────
        if (o.ScanRegistry) modules.Add(new RegistryScanModule());
        if (o.ScanAvExclusions) modules.Add(new WindowsDefenderExclusionScanModule());
        if (o.ScanEventLogTamper) modules.Add(new EventLogTamperScanModule());
        if (o.ScanHwidSpoofer) modules.Add(new HwidSpooferScanModule());
        if (o.ScanPacketCapture) modules.Add(new PacketCaptureScanModule());
        if (o.ScanFirewallRules) modules.Add(new FirewallRuleScanModule());
        if (o.ScanVolumeShadow) modules.Add(new VolumeShadowScanModule());
        if (o.ScanComHijack) modules.Add(new ComHijackScanModule());
        if (o.ScanDnsHistory) modules.Add(new DnsHistoryScanModule());
        if (o.ScanEnvironmentVariables) modules.Add(new EnvironmentVariableScanModule());
        if (o.ScanRegistryRunHistory) modules.Add(new RegistryRunHistoryScanModule());
        if (o.ScanBootConfig) modules.Add(new BootConfigScanModule());
        if (o.ScanSuspiciousServices) modules.Add(new SuspiciousServiceScanModule());
        if (o.ScanNetworkConnections) modules.Add(new NetworkConnectionScanModule());
        if (o.ScanAppInitDlls) modules.Add(new AppInitDllScanModule());
        if (o.ScanLsaPlugins) modules.Add(new LsaPluginScanModule());
        if (o.ScanPrintSpoolerPersistence) modules.Add(new PrintSpoolerPersistenceScanModule());
        if (o.ScanAppCompatShims) modules.Add(new AppCompatShimScanModule());
        if (o.ScanSipProviders) modules.Add(new SipProviderScanModule());
        if (o.ScanImageFileExecutionOptions) modules.Add(new ImageFileExecutionOptionsScanModule());
        if (o.ScanKnownDllsHijack) modules.Add(new KnownDllsHijackScanModule());
        if (o.ScanWinlogonHijack) modules.Add(new WinlogonHijackScanModule());
        if (o.ScanSvcHostGroups) modules.Add(new SvcHostGroupScanModule());
        if (o.ScanWmiSubscriptionDeep) modules.Add(new WmiSubscriptionDeepScanModule());
        if (o.ScanFileAssociationHijack) modules.Add(new FileAssociationHijackScanModule());
        if (o.ScanUdpSockets) modules.Add(new UdpSocketScanModule());
        if (o.ScanRegistryHijack) modules.Add(new RegistryHijackScanModule());
        if (o.ScanElamDriver) modules.Add(new ElamDriverScanModule());
        if (o.ScanNetworkShares) modules.Add(new NetworkShareEnumScanModule());
        if (o.ScanDllLoadOrderHijack) modules.Add(new DllLoadOrderHijackScanModule());
        if (o.ScanPowerShellSecurity) modules.Add(new PowerShellConstrainedLanguageScanModule());
        if (o.ScanVbsHvci) modules.Add(new VirtualizationBasedSecurityScanModule());
        if (o.ScanWerFaultHijack) modules.Add(new WerFaultHijackScanModule());
        if (o.ScanWindowsDefenderTamper) modules.Add(new WindowsDefenderTamperScanModule());
        if (o.ScanCodeSigningBypass) modules.Add(new CodeSigningBypassScanModule());
        if (o.ScanDnsConfiguration) modules.Add(new DnsOverHttpsScanModule());
        if (o.ScanRpcEndpoints) modules.Add(new RpcEndpointScanModule());
        if (o.ScanRegistryTimestamps) modules.Add(new RegistryKeyTimestampScanModule());
        if (o.ScanLspProviders) modules.Add(new LspProviderScanModule());
        if (o.ScanCorProfilerInjection) modules.Add(new CorProfilerInjectionScanModule());
        if (o.ScanInputDeviceFilter) modules.Add(new InputDeviceFilterScanModule());
        if (o.ScanUacBypassArtifacts) modules.Add(new UacBypassArtifactScanModule());
        if (o.ScanAntiCheatServiceIntegrity) modules.Add(new AntiCheatServiceIntegrityScanModule());
        if (o.ScanVulkanLayerInjection) modules.Add(new VulkanLayerInjectionScanModule());
        if (o.ScanProcessCommandLines) modules.Add(new ProcessCommandLineScanModule());
        if (o.ScanDirectXDebugLayer) modules.Add(new DirectXDebugLayerScanModule());
        if (o.ScanAvExclusionActivePaths) modules.Add(new AvExclusionActivePathScanModule());
        if (o.ScanWfpFilters) modules.Add(new WfpFilterScanModule());
        if (o.ScanCryptoApiProviders) modules.Add(new CryptoApiProviderScanModule());
        if (o.ScanHkcuAppInitDlls) modules.Add(new HkcuAppInitDllsScanModule());
        if (o.ScanCompatibilityLayerBypass) modules.Add(new CompatibilityLayerBypassScanModule());
        if (o.ScanCheatToolRegistryArtifacts) modules.Add(new CheatToolRegistryArtifactsScanModule());
        if (o.ScanAimAssistHardware) modules.Add(new CronusZenXimAimAssistScanModule());
        if (o.ScanDseBypass) modules.Add(new DriverSignatureEnforcementScanModule());
        if (o.ScanWifiHistory) modules.Add(new WiFiNetworkHistoryScanModule());
        if (o.ScanVirtualAudioDevices) modules.Add(new VirtualAudioDeviceScanModule());
        if (o.ScanGpuComputeCheat) modules.Add(new GpuComputeCheatProcessScanModule());
        if (o.ScanAfterburnerRtss) modules.Add(new MSIAfterburnerRTSSScanModule());
        if (o.ScanCheatTools) modules.Add(new GameBoosterCheatToolScanModule());
        if (o.ScanNetworkCheatSetup) modules.Add(new NetworkShareCheatScanModule());
        if (o.ScanVmHypervisor) modules.Add(new VmwareParavirtCheatScanModule());
        if (o.ScanEventLogCheat) modules.Add(new WindowsEventLogCheatScanModule());
        if (o.ScanAntiDebugTools) modules.Add(new AntiDebugBypassScanModule());
        if (o.ScanSpecialKReShade) modules.Add(new SpecialKModScanModule());
        if (o.ScanFpsUnlockerExploits) modules.Add(new FpsUnlockerCheatScanModule());
        if (o.ScanAcServiceTamper) modules.Add(new AnticheatServiceTamperScanModule());
        if (o.ScanShadowCopyState) modules.Add(new ShadowCopyCheatArtifactScanModule());
        if (o.ScanAntiVirusTamper) modules.Add(new AntiVirusTamperScanModule());
        if (o.ScanRawAccelDriver) modules.Add(new RawAccelDriverScanModule());
        if (o.ScanVulnerableDriverFiles) modules.Add(new VulnerableDriverFilesScanModule());
        if (o.ScanSearchHistoryForensics) modules.Add(new WindowsSearchHistoryForensicScanModule());
        if (o.ScanInterceptionDriver) modules.Add(new InterceptionDriverCheatScanModule());
        if (o.ScanCheatNetworkProtocol) modules.Add(new CheatNetworkProtocolScanModule());
        if (o.ScanRegistryForensicArtifacts) modules.Add(new RegistryForensicArtifactScanModule());
        if (o.ScanThirdPartyGameOverlay) modules.Add(new ThirdPartyGameOverlayScanModule());
        if (o.ScanAntiCheatTelemetryBlock) modules.Add(new AntiCheatTelemetryBlockScanModule());
        if (o.ScanKernelCodesignBypass) modules.Add(new KernelDriverCodesignBypassScanModule());
        if (o.ScanDmaCheatInfrastructure) modules.Add(new DmaCheatInfrastructureScanModule());
        if (o.ScanMouseFirmwareAnomaly) modules.Add(new MouseFirmwareAnomalyScanModule());
        if (o.ScanSpooferArtifacts) modules.Add(new SpooferArtifactScanModule());
        if (o.ScanAntiCheatGameVersion) modules.Add(new AntiCheatGameVersionScanModule());
        if (o.ScanWslAbuse) modules.Add(new WindowsSubsystemLinuxAbuseScanModule());
        if (o.ScanEfiVariables) modules.Add(new EfiVariableAnomalyScanModule());
        if (o.ScanSuspiciousNetworkAdapters) modules.Add(new SuspiciousNetworkAdapterScanModule());
        if (o.ScanMouseAccelerationCheat) modules.Add(new MouseAccelerationCheatScanModule());
        if (o.ScanWmiPersistence) modules.Add(new WmiPersistenceScanModule());
        if (o.ScanScheduledTasks) modules.Add(new ScheduledTaskScanModule());
        if (o.ScanKernelDrivers) modules.Add(new DriverScanModule());
        if (o.ScanHiddenDrivers) modules.Add(new HiddenDriverScanModule());
        if (o.ScanKernelBridge) modules.Add(new KernelBridgeModule());

        // ── Group 4: user-data file reads ────────────────────────────────────
        if (o.ScanBrowserHistory) modules.Add(new BrowserHistoryScanModule());
        if (o.ScanFiveM) modules.Add(new FiveMScanModule());
        if (o.ScanDownloads) modules.Add(new DownloadsScanModule());
        if (o.ScanPowerShell) modules.Add(new PowerShellScanModule());
        if (o.ScanSecurityTimeline) modules.Add(new SecurityTimelineScanModule());
        if (o.ScanCredentialTheft) modules.Add(new CredentialTheftScanModule());
        if (o.ScanLuaScripts) modules.Add(new LuaScriptScanModule());
        if (o.ScanPowerShellHistoryDeep) modules.Add(new PowerShellHistoryDeepScanModule());
        if (o.ScanEventLogDeep) modules.Add(new WindowsEventLogDeepScanModule());
        if (o.ScanTaskSchedulerDeep) modules.Add(new TaskSchedulerDeepScanModule());
        if (o.ScanStartupFolderDeep) modules.Add(new StartupFolderDeepScanModule());
        if (o.ScanSensitiveDataAccess) modules.Add(new SensitiveDataAccessScanModule());
        if (o.ScanGameConfigManipulation) modules.Add(new GameConfigManipulationScanModule());
        if (o.ScanCheatFileArtifacts) modules.Add(new CheatToolFileArtifactScanModule());
        if (o.ScanJumpListForensics) modules.Add(new JumpListForensicScanModule());
        if (o.ScanCloudSyncCheatArtifacts) modules.Add(new CloudSyncCheatArtifactScanModule());
        if (o.ScanTimelineActivity) modules.Add(new WindowsTimelineActivityScanModule());
        if (o.ScanRecycleBinForensics) modules.Add(new RecycleBinForensicScanModule());
        if (o.ScanAppDataLocalLow) modules.Add(new AppDataLocalLowCheatScanModule());
        if (o.ScanBrowserBookmarks) modules.Add(new BrowserBookmarksCheatScanModule());
        if (o.ScanDiscordCheatArtifacts) modules.Add(new DiscordCheatArtifactScanModule());
        if (o.ScanTelegramArtifacts) modules.Add(new TelegramDesktopArtifactScanModule());
        if (o.ScanMacroSoftware) modules.Add(new MacroSoftwareCheatScanModule());
        if (o.ScanSteamCheatCorrelation) modules.Add(new SteamCheatCorrelationScanModule());
        if (o.ScanShadowplayArtifacts) modules.Add(new NvidiaShadowplayArtifactScanModule());
        if (o.ScanObsConfiguration) modules.Add(new OBSStreamingCheatScanModule());
        if (o.ScanScheduledTaskCheat) modules.Add(new SuspiciousScheduledTaskScanModule());
        if (o.ScanPowerShellHistory) modules.Add(new PowerShellCheatHistoryScanModule());
        if (o.ScanClipboardHistory) modules.Add(new ClipboardCheatArtifactScanModule());
        if (o.ScanAccountCorrelation) modules.Add(new CheaterAccountCorrelationScanModule());
        if (o.ScanCryptoPayment) modules.Add(new CryptoPaymentCheatScanModule());
        if (o.ScanGameFileIntegrity) modules.Add(new GameFileIntegrityScanModule());
        if (o.ScanCheatPayloadStaging) modules.Add(new CheatPayloadStagingScanModule());
        if (o.ScanWindowsNotificationForensics) modules.Add(new WindowsNotificationCheatScanModule());
        if (o.ScanSteamUserdataForensics) modules.Add(new SteamAchievementCheatScanModule());
        if (o.ScanGameSaveCheatMods) modules.Add(new GameSaveCheatModScanModule());
        if (o.ScanScreenRecordingArtifacts) modules.Add(new ScreenRecordingCheatArtifactScanModule());
        if (o.ScanCheatLicenseArtifacts) modules.Add(new CheatLicenseKeygenScanModule());
        if (o.ScanCheatForumArtifacts) modules.Add(new CheatCommunityForumScanModule());
        if (o.ScanSteamCacheArtifacts) modules.Add(new SteamCacheCheatArtifactScanModule());
        if (o.ScanGameReplayManipulation) modules.Add(new GameReplayManipulationScanModule());
        if (o.ScanAntiForensicCleanerTools) modules.Add(new AntiForensicCleanerToolScanModule());
        if (o.ScanWindowsStoreGameCheats) modules.Add(new WindowsStoreGameCheatScanModule());
        if (o.ScanCheatLaunchScripts) modules.Add(new CheatLaunchScriptScanModule());
        if (o.ScanFiveMDeep) modules.Add(new FiveMDeepCheatScanModule());
        if (o.ScanRageMp) modules.Add(new RageMpCheatDetectionScanModule());
        if (o.ScanAltV) modules.Add(new AltVCheatDetectionScanModule());
        if (o.ScanFiveMResourceCacheDeep) modules.Add(new FiveMResourceCacheDeepScanModule());
        if (o.ScanRageMpNetworkPacket) modules.Add(new RageMpNetworkPacketScanModule());
        if (o.ScanAltVDeepResource) modules.Add(new AltVDeepResourceScanModule());
        if (o.ScanHwidSpoofingDeep) modules.Add(new HwidSpoofingDeepScanModule());
        if (o.ScanMouseKeyboardEmulator) modules.Add(new MouseKeyboardEmulatorScanModule());
        if (o.ScanDllInjectionArtifact) modules.Add(new DllInjectionArtifactScanModule());
        if (o.ScanDirectXHookCheat) modules.Add(new DirectXHookCheatScanModule());
        if (o.ScanAntiCheatBypassArtifact) modules.Add(new AntiCheatBypassArtifactScanModule());
        if (o.ScanGtaVModMenuCheat) modules.Add(new GtaVModMenuCheatScanModule());
        if (o.ScanKernelTamperingArtifact) modules.Add(new KernelTamperingArtifactScanModule());
        if (o.ScanCheatMarketplaceArtifact) modules.Add(new CheatMarketplaceArtifactScanModule());
        if (o.ScanSteamApiHook) modules.Add(new SteamApiHookScanModule());
        if (o.ScanValorantCheat) modules.Add(new ValorantCheatScanModule());
        if (o.ScanNetworkC2Cheat) modules.Add(new NetworkC2CheatScanModule());
        if (o.ScanMemoryCheatSignature) modules.Add(new MemoryCheatSignatureScanModule());
        if (o.ScanCs2Cheat) modules.Add(new Cs2CheatScanModule());
        if (o.ScanRustApexCheat) modules.Add(new RustApexCheatScanModule());
        if (o.ScanScreenCaptureCheat) modules.Add(new ScreenCaptureCheatScanModule());
        if (o.ScanCheatDebugAnalysis) modules.Add(new CheatDebugAnalysisToolScanModule());
        if (o.ScanVirtualMachineCheat) modules.Add(new VirtualMachineCheatScanModule());
        if (o.ScanFortniteWarzoneCheat) modules.Add(new FortniteWarzoneCheatScanModule());
        if (o.ScanRobloxExploit) modules.Add(new RobloxExploitScanModule());
        if (o.ScanCheatTrainerKeygen) modules.Add(new CheatTrainerKeygenScanModule());
        if (o.ScanWindowsEventLogTamper) modules.Add(new WindowsEventLogTamperScanModule());
        if (o.ScanAmsiBypassArtifact) modules.Add(new AmsiBypassArtifactScanModule());
        if (o.ScanCheatHashSignature) modules.Add(new CheatHashSignatureScanModule());
        if (o.ScanCryptoMiner) modules.Add(new CryptoMinerScanModule());
        if (o.ScanFiveMExploitInjection) modules.Add(new FiveMExploitInjectionScanModule());
        if (o.ScanOverlayEspAimbot) modules.Add(new OverlayEspAimbotScanModule());
        if (o.ScanSpeedHackTimer) modules.Add(new SpeedHackTimerScanModule());
        if (o.ScanAntiScreenshotEvasion) modules.Add(new AntiScreenshotEvasionScanModule());
        if (o.ScanCryptoMinerCheatBundle) modules.Add(new CryptoMinerCheatBundleScanModule());
        if (o.ScanRagePluginHookCheat) modules.Add(new RagePluginHookCheatScanModule());
        if (o.ScanByovdVulnerableDriver) modules.Add(new ByovdVulnerableDriverScanModule());
        if (o.ScanEtwBypassTelemetry) modules.Add(new EtwBypassTelemetryScanModule());
        if (o.ScanEasyAntiCheatBypass) modules.Add(new EasyAntiCheatBypassScanModule());
        if (o.ScanBattlEyeBypass) modules.Add(new BattlEyeBypassScanModule());
        if (o.ScanVacFaceitBypass) modules.Add(new VacFaceitBypassScanModule());
        if (o.ScanProcessInjectionTechnique) modules.Add(new ProcessInjectionTechniqueScanModule());
        if (o.ScanFiveMRageMpAltVCheatNetwork) modules.Add(new FiveMRageMpAltVCheatNetworkScanModule());
        if (o.ScanHypervisorCheatDetection) modules.Add(new HypervisorCheatDetectionScanModule());
        if (o.ScanVanguardBypass) modules.Add(new VanguardBypassScanModule());
        if (o.ScanAntiDebugBypassArtifact) modules.Add(new AntiDebugBypassArtifactScanModule());
        if (o.ScanGtaOnlineModder) modules.Add(new GtaOnlineModderDetectionScanModule());
        if (o.ScanHwidSpoofDeep) modules.Add(new HwidSpoofDeepScanModule());
        if (o.ScanCheatDiscordC2) modules.Add(new CheatDiscordC2ScanModule());
        if (o.ScanMpghNprotectBypass) modules.Add(new MpghNprotectBypassScanModule());
        if (o.ScanPrefetchCheatForensic) modules.Add(new PrefetchCheatForensicScanModule());
        if (o.ScanAmcacheCheatForensic) modules.Add(new AmcacheCheatForensicScanModule());
        if (o.ScanLnkShellbagForensic) modules.Add(new LnkShellbagForensicScanModule());
        if (o.ScanDseBypassKernelSignature) modules.Add(new DseBypassKernelSignatureScanModule());
        if (o.ScanMemoryForensicTrail) modules.Add(new MemoryForensicTrailScanModule());
        if (o.ScanEscapeFromTarkovCheat) modules.Add(new EscapeFromTarkovCheatScanModule());
        if (o.ScanRainbowSixSiegeCheat) modules.Add(new RainbowSixSiegeCheatScanModule());
        if (o.ScanMinecraftCheatDeep) modules.Add(new MinecraftCheatDeepScanModule());
        if (o.ScanAimbotMouseSignature) modules.Add(new AimbotMouseSignatureScanModule());
        if (o.ScanBattlefieldCheat) modules.Add(new BattlefieldCheatScanModule());
        if (o.ScanOverwatchCheat) modules.Add(new OverwatchCheatScanModule());
        if (o.ScanWarzoneCheatDeep) modules.Add(new WarzoneCheatDeepScanModule());
        if (o.ScanCounterStrike2Cheat) modules.Add(new CounterStrike2CheatScanModule());
        if (o.ScanApexLegendsCheat) modules.Add(new ApexLegendsCheatScanModule());
        if (o.ScanValorantCheat) modules.Add(new ValorantCheatScanModule());
        if (o.ScanDota2Cheat) modules.Add(new Dota2CheatScanModule());
        if (o.ScanLeagueOfLegendsCheat) modules.Add(new LeagueOfLegendsCheatScanModule());
        if (o.ScanPubgCheat) modules.Add(new PubgCheatScanModule());
        if (o.ScanKernelRootkitDetection) modules.Add(new KernelRootkitDetectionScanModule());
        if (o.ScanUefiSecureBootBypass) modules.Add(new UefiSecureBootBypassScanModule());
        if (o.ScanAntiVirusEvasionArtifact) modules.Add(new AntiVirusEvasionArtifactScanModule());
        if (o.ScanFiveMMenuCheat) modules.Add(new FiveMMenuCheatScanModule());
        if (o.ScanAltVCheatMenu) modules.Add(new AltVCheatMenuScanModule());
        if (o.ScanRageMpDeepCheat) modules.Add(new RageMpDeepCheatScanModule());
        if (o.ScanCheatLoaderPacker) modules.Add(new CheatLoaderPackerScanModule());
        if (o.ScanDmaCheatHardware) modules.Add(new DmaCheatHardwareScanModule());
        if (o.ScanStreamerModeCheatEvasion) modules.Add(new StreamerModeCheatEvasionScanModule());
        if (o.ScanHwidSpooferRegistry) modules.Add(new HwidSpooferRegistryScanModule());
        if (o.ScanAntiCheatFingerPrintEvasion) modules.Add(new AntiCheatFingerPrintEvasionScanModule());
        if (o.ScanBanEvasionAccount) modules.Add(new BanEvasionAccountScanModule());
        if (o.ScanNetworkPacketManipulation) modules.Add(new NetworkPacketManipulationScanModule());
        if (o.ScanGameTrainerCheatEngine) modules.Add(new GameTrainerCheatEngineScanModule());
        if (o.ScanVirtualMachineCheatBypass) modules.Add(new VirtualMachineCheatBypassScanModule());
        if (o.ScanEasyAntiCheatBypass) modules.Add(new EasyAntiCheatBypassScanModule());
        if (o.ScanBattleEyeBypass) modules.Add(new BattleEyeBypassScanModule());
        if (o.ScanVanguardBypass) modules.Add(new VanguardBypassScanModule());
        if (o.ScanFiveMNativeSpoof) modules.Add(new FiveMNativeSpoofScanModule());
        if (o.ScanAltVResourceInjection) modules.Add(new AltVResourceInjectionScanModule());
        if (o.ScanRageMpPacketSpoof) modules.Add(new RageMpPacketSpoofScanModule());
        if (o.ScanAntiDebugEvasion) modules.Add(new AntiDebugEvasionScanModule());
        if (o.ScanProcessInjectionArtifact) modules.Add(new ProcessInjectionArtifactScanModule());
        if (o.ScanKernelCallbackHijack) modules.Add(new KernelCallbackHijackScanModule());
        if (o.ScanMemoryPatchingDetection) modules.Add(new MemoryPatchingDetectionScanModule());
        if (o.ScanFiveMResourceManifestTamper) modules.Add(new FiveMResourceManifestTamperScanModule());
        if (o.ScanCheatCloudService) modules.Add(new CheatCloudServiceScanModule());
        if (o.ScanAntiCheatKiller) modules.Add(new AntiCheatKillerScanModule());
        if (o.ScanGameExploitKit) modules.Add(new GameExploitKitScanModule());
        if (o.ScanRootKitUserModeArtifact) modules.Add(new RootKitUserModeArtifactScanModule());
        if (o.ScanGTA5OnlineCheat) modules.Add(new GTA5OnlineCheatScanModule());
        if (o.ScanRustApexCheat) modules.Add(new RustApexCheatScanModule());
        if (o.ScanFortniteWarzoneCheat) modules.Add(new FortniteWarzoneCheatScanModule());
        if (o.ScanFortniteCheatDetection) modules.Add(new FortniteCheatDetectionScanModule());
        if (o.ScanFiveMKernelExploit) modules.Add(new FiveMKernelExploitScanModule());
        if (o.ScanRustCheatDetection) modules.Add(new RustCheatDetectionScanModule());
        if (o.ScanCS2Cheat) modules.Add(new CS2CheatScanModule());
        if (o.ScanDayZCheat) modules.Add(new DayZCheatScanModule());
        if (o.ScanMinecraftCheat) modules.Add(new MinecraftCheatScanModule());
        if (o.ScanARKSurvivalCheat) modules.Add(new ARKSurvivalCheatScanModule());
        if (o.ScanAltVDeepCheatForensic) modules.Add(new AltVDeepCheatForensicScanModule());
        if (o.ScanFiveMServerLogCheat) modules.Add(new FiveMServerLogCheatScanModule());
        if (o.ScanLOLCheatForensic) modules.Add(new LOLCheatForensicScanModule());
        if (o.ScanSeaOfThievesCheat) modules.Add(new SeaOfThievesCheatScanModule());
        if (o.ScanDota2CheatArtifact) modules.Add(new Dota2CheatArtifactScanModule());
        if (o.ScanDeadByDaylightCheat) modules.Add(new DeadByDaylightCheatScanModule());
        if (o.ScanTeamFortress2Cheat) modules.Add(new TeamFortress2CheatScanModule());
        if (o.ScanWarzoneCODCheat) modules.Add(new WarzoneCODCheatScanModule());
        if (o.ScanWindowsEventLogCheatForensic) modules.Add(new WindowsEventLogCheatForensicScanModule());
        if (o.ScanBattlefield2042Cheat) modules.Add(new Battlefield2042CheatScanModule());
        if (o.ScanOverwatchCheatForensicDeep) modules.Add(new OverwatchCheatForensicDeepScanModule());
        if (o.ScanPUBG2CheatDeep) modules.Add(new PUBG2CheatDeepScanModule());
        if (o.ScanRageMPDeepForensic) modules.Add(new RageMPDeepForensicScanModule());
        if (o.ScanFiveMCrasherDetection) modules.Add(new FiveMCrasherDetectionScanModule());
        if (o.ScanFiveMMoneyDropCheat) modules.Add(new FiveMMoneyDropCheatScanModule());
        if (o.ScanHaloInfiniteCheat) modules.Add(new HaloInfiniteCheatScanModule());
        if (o.ScanHearthstoneCheat) modules.Add(new HearthstoneCheatScanModule());
        if (o.ScanCheatDiscordArtifact) modules.Add(new CheatDiscordArtifactScanModule());
        if (o.ScanCheatEngineDeepForensic) modules.Add(new CheatEngineDeepForensicScanModule());
        if (o.ScanRageMPMoneyGlitch) modules.Add(new RageMPMoneyGlitchScanModule());
        if (o.ScanMappingDriverForensic) modules.Add(new MappingDriverForensicScanModule());
        if (o.ScanSteamCheatWorkshop) modules.Add(new SteamCheatWorkshopScanModule());
        if (o.ScanAltVCrasherDetection) modules.Add(new AltVCrasherDetectionScanModule());
        if (o.ScanAltVMoneyCheat) modules.Add(new AltVMoneyCheatScanModule());
        if (o.ScanFiveMNativeHook) modules.Add(new FiveMNativeHookScanModule());
        if (o.ScanRageMPScriptInjection) modules.Add(new RageMPScriptInjectionScanModule());
        if (o.ScanGTA5ModMenu) modules.Add(new GTA5ModMenuForensicScanModule());
        if (o.ScanAntiCheatBypassForensic) modules.Add(new AntiCheatBypassForensicScanModule());
        if (o.ScanRageMPAdminAbuseForensic) modules.Add(new RageMPAdminAbuseForensicScanModule());
        if (o.ScanAltVAdminAbuseForensic) modules.Add(new AltVAdminAbuseForensicScanModule());
        if (o.ScanFiveMESXHack) modules.Add(new FiveMESXHackForensicScanModule());
        if (o.ScanAltVResourceTamper) modules.Add(new AltVResourceTamperScanModule());
        if (o.ScanFiveMIdentitySpoof) modules.Add(new FiveMIdentitySpoofScanModule());
        if (o.ScanFiveMNUIExploit) modules.Add(new FiveMNUIExploitScanModule());
        if (o.ScanRageMPKickExploit) modules.Add(new RageMPKickExploitScanModule());
        if (o.ScanRageMPCEFExploit) modules.Add(new RageMPCEFExploitScanModule());
        if (o.ScanEFTCheatDeep) modules.Add(new EFTCheatDeepScanModule());
        if (o.ScanValorantAimbotForensic) modules.Add(new ValorantAimbotForensicScanModule());
        if (o.ScanAltVPlayerDataSpoof) modules.Add(new AltVPlayerDataSpoofScanModule());
        if (o.ScanApexLegendsMacroForensic) modules.Add(new ApexLegendsMacroForensicScanModule());
        if (o.ScanAltVObjectSpawnAbuse) modules.Add(new AltVObjectSpawnAbuseScanModule());
        if (o.ScanCS2WallhackForensic) modules.Add(new CS2WallhackForensicScanModule());
        if (o.ScanFiveMPoliceAbuse) modules.Add(new FiveMPoliceAbuseScanModule());
        if (o.ScanRustCheatForensic) modules.Add(new RustCheatForensicScanModule());
        if (o.ScanAltVVehicleHack) modules.Add(new AltVVehicleHackScanModule());
        if (o.ScanFiveMBankHackForensic) modules.Add(new FiveMBankHackForensicScanModule());
        if (o.ScanFiveMSpeedHackForensic) modules.Add(new FiveMSpeedHackForensicScanModule());
        if (o.ScanRageMPAntibanForensic) modules.Add(new RageMPAntibanForensicScanModule());
        if (o.ScanWarzoneCheatForensic) modules.Add(new WarzoneCheatForensicScanModule());
        if (o.ScanAltVAntibanForensic) modules.Add(new AltVAntibanForensicScanModule());
        if (o.ScanFiveMChatSpam) modules.Add(new FiveMChatSpamScanModule());
        if (o.ScanFiveMGodModeForensic) modules.Add(new FiveMGodModeForensicScanModule());
        if (o.ScanFortniteCheatForensic) modules.Add(new FortniteCheatForensicScanModule());
        if (o.ScanPUBGCheatForensic) modules.Add(new PUBGCheatForensicScanModule());
        if (o.ScanRageMPHealthHack) modules.Add(new RageMPHealthHackScanModule());
        if (o.ScanRageMPWeaponHack) modules.Add(new RageMPWeaponHackScanModule());
        if (o.ScanFiveMNotoriousCheatVendor) modules.Add(new FiveMNotoriousCheatVendorScanModule());
        if (o.ScanRageMPAltVCheatVendor) modules.Add(new RageMPAltVCheatVendorScanModule());
        if (o.ScanUniversalCheatLoader) modules.Add(new UniversalCheatLoaderScanModule());
        if (o.ScanMultiPlatformBanEvidence) modules.Add(new MultiPlatformBanEvidenceScanModule());
        if (o.ScanFiveMRageMPAltVCleaner) modules.Add(new FiveMRageMPAltVCleanerForensicScanModule());
        if (o.ScanFiveMRageMPAltVBypass) modules.Add(new FiveMRageMPAltVBypassForensicScanModule());
        if (o.ScanAntiForensicScannerEvasion) modules.Add(new AntiForensicScannerEvasionScanModule());
        if (o.ScanCleanerResidueForensic) modules.Add(new CleanerResidueForensicScanModule());
        if (o.ScanBypassRuntimeAction) modules.Add(new BypassRuntimeActionForensicScanModule());
        if (o.ScanCleanerExecutionTrace) modules.Add(new CleanerExecutionTraceForensicScanModule());
        if (o.ScanGeneralAntiForensicAction) modules.Add(new GeneralAntiForensicActionForensicScanModule());
        if (o.ScanBypassCleanerAction) modules.Add(new BypassCleanerActionDetectionScanModule());
        if (o.ScanAntivirusHistory) modules.Add(new AntivirusHistoryScanModule());
        if (o.ScanWindowsDefenderEventLog) modules.Add(new WindowsDefenderEventLogForensicScanModule());
        if (o.ScanSecurityAuditPolicyForensic) modules.Add(new SecurityAuditPolicyForensicScanModule());
        if (o.ScanAntivirusDeepCrossPlatform) modules.Add(new AntivirusDeepCrossPlatformScanModule());
        if (o.ScanBypassToolBehaviorDeep) modules.Add(new BypassToolBehaviorDeepScanModule());
        if (o.ScanFiveMRageMPAltVDeep) modules.Add(new FiveMRageMPAltVDeepForensicScanModule());
        if (o.ScanAntiScannerEvasionDeep) modules.Add(new AntiScannerEvasionDeepScanModule());
        if (o.ScanNetworkCheatForensic) modules.Add(new NetworkCheatForensicScanModule());
        if (o.ScanCheatLoaderInjector) modules.Add(new CheatLoaderInjectorForensicScanModule());
        if (o.ScanCleanerDeepWipe) modules.Add(new CleanerDeepWipeForensicScanModule());
        if (o.ScanHWIDSpoofing) modules.Add(new HWIDSpoofingForensicScanModule());
        if (o.ScanUserAssistShell) modules.Add(new UserAssistShellForensicScanModule());
        if (o.ScanDiscordCheatCommunication) modules.Add(new DiscordCheatCommunicationScanModule());
        if (o.ScanWindowsEventDeep) modules.Add(new WindowsEventDeepForensicScanModule());
        if (o.ScanFiveMCitizenFXDeep) modules.Add(new FiveMCitizenFXDeepScanModule());
        if (o.ScanFiveMDeepForensic) modules.Add(new FiveMDeepForensicScanModule());
        if (o.ScanGameSaveFileCheat) modules.Add(new GameSaveFileCheatForensicScanModule());
        if (o.ScanAltVDeep) modules.Add(new AltVDeepForensicScanModule());
        if (o.ScanBrowserCheatShopping) modules.Add(new BrowserCheatShoppingForensicScanModule());
        if (o.ScanKernelBypassRootkit) modules.Add(new KernelBypassRootkitForensicScanModule());
        if (o.ScanCheatLoaderUnpacker) modules.Add(new CheatLoaderUnpackerForensicScanModule());
        if (o.ScanVirtualMachineBanEvasion) modules.Add(new VirtualMachineBanEvasionForensicScanModule());
        if (o.ScanFiveMServerSideCheat) modules.Add(new FiveMServerSideCheatForensicScanModule());
        if (o.ScanRageMPServerExploit) modules.Add(new RageMPServerExploitForensicScanModule());
        if (o.ScanAltVServerExploit) modules.Add(new AltVServerExploitForensicScanModule());
        if (o.ScanCheatSourceCodeRepo) modules.Add(new CheatSourceCodeRepoScanModule());
        if (o.ScanGTAVDeep) modules.Add(new GTAVDeepForensicScanModule());
        if (o.ScanGamingVPNBanEvasion) modules.Add(new GamingVPNBanEvasionForensicScanModule());
        if (o.ScanCheatCommunityPlatform) modules.Add(new CheatCommunityPlatformForensicScanModule());
        if (o.ScanFiveMNativeHook) modules.Add(new FiveMNativeHookForensicScanModule());
        if (o.ScanWindowsDefenderTamperDeep) modules.Add(new WindowsDefenderTamperDeepForensicScanModule());
        if (o.ScanFiveMModMenuDeep) modules.Add(new FiveMModMenuDeepForensicScanModule());
        if (o.ScanESXQBCoreExploitDeep) modules.Add(new ESXQBCoreExploitDeepForensicScanModule());
        if (o.ScanRageMPModMenuDeep) modules.Add(new RageMPModMenuDeepForensicScanModule());
        if (o.ScanFiveMBanEvasionDeep) modules.Add(new FiveMBanEvasionDeepForensicScanModule());
        if (o.ScanAltVModMenuDeep) modules.Add(new AltVModMenuDeepForensicScanModule());
        if (o.ScanRageMPBanEvasionDeep) modules.Add(new RageMPBanEvasionDeepForensicScanModule());
        if (o.ScanFiveMScriptExecutorDeep) modules.Add(new FiveMScriptExecutorDeepForensicScanModule());
        if (o.ScanMenyooStuffDeep) modules.Add(new MenyooStuffDeepForensicScanModule());
        if (o.ScanFiveMNetEventExploit) modules.Add(new FiveMNetEventExploitForensicScanModule());
        if (o.ScanGameRecordingCheatEvidence) modules.Add(new GameRecordingCheatEvidenceForensicScanModule());
        if (o.ScanAltVBanEvasionDeep) modules.Add(new AltVBanEvasionDeepForensicScanModule());
        if (o.ScanKernelCheatDriverDeep) modules.Add(new KernelCheatDriverDeepForensicScanModule());
        if (o.ScanFiveMTxAdminAbuseDeep) modules.Add(new FiveMTxAdminAbuseDeepForensicScanModule());
        if (o.ScanAIAimbotDeep) modules.Add(new AIAimbotDeepForensicScanModule());
        if (o.ScanRobloxExecutorDeep) modules.Add(new RobloxExecutorDeepForensicScanModule());
        if (o.ScanHardwareAimbotDevice) modules.Add(new HardwareAimbotDeviceForensicScanModule());
        if (o.ScanFiveMResourceExploitDeep) modules.Add(new FiveMResourceExploitDeepForensicScanModule());

        // ── Group 5: forensic / trace artefacts ──────────────────────────────
        if (o.ScanForensicTraces) modules.Add(new ForensicTraceScanModule());
        if (o.ScanRemnants) modules.Add(new RemnantsScanModule());
        if (o.ScanUsnJournal) modules.Add(new UsnJournalScanModule());
        if (o.ScanTamper) modules.Add(new TamperScanModule());
        if (o.ScanDllHijack) modules.Add(new DllHijackScanModule());

        // ── Group 1: independent fast checks (already assigned group 1) ──────
        if (o.ScanExecutionHistory) modules.Add(new ExecutionHistoryScanModule());
        if (o.ScanUsbDevices) modules.Add(new UsbDeviceScanModule());
        if (o.ScanBrowserExtensions) modules.Add(new BrowserExtensionScanModule());
        if (o.ScanRootCertificates) modules.Add(new RootCertificateScanModule());
        if (o.ScanInstalledSoftware) modules.Add(new InstalledSoftwareScanModule());
        if (o.ScanPrefetch) modules.Add(new PrefetchScanModule());
        if (o.ScanClipboard) modules.Add(new ClipboardScanModule());
        if (o.ScanBepInExDoorstop) modules.Add(new BepInExDoorstopScanModule());
        if (o.ScanSteamEmulators) modules.Add(new SteamEmulatorDetectionScanModule());
        if (o.ScanNtfsReparsePoints) modules.Add(new NtfsReparsePointScanModule());
        if (o.ScanGameConfigCheats) modules.Add(new GameConfigCheatCommandScanModule());
        if (o.ScanCheatInstallerArtifacts) modules.Add(new CheatToolInstallerArtifactScanModule());
        if (o.ScanSteam) modules.Add(new SteamAccountScanModule());
        if (o.ScanAppData) modules.Add(new AppDataScanModule());
        if (o.ScanShellbags) modules.Add(new ShellbagScanModule());
        if (o.ScanUserAssist) modules.Add(new UserAssistScanModule());
        if (o.ScanAccessibilityAbuse) modules.Add(new AccessibilityAbuseScanModule());
        if (o.ScanMuiCache) modules.Add(new MuiCacheScanModule());
        if (o.ScanRecentDocs) modules.Add(new RecentDocsScanModule());
        if (o.ScanWerArtifacts) modules.Add(new WerArtifactScanModule());
        if (o.ScanAmcache) modules.Add(new AmcacheScanModule());
        if (o.ScanCertificateTrust) modules.Add(new CertificateTrustScanModule());
        if (o.ScanInstalledFonts) modules.Add(new InstalledFontScanModule());

        // ── Sequential (group 0): order-sensitive or internally parallel ──────
        if (o.ScanMacroSoftware) modules.Add(new MacroSoftwareScanModule());
        if (o.ScanSuspiciousExecutables) modules.Add(new SuspiciousExecutableScanModule());
        if (o.ScanProcessInjection) modules.Add(new ProcessInjectionScanModule());
        if (o.ScanSignatureVerification) modules.Add(new SignatureVerificationScanModule());
        if (o.ScanDirectSyscalls) modules.Add(new SystemCallDirectScanModule());
        if (o.ScanBootSector) modules.Add(new BootSectorScanModule());
        if (o.ScanPEHeaderAnomalies) modules.Add(new PEHeaderAnomalyScanModule());
        if (o.ScanThreadStartAddress) modules.Add(new ThreadStartAddressScanModule());
        if (o.ScanGameDirectoryInjection) modules.Add(new GameDirectoryInjectionScanModule());
        if (o.ScanProcessHollowing) modules.Add(new ProcessHollowingScanModule());
        if (o.ScanAntiDebugTechniques) modules.Add(new AntiDebugTechniqueScanModule());
        if (o.ScanTokenImpersonation) modules.Add(new TokenImpersonationScanModule());
        if (o.ScanTokenIntegrityAbuse) modules.Add(new TokenImpersonationAbuseModule());
        if (o.ScanAlternativeDataStreams) modules.Add(new AlternativeDataStreamScanModule());
        if (o.ScanMemoryProtection) modules.Add(new MemoryProtectionScanModule());
        if (o.ScanHiddenFiles) modules.Add(new HiddenFileScanModule());
        if (o.ScanLoadedModuleIntegrity) modules.Add(new LoadedModuleIntegrityScanModule());
        if (o.ScanKernelCallbackTable) modules.Add(new KernelCallbackTableScanModule());
        if (o.ScanExceptionHandlerChain) modules.Add(new ExceptionHandlerChainScanModule());
        if (o.ScanApcInjection) modules.Add(new ApcInjectionScanModule());
        if (o.ScanTlsCallbacks) modules.Add(new TlsCallbackScanModule());
        if (o.ScanReflectiveDllInjection) modules.Add(new ReflectiveDllInjectionScanModule());
        if (o.ScanInlineHooks) modules.Add(new InlineHookDetectionScanModule());
        if (o.ScanEtwTamper) modules.Add(new EtwTamperScanModule());
        if (o.ScanHardwareBreakpoints) modules.Add(new HardwareBreakpointScanModule());
        if (o.ScanShellcodeSignatures) modules.Add(new ShellcodeSignatureScanModule());
        if (o.ScanProcessMemoryStrings) modules.Add(new ProcessMemoryStringsScanModule());
        if (o.ScanSuspiciousImports) modules.Add(new SuspiciousImportedFunctionsScanModule());
        if (o.ScanMmapCodeInjection) modules.Add(new MmapCodeInjectionScanModule());
        if (o.ScanHiddenThreads) modules.Add(new HiddenThreadDetectionScanModule());
        if (o.ScanApiHashing) modules.Add(new WinApiHashingScanModule());
        if (o.ScanNtdllDoubleLoad) modules.Add(new NtdllDoubleLoadScanModule());
        if (o.ScanAntiDumpProtection) modules.Add(new AntiDumpProtectionScanModule());
        if (o.ScanPebAnomalies) modules.Add(new ProcessEnvironmentBlockScanModule());
        if (o.ScanModuleStomping) modules.Add(new ProcessModuleStompingScanModule());
        if (o.ScanMemoryAllocatorAnomaly) modules.Add(new MemoryAllocatorAnomalyScanModule());
        if (o.ScanSteamApiIntegrity) modules.Add(new SteamApiIntegrityScanModule());
        if (o.ScanCodeCaves) modules.Add(new CodeCaveDetectionScanModule());
        if (o.ScanVirtualProtectAbuse) modules.Add(new VirtualProtectAbuseScanModule());
        if (o.ScanDebuggerAttach) modules.Add(new DebuggerAttachDetectionScanModule());
        if (o.ScanStagedShellcode) modules.Add(new StagedShellcodeDetectionScanModule());
        if (o.ScanExportAddressTableHooks) modules.Add(new ExportAddressTableHookScanModule());
        if (o.ScanPackedModules) modules.Add(new PackedModuleDetectionScanModule());
        if (o.ScanHeapSpray) modules.Add(new HeapSprayScanModule());
        if (o.ScanKnownHashes) modules.Add(new KnownHashScanModule());
        if (o.ScanMemory) modules.Add(new MemoryScanModule());
        if (o.ScanDrives) modules.Add(new DriveScanModule());
        if (o.ScanNtfsAds) modules.Add(new NtfsAdsScanModule());
        if (o.ScanTimestampManipulation) modules.Add(new TimestampManipulationScanModule());
        if (o.ScanGameIntegrity) modules.Add(new GameIntegrityScanModule());
        if (o.ScanCustomStrings) modules.Add(new CustomStringsScanModule());
        // Cloud analysis runs after drives so all hashes are collected first.
        if (o.ScanCloudAnalysis) modules.Add(new CloudAnalysisScanModule(
            new Services.CloudAnalysisService(
                new System.Net.Http.HttpClient(),
                "https://api.zerotrace.gg")));
        // Discord last — cross-correlates findings from all preceding modules.
        if (o.ScanDiscordGuilds) modules.Add(new DiscordScanModule());

        return modules;
    }
}
