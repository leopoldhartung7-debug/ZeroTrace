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
