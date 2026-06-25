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

                    var concurrency = Math.Min(phase.Count, Environment.ProcessorCount);
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
        if (o.ScanThreadStartAddress) modules.Add(new ThreadStartAddressScanModule());
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
