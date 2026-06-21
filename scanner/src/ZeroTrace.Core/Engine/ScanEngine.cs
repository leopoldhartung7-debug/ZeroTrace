using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Modules;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Engine;

/// <summary>
/// Builds the active module set from the options, executes them while reporting
/// weighted progress, and returns a complete report. Modules that declare
/// <see cref="IScanModule.ParallelSafe"/> are grouped and run concurrently to
/// shorten scan time on multi-core machines. Sequential execution is preserved
/// for all other modules to keep disk/IO load predictable.
/// </summary>
public sealed class ScanEngine
{
    private readonly IndicatorMatcher _matcher;

    public ScanEngine(IndicatorMatcher matcher) => _matcher = matcher;

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
    /// Consecutive parallel-safe modules run as a group with Task.WhenAll.
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
            System = SystemInfo.Capture(),
            Inventory = options.ScanInventory ? HostInventoryCollector.Collect() : new()
        };

        progress?.Report(new ScanProgress
        {
            Phase = ScanPhase.Initializing,
            Message = $"{modules.Count} Module werden ausgefuehrt",
            Percent = 0
        });

        double totalWeight = modules.Sum(m => m.Weight);
        double consumed = 0;

        // Build execution pipeline: consecutive parallel-safe modules are grouped.
        var pipeline = BuildPipeline(modules);

        try
        {
            foreach (var stage in pipeline)
            {
                ct.ThrowIfCancellationRequested();

                if (stage is IScanModule single)
                {
                    context.CurrentModule = single.Name;
                    context.ModuleBaseline = totalWeight <= 0 ? 0 : consumed / totalWeight;
                    context.ModuleSpan = totalWeight <= 0 ? 1 : single.Weight / totalWeight;

                    context.Report(0, $"Starte Modul: {single.Name}");
                    await ExecuteModuleAsync(single, context, options, ct);
                    context.Report(1, $"Modul abgeschlossen: {single.Name}");

                    consumed += single.Weight;
                }
                else if (stage is List<IScanModule> group)
                {
                    double groupWeight = group.Sum(m => m.Weight);
                    context.CurrentModule = $"Parallele Analyse ({group.Count} Module)";
                    context.ModuleBaseline = totalWeight <= 0 ? 0 : consumed / totalWeight;
                    context.ModuleSpan = totalWeight <= 0 ? 1 : groupWeight / totalWeight;

                    context.Report(0, "", $"{group.Count} Module laufen parallel");

                    // Each module runs on a thread-pool thread. ScanContext is
                    // thread-safe; progress reporting from multiple modules is
                    // harmlessly interleaved.
                    await Task.WhenAll(group.Select(m =>
                        Task.Run(() => ExecuteModuleAsync(m, context, options, ct), ct)));

                    context.Report(1, "", "Parallele Analyse abgeschlossen");
                    consumed += groupWeight;
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
        report.Findings = context.Findings.OrderByDescending(f => f.Risk).ToList();

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
    /// Executes one module with its own cancellation deadline and isolates any
    /// exception so a single broken module cannot abort the whole scan.
    /// </summary>
    private static async Task ExecuteModuleAsync(
        IScanModule module, ScanContext context, ScanOptions options, CancellationToken ct)
    {
        using var moduleCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (options.ModuleTimeoutSeconds > 0)
            moduleCts.CancelAfter(TimeSpan.FromSeconds(options.ModuleTimeoutSeconds));

        try
        {
            await module.RunAsync(context, moduleCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw; // the user cancelled the whole scan
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
    }

    /// <summary>
    /// Groups consecutive parallel-safe modules into List&lt;IScanModule&gt; stages;
    /// single or non-safe modules remain as bare IScanModule stages.
    /// </summary>
    private static List<object> BuildPipeline(List<IScanModule> modules)
    {
        var pipeline = new List<object>();
        int i = 0;
        while (i < modules.Count)
        {
            if (modules[i].ParallelSafe)
            {
                var group = new List<IScanModule>();
                while (i < modules.Count && modules[i].ParallelSafe)
                    group.Add(modules[i++]);

                // A single-item group runs sequentially (no overhead).
                if (group.Count == 1) pipeline.Add(group[0]);
                else pipeline.Add(group);
            }
            else
            {
                pipeline.Add(modules[i++]);
            }
        }
        return pipeline;
    }

    private static List<IScanModule> BuildModules(ScanOptions o)
    {
        var modules = new List<IScanModule>();
        if (o.ScanProcesses) modules.Add(new ProcessScanModule());
        if (o.ScanAutostart) modules.Add(new AutostartScanModule());
        if (o.ScanRegistry) modules.Add(new RegistryScanModule());
        if (o.ScanFiveM) modules.Add(new FiveMScanModule());
        if (o.ScanDownloads) modules.Add(new DownloadsScanModule());
        if (o.ScanBrowserHistory) modules.Add(new BrowserHistoryScanModule());
        if (o.ScanSecurityTimeline) modules.Add(new SecurityTimelineScanModule());
        if (o.ScanPowerShell) modules.Add(new PowerShellScanModule());
        if (o.ScanKernelDrivers) modules.Add(new DriverScanModule());
        if (o.ScanExecutionHistory) modules.Add(new ExecutionHistoryScanModule());
        if (o.ScanDmaRisk) modules.Add(new DmaRiskScanModule());
        if (o.ScanRemnants) modules.Add(new RemnantsScanModule());
        if (o.ScanForensicTraces) modules.Add(new ForensicTraceScanModule());
        if (o.ScanUsnJournal) modules.Add(new UsnJournalScanModule());
        if (o.ScanNetwork) modules.Add(new NetworkScanModule());
        if (o.ScanOverlay) modules.Add(new OverlayScanModule());
        if (o.ScanWmiPersistence) modules.Add(new WmiPersistenceScanModule());
        if (o.ScanScheduledTasks) modules.Add(new ScheduledTaskScanModule());
        if (o.ScanUsbDevices) modules.Add(new UsbDeviceScanModule());
        if (o.ScanDllHijack) modules.Add(new DllHijackScanModule());
        if (o.ScanBrowserExtensions) modules.Add(new BrowserExtensionScanModule());
        if (o.ScanRootCertificates) modules.Add(new RootCertificateScanModule());
        if (o.ScanVirtualMachine) modules.Add(new VirtualMachineScanModule());
        if (o.ScanHiddenDrivers) modules.Add(new HiddenDriverScanModule());
        if (o.ScanMemory) modules.Add(new MemoryScanModule());
        if (o.ScanTamper) modules.Add(new TamperScanModule());
        if (o.ScanDrives) modules.Add(new DriveScanModule());
        if (o.ScanCustomStrings) modules.Add(new CustomStringsScanModule());
        return modules;
    }
}
