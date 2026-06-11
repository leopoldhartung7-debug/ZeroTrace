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

    public ScanEngine(IndicatorMatcher matcher) => _matcher = matcher;

    public async Task<ScanReport> RunAsync(
        ScanOptions options,
        IProgress<ScanProgress>? progress,
        CancellationToken ct)
    {
        var modules = BuildModules(options);
        var context = new ScanContext(options, _matcher, progress);

        var report = new ScanReport
        {
            StartedUtc = DateTime.UtcNow,
            Elevated = PrivilegeChecker.IsElevated(),
            System = SystemInfo.Capture(),
            Inventory = options.ScanInventory ? HostInventoryCollector.Collect() : new()
        };

        // Surface findings to subscribers (live view) by re-raising on the context.
        // (FindingAdded is wired by the caller before RunAsync if needed.)

        progress?.Report(new ScanProgress
        {
            Phase = ScanPhase.Initializing,
            Message = $"{modules.Count} Module werden ausgefuehrt",
            Percent = 0
        });

        double totalWeight = modules.Sum(m => m.Weight);
        double consumed = 0;

        try
        {
            foreach (var module in modules)
            {
                ct.ThrowIfCancellationRequested();
                context.CurrentModule = module.Name;
                context.ModuleBaseline = totalWeight <= 0 ? 0 : consumed / totalWeight;
                context.ModuleSpan = totalWeight <= 0 ? 1 : module.Weight / totalWeight;

                context.Report(0, $"Starte Modul: {module.Name}");
                await module.RunAsync(context, ct).ConfigureAwait(false);
                context.Report(1, $"Modul abgeschlossen: {module.Name}");

                consumed += module.Weight;
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
                Reason = "Ein Modul hat eine Ausnahme ausgeloest: " + ex.Message
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
    /// Lets the caller subscribe to live findings: returns a context-less engine
    /// run is not possible, so we expose this overload that wires the event.
    /// </summary>
    public async Task<ScanReport> RunAsync(
        ScanOptions options,
        IProgress<ScanProgress>? progress,
        Action<Finding>? onFinding,
        CancellationToken ct)
    {
        // Build a context up front so we can attach the live callback, then run
        // the same pipeline. We duplicate minimal orchestration here to keep the
        // primary RunAsync clean.
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

        try
        {
            foreach (var module in modules)
            {
                ct.ThrowIfCancellationRequested();
                context.CurrentModule = module.Name;
                context.ModuleBaseline = totalWeight <= 0 ? 0 : consumed / totalWeight;
                context.ModuleSpan = totalWeight <= 0 ? 1 : module.Weight / totalWeight;

                context.Report(0, $"Starte Modul: {module.Name}");
                await module.RunAsync(context, ct).ConfigureAwait(false);
                context.Report(1, $"Modul abgeschlossen: {module.Name}");

                consumed += module.Weight;
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
                Reason = "Ein Modul hat eine Ausnahme ausgeloest: " + ex.Message
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
        if (o.ScanMemory) modules.Add(new MemoryScanModule());
        if (o.ScanTamper) modules.Add(new TamperScanModule());
        if (o.ScanDrives) modules.Add(new DriveScanModule());
        return modules;
    }
}
