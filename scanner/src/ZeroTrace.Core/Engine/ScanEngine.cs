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
                try
                {
                    await module.RunAsync(context, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    throw; // a cancellation must abort the whole scan
                }
                catch (Exception ex)
                {
                    // Isolate the failure: skip this module, keep scanning the rest.
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
        if (o.ScanHostsFile) modules.Add(new HostsFileScanModule());
        if (o.ScanOverlay) modules.Add(new OverlayScanModule());
        if (o.ScanWmiPersistence) modules.Add(new WmiPersistenceScanModule());
        if (o.ScanMemory) modules.Add(new MemoryScanModule());
        if (o.ScanTamper) modules.Add(new TamperScanModule());
        if (o.ScanDrives) modules.Add(new DriveScanModule());
        return modules;
    }
}
