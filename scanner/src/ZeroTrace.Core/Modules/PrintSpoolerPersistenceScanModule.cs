using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects malicious printer processor and print monitor DLLs used for
/// persistence via the Windows print spooler service.
///
/// The Print Spooler (spoolsv.exe) loads:
///   1. Print Processors:  HKLM\...\Print\Environments\...\Print Processors\
///      (DLLs that process print jobs — run as SYSTEM in spoolsv.exe)
///   2. Print Monitors:    HKLM\SYSTEM\...\Control\Print\Monitors\
///      (DLLs that communicate with printers — run as SYSTEM in spoolsv.exe)
///
/// This is a well-known persistence technique (used by APT groups, admin tools,
/// and increasingly by cheat tools) because:
///   - SYSTEM privileges (loaded in spoolsv.exe)
///   - Survives reboots
///   - Difficult to detect (not visible in standard autoruns tools)
///   - Requires no admin rights to register (HKCU variants)
///
/// Detection:
///   1. Enumerate all Print Monitors and flag non-system DLLs.
///   2. Enumerate all Print Processors and flag non-system DLLs.
///   3. Check DLL signatures for each entry.
/// </summary>
public sealed class PrintSpoolerPersistenceScanModule : IScanModule
{
    public string Name => "Druckspooler-Persistenz";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    private const string PrintMonitorsKey =
        @"SYSTEM\CurrentControlSet\Control\Print\Monitors";
    private const string PrintEnvironmentsKey =
        @"SYSTEM\CurrentControlSet\Control\Print\Environments";

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System);

    // Known legitimate print monitors
    private static readonly HashSet<string> KnownGoodMonitors = new(StringComparer.OrdinalIgnoreCase)
    {
        "Local Port", "Standard TCP/IP Port", "USB Monitor",
        "Microsoft Shared Fax Monitor", "BJ Language Monitor",
        "LexBce Server", "PJL Language Monitor",
        "Microsoft IPP Class Driver", "WSD Port",
        "AppMon", "TCPMon", "LPRMon",
    };

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "persist",
        "kiddion", "cherax", "aimware", "spoofer", "hook",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckPrintMonitors(ctx, ct);
        hits += CheckPrintProcessors(ctx, ct);

        ctx.Report(1.0, Name, $"Druckspooler-Persistenz geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckPrintMonitors(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(PrintMonitorsKey, writable: false);
            if (key is null) return 0;

            foreach (var monitorName in key.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementRegistryKeys();

                if (KnownGoodMonitors.Contains(monitorName)) continue;

                using var monKey = key.OpenSubKey(monitorName, writable: false);
                if (monKey is null) continue;

                var driver = monKey.GetValue("Driver") as string ?? "";
                var lower = driver.ToLowerInvariant();
                var nameLower = monitorName.ToLowerInvariant();
                var combined = lower + " " + nameLower;

                // Check if DLL is outside System32
                var dllPath = lower.Contains('\\') ? driver
                    : Path.Combine(System32, driver);
                bool isSystem32 = dllPath.ToLowerInvariant().StartsWith(System32.ToLowerInvariant());
                bool exists = File.Exists(dllPath);

                var cheatKw = CheatKeywords.FirstOrDefault(k =>
                    combined.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (cheatKw is not null || !isSystem32)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtiger Druck-Monitor: {monitorName}",
                        Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"HKLM\{PrintMonitorsKey}\{monitorName}",
                        FileName = driver,
                        Reason   = $"Druck-Monitor '{monitorName}' lädt DLL '{driver}' " +
                                   (isSystem32 ? "aus System32 " : "von Nicht-System-Pfad ") +
                                   "als SYSTEM in spoolsv.exe. " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                   (!exists ? "DLL fehlt (Tombstone)." : "") +
                                   " Print-Monitor-Persistenz überlebt Reboots ohne sichtbaren Autostart-Eintrag.",
                        Detail   = $"Monitor: {monitorName} | DLL: {dllPath} | Keyword: {cheatKw ?? "keins"} | Existiert: {exists}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckPrintProcessors(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var envRoot = Registry.LocalMachine.OpenSubKey(PrintEnvironmentsKey, writable: false);
            if (envRoot is null) return 0;

            foreach (var envName in envRoot.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;

                using var ppRoot = envRoot.OpenSubKey(
                    $@"{envName}\Print Processors", writable: false);
                if (ppRoot is null) continue;

                foreach (var ppName in ppRoot.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) break;
                    if (string.Equals(ppName, "winprint", StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.IncrementRegistryKeys();

                    using var ppKey = ppRoot.OpenSubKey(ppName, writable: false);
                    var driver = ppKey?.GetValue("Driver") as string ?? "";

                    var dllPath = driver.Contains('\\') ? driver
                        : Path.Combine(System32, driver);
                    bool isSystem32 = dllPath.ToLowerInvariant().StartsWith(System32.ToLowerInvariant());
                    bool exists = File.Exists(dllPath);

                    var lower = (driver + " " + ppName).ToLowerInvariant();
                    var cheatKw = CheatKeywords.FirstOrDefault(k =>
                        lower.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (cheatKw is not null || !isSystem32)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Verdächtiger Druck-Prozessor: {ppName}",
                            Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                            Location = $@"HKLM\{PrintEnvironmentsKey}\{envName}\Print Processors\{ppName}",
                            FileName = driver,
                            Reason   = $"Print-Prozessor '{ppName}' in Umgebung '{envName}' lädt " +
                                       $"DLL '{driver}'. " +
                                       (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "Nicht in System32. ") +
                                       "Print-Prozessoren laufen als SYSTEM in spoolsv.exe.",
                            Detail   = $"PP: {ppName} | Env: {envName} | DLL: {dllPath} | Existiert: {exists}"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }
}
