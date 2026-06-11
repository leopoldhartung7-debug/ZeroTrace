using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects attempts to defeat / fake the scan itself (anti-tamper). All checks
/// are read-only and only report to the dashboard — the tool does not fight back
/// or hide. Covered:
///   - a debugger attached to the scanner (tampering with results);
///   - scanned folders replaced by a junction/symlink (decoy redirection);
///   - implausibly empty enumerations (process/driver APIs hooked to hide things);
///   - future-dated files (system clock rolled back to age cheat traces);
///   - running scan/anti-cheat bypass tooling (cross-checked via indicators).
/// </summary>
public sealed class TamperScanModule : IScanModule
{
    public string Name => "Scan-Manipulation";
    public double Weight => 0.4;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        CheckDebugger(ctx);
        ctx.Report(0.25, "Debugger", "Selbstschutz geprueft");

        CheckRedirectedFolders(ctx);
        ctx.Report(0.5, "Verzeichnisse", "Verzeichnis-Umleitungen geprueft");

        CheckEnumerationSanity(ctx);
        ctx.Report(0.75, "Enumeration", "Sichtbarkeit geprueft");

        CheckClockRollback(ctx, ct);
        ctx.Report(1.0, "Systemzeit", "Zeit-Manipulation geprueft");
        return Task.CompletedTask;
    }

    // --- debugger attached to the scanner --------------------------------------

    [DllImport("kernel32.dll")] private static extern bool IsDebuggerPresent();
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDbg);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();

    private void CheckDebugger(ScanContext ctx)
    {
        bool managed = Debugger.IsAttached;
        bool native = false, remote = false;
        try { native = IsDebuggerPresent(); } catch { }
        try { bool b = false; if (CheckRemoteDebuggerPresent(GetCurrentProcess(), ref b)) remote = b; } catch { }

        if (managed || native || remote)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Scanner wird debuggt (Manipulationsversuch)",
                Risk = RiskLevel.High,
                Location = "ZeroTrace-Prozess",
                Reason = "Waehrend des Scans war ein Debugger am Scanner angehaengt. Das deutet auf " +
                         "den Versuch hin, den Scan zu manipulieren oder die Ergebnisse zu faelschen.",
                Detail = $"managed={managed} native={native} remote={remote}"
            });
        }
    }

    // --- scanned folders replaced by a junction / symlink ----------------------

    private void CheckRedirectedFolders(ScanContext ctx)
    {
        var roots = new List<string> { KnownPaths.Downloads, KnownPaths.Temp };
        roots.AddRange(KnownPaths.FindMpFrameworks().Select(f => f.Root));

        foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!IsReparsePoint(root)) continue;
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Gescanntes Verzeichnis umgeleitet (Junction/Symlink)",
                Risk = RiskLevel.High,
                Location = root,
                Reason = "Ein normalerweise echtes Verzeichnis ist ein Reparse-Punkt " +
                         "(Junction/Symlink). So kann der Scan auf einen leeren Koeder-Ordner " +
                         "umgeleitet werden, waehrend die echten Dateien woanders liegen.",
                Detail = "Reparse-Punkt erkannt."
            });
        }
    }

    private static bool IsReparsePoint(string path)
    {
        try
        {
            return Directory.Exists(path) &&
                   (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch { return false; }
    }

    // --- enumerations that come back implausibly empty (API hooking) -----------

    private void CheckEnumerationSanity(ScanContext ctx)
    {
        int procs = SafeProcessCount();
        if (procs is > 0 and < 15)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Auffaellig wenige Prozesse sichtbar",
                Risk = RiskLevel.Medium,
                Location = "Prozess-Enumeration",
                Reason = $"Es waren nur {procs} Prozesse sichtbar. Auf einem normalen Windows laufen " +
                         "deutlich mehr. Das kann auf gehookte/blockierte Enumeration hindeuten " +
                         "(Verstecken von Prozessen).",
                Detail = "Schwelle: < 15."
            });
        }

        int drivers = SafeDriverCount();
        if (drivers is > 0 and < 20)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Auffaellig wenige Treiber sichtbar",
                Risk = RiskLevel.Medium,
                Location = "Treiber-Enumeration",
                Reason = $"Es waren nur {drivers} Kernel-Treiber sichtbar. Das ist ungewoehnlich " +
                         "niedrig und kann auf eine manipulierte/gefilterte Treiberliste hindeuten.",
                Detail = "Schwelle: < 20."
            });
        }
    }

    private static int SafeProcessCount()
    {
        try { return Process.GetProcesses().Length; } catch { return -1; }
    }

    private static int SafeDriverCount()
    {
        try
        {
            using var s = new ManagementObjectSearcher("SELECT Name FROM Win32_SystemDriver");
            int n = 0;
            foreach (var _ in s.Get()) n++;
            return n;
        }
        catch { return -1; }
    }

    // --- system clock rolled back (future-dated files) -------------------------

    private void CheckClockRollback(ScanContext ctx, CancellationToken ct)
    {
        var roots = new List<string> { KnownPaths.Downloads, KnownPaths.Temp,
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory) };
        roots.AddRange(KnownPaths.FindMpFrameworks().Select(f => f.Root));

        var threshold = DateTime.UtcNow.AddDays(1);
        foreach (var root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (ct.IsCancellationRequested) return;
            string[] files;
            try { files = Directory.GetFiles(root); } catch { continue; }
            foreach (var f in files)
            {
                DateTime w;
                try { w = File.GetLastWriteTimeUtc(f); } catch { continue; }
                if (w > threshold)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Zukunftsdatierte Datei (moegliche Zeit-Manipulation)",
                        Risk = RiskLevel.Medium,
                        Location = f,
                        FileName = Path.GetFileName(f),
                        Reason = "Die Datei traegt ein Aenderungsdatum in der Zukunft. Das kann " +
                                 "auf eine zurueckgestellte Systemuhr hindeuten, mit der Cheat-Spuren " +
                                 "kuenstlich gealtert werden.",
                        Detail = $"Geaendert (UTC): {w:yyyy-MM-dd HH:mm}"
                    });
                    return; // one hit is enough to flag the machine
                }
            }
        }
    }
}
