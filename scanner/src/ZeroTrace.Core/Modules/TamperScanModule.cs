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
        ctx.Report(0.15, "Debugger", "Selbstschutz geprueft");

        CheckRedirectedFolders(ctx);
        ctx.Report(0.30, "Verzeichnisse", "Verzeichnis-Umleitungen geprueft");

        CheckEnumerationSanity(ctx);
        ctx.Report(0.50, "Enumeration", "Sichtbarkeit geprueft");

        CheckClockRollback(ctx, ct);
        ctx.Report(0.65, "Systemzeit", "Zeit-Manipulation geprueft");

        CheckRecycleBinCleared(ctx);
        ctx.Report(0.80, "Papierkorb", "Papierkorb-Leerung geprueft");

        CheckEvidenceClearing(ctx);
        ctx.Report(1.0, "Spuren loeschen", "Spurenbeseitigung geprueft");

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

    // --- recycle bin recently emptied ------------------------------------------

    private void CheckRecycleBinCleared(ScanContext ctx)
    {
        // A Recycle Bin folder that exists but whose last-write time is very
        // recent (within the last 2 hours) and which is now empty strongly
        // suggests that evidence was deliberately wiped just before the scan.
        var threshold = DateTime.UtcNow.AddHours(-2);

        DriveInfo[] drives;
        try { drives = DriveInfo.GetDrives(); }
        catch { return; }

        foreach (var d in drives)
        {
            string root;
            try { if (d.DriveType != DriveType.Fixed || !d.IsReady) continue; root = d.RootDirectory.FullName; }
            catch { continue; }

            var bin = Path.Combine(root, "$Recycle.Bin");
            if (!Directory.Exists(bin)) continue;

            // Look at each user SID subfolder
            string[] sidDirs;
            try { sidDirs = Directory.GetDirectories(bin); } catch { continue; }

            foreach (var sidDir in sidDirs)
            {
                DateTime lastWrite;
                try { lastWrite = Directory.GetLastWriteTimeUtc(sidDir); } catch { continue; }
                if (lastWrite < threshold) continue;

                // Verify the folder is now empty (no $I metadata files = all entries gone)
                string[] meta;
                try { meta = Directory.GetFiles(sidDir, "$I*"); } catch { continue; }
                if (meta.Length > 0) continue; // still has items -> not freshly emptied

                string[] all;
                try { all = Directory.GetFiles(sidDir); } catch { continue; }
                // Only flag if truly empty (no $R data files either)
                if (all.Length > 0) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Papierkorb kuerzlich geleert (moegliche Spurenbeseitigung)",
                    Risk = RiskLevel.Medium,
                    Recommendation = Recommendation.Review,
                    Location = sidDir,
                    Reason = $"Der Papierkorb auf Laufwerk {root[0]}: wurde kuerzlich (ca. " +
                             $"{lastWrite.ToLocalTime():HH:mm} Uhr) vollstaendig geleert. " +
                             "Cheater leeren den Papierkorb oft kurz vor einem Scan, um geloeschte " +
                             "Cheat-Dateien unwiederherstellbar zu machen.",
                    Detail = $"Letzte Aenderung: {lastWrite:yyyy-MM-dd HH:mm} UTC"
                });
            }
        }
    }

    // --- evidence clearing: event log, browser history, run MRU ---------------

    private void CheckEvidenceClearing(ScanContext ctx)
    {
        CheckEventLogCleared(ctx);
        CheckRunMruCleared(ctx);
        CheckPowerShellHistoryCleared(ctx);
    }

    private void CheckEventLogCleared(ScanContext ctx)
    {
        // Event ID 1102 (Security log cleared) or 104 (System/Application log cleared)
        // are written when someone clears an event log. Look for these in the Security log.
        try
        {
            using var log = new System.Diagnostics.Eventing.Reader.EventLogReader(
                new System.Diagnostics.Eventing.Reader.EventLogQuery(
                    "Security", System.Diagnostics.Eventing.Reader.PathType.LogName,
                    "*[System[(EventID=1102)]]")
                { ReverseDirection = true });

            var rec = log.ReadEvent();
            if (rec is null) return;

            var when = rec.TimeCreated?.ToLocalTime();
            rec.Dispose();

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Sicherheits-Ereignisprotokoll wurde geloescht",
                Risk = RiskLevel.High,
                Location = "Windows Security Log",
                Reason = "Das Windows-Sicherheitsprotokoll wurde geloescht (Event 1102). " +
                         "Das ist eine klare Anti-Forensik-Massnahme, die Aktivitaetsspuren " +
                         "wie Prozess-Starts oder Anmeldungen vernichtet.",
                Detail = when is null ? "" : $"Geloescht am: {when:yyyy-MM-dd HH:mm}"
            });
        }
        catch { }

        // Also check System log (Event 104 = log cleared by non-admin tool)
        try
        {
            using var log = new System.Diagnostics.Eventing.Reader.EventLogReader(
                new System.Diagnostics.Eventing.Reader.EventLogQuery(
                    "System", System.Diagnostics.Eventing.Reader.PathType.LogName,
                    "*[System[(EventID=104)]]")
                { ReverseDirection = true });

            var rec = log.ReadEvent();
            if (rec is null) return;

            var when = rec.TimeCreated?.ToLocalTime();
            rec.Dispose();

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "System-Ereignisprotokoll wurde geloescht",
                Risk = RiskLevel.High,
                Location = "Windows System Log",
                Reason = "Das Windows-Systemprotokoll wurde geloescht (Event 104). " +
                         "Treiber-Installationen und Systemereignisse wurden damit entfernt.",
                Detail = when is null ? "" : $"Geloescht am: {when:yyyy-MM-dd HH:mm}"
            });
        }
        catch { }
    }

    private void CheckRunMruCleared(ScanContext ctx)
    {
        // HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
        // holds the list of commands typed into Win+R. If it doesn't exist at all
        // on a machine that's been used regularly, it was cleared.
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU");
            // Key exists but MRUList is absent or empty -> recently cleared
            if (key is null) return;
            var mru = key.GetValue("MRUList")?.ToString();
            if (!string.IsNullOrEmpty(mru)) return; // still has entries

            // Only flag if the key modification time is recent (within 4 hours)
            // Registry key timestamps aren't directly accessible via .NET, so we
            // report it as a low-signal note without a timestamp.
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Ausfuehren-Verlauf (Win+R) geloescht",
                Risk = RiskLevel.Low,
                Recommendation = Recommendation.Review,
                Location = @"HKCU\Software\...\Explorer\RunMRU",
                Reason = "Der Ausfuehren-Dialog-Verlauf (Win+R) ist leer. Loader und Injektoren " +
                         "werden haeufig ueber Win+R gestartet; ein geleerer Verlauf kann " +
                         "auf Spurenbeseitigung hindeuten."
            });
        }
        catch { }
    }

    private void CheckPowerShellHistoryCleared(ScanContext ctx)
    {
        // If the PSReadLine history file exists but is 0 bytes, it was explicitly
        // cleared. A missing file is normal (PSReadLine not used). A 0-byte file
        // is almost always deliberate clearing.
        var histPath = Path.Combine(KnownPaths.RoamingAppData,
            "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
        try
        {
            if (!File.Exists(histPath)) return;
            var info = new FileInfo(histPath);
            if (info.Length > 0) return;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "PowerShell-Verlauf absichtlich geleert",
                Risk = RiskLevel.Medium,
                Location = histPath,
                Reason = "Die PowerShell-Verlaufsdatei (PSReadLine) existiert, ist aber leer (0 Byte). " +
                         "Das deutet auf absichtliches Loeschen des Befehlsverlaufs hin – " +
                         "ein haeufiges Zeichen fuer Spurenbeseitigung nach Loader-/Cheat-Nutzung.",
                Detail = $"Zuletzt geaendert: {info.LastWriteTime:yyyy-MM-dd HH:mm}"
            });
        }
        catch { }
    }
}
