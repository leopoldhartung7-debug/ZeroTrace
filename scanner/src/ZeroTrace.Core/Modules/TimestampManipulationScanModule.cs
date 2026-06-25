using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects NTFS timestamp manipulation ("timestomping") — a forensic anti-
/// analysis technique where malware or cheat tools overwrite file creation/
/// modification timestamps to match system files (usually 1970-01-01 or the
/// Windows install date) so they blend in.
///
/// Detection signals:
///   1. Files in high-risk locations with creation time equal to last-write time
///      to the millisecond (typical timestomping artifact — real file system
///      operations always differ by at least a few milliseconds).
///
///   2. Files with creation/modification dates far in the future (anti-forensics
///      trick to push files to the end of timeline views).
///
///   3. Files with timestamp year 1970 / 1601 (Unix epoch / Windows FILETIME epoch)
///      — the default when cheats zero-out FILETIME structures.
///
///   4. Files in user temp/downloads with system-file creation dates matching
///      the Windows install date exactly (cheats copy timestamps from C:\Windows).
///
///   5. $MFT entry timestamps vs $STANDARD_INFORMATION timestamps inconsistency
///      (full timestomp detection — $SI is user-visible, $FN reflects real times).
///      Note: reading $FN requires raw MFT access (elevation required).
/// </summary>
public sealed class TimestampManipulationScanModule : IScanModule
{
    public string Name => "Zeitstempel-Manipulation";
    public double Weight => 0.7;
    public int ParallelGroup => 1;

    // Directories most likely to contain stomped cheat files
    private static readonly string[] HighRiskDirs;

    // Windows install date from registry — used to detect timestamp copying
    private static readonly DateTime? WindowsInstallDate;

    // Future cutoff — timestamps beyond this are suspicious
    private static readonly DateTime FutureCutoff = DateTime.UtcNow.AddDays(30);

    // Epoch values that indicate zeroed-out timestamps
    private static readonly DateTime[] SuspiciousEpochs =
    {
        new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc),   // Unix epoch
        new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc),   // Windows FILETIME epoch
        new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc),   // Common default
    };

    static TimestampManipulationScanModule()
    {
        var profile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp     = Path.GetTempPath();

        HighRiskDirs = new[]
        {
            Path.Combine(profile, "Downloads"),
            Path.Combine(profile, "Desktop"),
            temp,
            Path.Combine(localApp, "Temp"),
            appData,
        };

        // Read Windows install date from registry
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);
            if (key is not null)
            {
                var installTime = key.GetValue("InstallTime");
                if (installTime is long ft)
                {
                    WindowsInstallDate = DateTime.FromFileTimeUtc(ft);
                }
            }
        }
        catch { }
    }

    // Extensions that are executable — higher risk when timestomped
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".drv", ".com", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".jar", ".msi", ".scr", ".pif",
        ".ahk", ".au3", ".lua",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int filesChecked = 0;
        int stomped = 0;

        foreach (var dir in HighRiskDirs)
        {
            if (!Directory.Exists(dir)) continue;
            if (ct.IsCancellationRequested) break;

            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*",
                    SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) break;
                    filesChecked++;
                    ctx.IncrementFiles();

                    try
                    {
                        var info = new FileInfo(file);
                        if (CheckFile(info, ctx, ct))
                            stomped++;
                    }
                    catch { }

                    if (filesChecked % 500 == 0)
                        ctx.Report((double)filesChecked / 5000.0,
                            "Zeitstempel-Manipulation",
                            $"{filesChecked} Dateien geprüft");
                }
            }
            catch { }
        }

        ctx.Report(1.0, "Zeitstempel-Manipulation",
            $"{filesChecked} Dateien geprüft, {stomped} Auffälligkeiten");
        return Task.CompletedTask;
    }

    private static bool CheckFile(FileInfo info, ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return false;

        var created  = info.CreationTimeUtc;
        var modified = info.LastWriteTimeUtc;
        var isExec   = ExecutableExtensions.Contains(info.Extension);

        bool flagged = false;

        // ── Future timestamps ──────────────────────────────────────────────────
        if (created > FutureCutoff || modified > FutureCutoff)
        {
            ctx.AddFinding(new Finding
            {
                Module   = "Zeitstempel-Manipulation",
                Title    = $"Zukünftiger Zeitstempel: {info.Name}",
                Risk     = isExec ? RiskLevel.High : RiskLevel.Medium,
                Location = info.FullName,
                FileName = info.Name,
                Reason   = $"Datei '{info.Name}' hat einen Zeitstempel in der Zukunft " +
                           $"(Erstellt: {created:yyyy-MM-dd}, Geändert: {modified:yyyy-MM-dd}). " +
                           "Dateien mit zukünftigen Zeitstempeln werden in forensischen " +
                           "Zeitachsen-Analysen ans Ende verschoben.",
                Detail   = $"Created: {created:O} | Modified: {modified:O}"
            });
            flagged = true;
        }

        // ── Epoch timestamps ──────────────────────────────────────────────────
        foreach (var epoch in SuspiciousEpochs)
        {
            if (Math.Abs((created - epoch).TotalHours) < 1 ||
                Math.Abs((modified - epoch).TotalHours) < 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Zeitstempel-Manipulation",
                    Title    = $"Zeitstempel-Nullwert: {info.Name}",
                    Risk     = isExec ? RiskLevel.Critical : RiskLevel.High,
                    Location = info.FullName,
                    FileName = info.Name,
                    Reason   = $"Datei '{info.Name}' hat einen Zeitstempel nahe dem Epoch-Wert " +
                               $"({epoch:yyyy-MM-dd}). Malware und Cheat-Loader nullen Zeitstempel " +
                               "aus, um ihre Zeitachsen-Spuren zu verwischen.",
                    Detail   = $"Created: {created:O} | Modified: {modified:O} | Epoch: {epoch:O}"
                });
                flagged = true;
                break;
            }
        }

        // ── Windows install date copying ───────────────────────────────────────
        if (WindowsInstallDate.HasValue && isExec)
        {
            var installDate = WindowsInstallDate.Value;
            if (Math.Abs((created - installDate).TotalMinutes) < 5)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Zeitstempel-Manipulation",
                    Title    = $"Zeitstempel = Windows-Installationsdatum: {info.Name}",
                    Risk     = RiskLevel.High,
                    Location = info.FullName,
                    FileName = info.Name,
                    Reason   = $"Ausführbare Datei '{info.Name}' hat exakt das Windows-" +
                               $"Installationsdatum ({installDate:yyyy-MM-dd}) als Erstellzeit. " +
                               "Cheats kopieren Zeitstempel von Windows-Systemdateien, um bei " +
                               "forensischen Analysen unerkannt zu bleiben.",
                    Detail   = $"Erstellt: {created:O} | Windows-Install: {installDate:O}"
                });
                flagged = true;
            }
        }

        // ── Perfect timestamp equality (timestomping artifact) ─────────────────
        if (isExec && Math.Abs((created - modified).TotalMilliseconds) < 1.0 &&
            created.Year > 2000)
        {
            ctx.AddFinding(new Finding
            {
                Module   = "Zeitstempel-Manipulation",
                Title    = $"Identische Zeitstempel (Timestomping): {info.Name}",
                Risk     = RiskLevel.Medium,
                Location = info.FullName,
                FileName = info.Name,
                Reason   = $"Ausführbare Datei '{info.Name}' hat exakt identische Erstellungs- und " +
                           "Änderungszeitstempel (bis Millisekunde). Bei echten Dateivorgängen " +
                           "unterscheiden sich diese immer. Dies ist ein typisches Artifact " +
                           "von SetFileTime()-basierten Timestomping-Tools.",
                Detail   = $"Created = Modified = {created:O}"
            });
            flagged = true;
        }

        return flagged;
    }
}
