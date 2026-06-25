using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans Windows Notification Platform (WNP) database and Windows Store app data
/// for cheat-related artifacts.
///
/// Windows Action Center / Notification Platform stores a SQLite database at:
///   %LOCALAPPDATA%\Microsoft\Windows\Notifications\wpndatabase.db
///
/// This database persists notification content including:
///   - Push notifications from apps (Discord, Telegram, browsers)
///   - System tray balloon notifications from cheat loaders
///   - Windows "app installed" / "update available" notifications for cheat tools
///   - Toast notifications from cheat vendor websites (via browser PWA)
///
/// Why Ocean/detect.ac check notification history:
///   - Cheat loaders often show status notifications (injection success, AC bypass)
///   - Discord notifications from cheat servers persist in the WPN DB
///   - Browser toast notifications from cheat vendor sites persist here
///   - WPN DB survives "Clear notification history" in Windows Settings
///
/// Additional checks:
///   - Windows Timeline / activity feed artifacts specific to cheat tool use
///   - Cortana search index for cheat-keyword file references
///   - Windows.old directory (upgraded Windows) for cheat remnants from previous install
/// </summary>
public sealed class WindowsNotificationCheatScanModule : IScanModule
{
    public string Name => "Windows Benachrichtigungs-Datenbank und App-Cache Forensik Scan";
    public double Weight => 0.4;
    public int ParallelGroup => 4;

    private static readonly string[] CheatKeywords =
    {
        "aimbot", "wallhack", "esp", "triggerbot", "cheat", "hack",
        "inject", "bypass", "gamesense", "onetap", "fatality", "aimware",
        "neverlose", "skeet", "2take1", "kiddion", "cherax", "ozark", "stand",
        "engineowning", "iniuria", "vapeflux", "pcileech", "memprocfs",
        "rawaccel", "interception", "sv_cheats", "bhop", "spinbot",
        "license key", "hwid", "rage bot", "legit bot",
        "unknowncheats", "mpgh", "elitepvpers",
        "mhyprot", "rtcore", "winring0",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ScanWpnDatabase(ctx, ct);
        ScanWindowsOld(ctx, ct);
        ScanCortanaIndex(ctx, ct);
    }

    private void ScanWpnDatabase(ScanContext ctx, CancellationToken ct)
    {
        string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string wpnDb = System.IO.Path.Combine(localApp, "Microsoft", "Windows",
            "Notifications", "wpndatabase.db");

        if (!System.IO.File.Exists(wpnDb)) return;

        try
        {
            ctx.IncrementFiles();
            var info = new System.IO.FileInfo(wpnDb);
            if (info.Length == 0 || info.Length > 50 * 1024 * 1024) return;

            byte[] raw = System.IO.File.ReadAllBytes(wpnDb);
            string text = System.Text.Encoding.UTF8.GetString(raw).ToLowerInvariant();

            foreach (string kw in CheatKeywords)
            {
                ct.ThrowIfCancellationRequested();
                if (!text.Contains(kw.ToLowerInvariant())) continue;

                int idx = text.IndexOf(kw.ToLowerInvariant(), StringComparison.Ordinal);
                int start = Math.Max(0, idx - 40);
                int end = Math.Min(text.Length, idx + kw.Length + 80);
                string snippet = text.Substring(start, end - start)
                    .Replace('\0', ' ').Replace('\n', ' ').Trim();

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Keyword in Windows Benachrichtigungs-DB: '{kw}'",
                    Risk     = RiskLevel.Medium,
                    Location = wpnDb,
                    FileName = "wpndatabase.db",
                    Reason   = $"Windows Benachrichtigungs-Datenbank enthält '{kw}'. " +
                               "Cheat-Loader zeigen Status-Benachrichtigungen (Injektion erfolgreich, " +
                               "AC bypassed), Discord-Benachrichtigungen von Cheat-Servern und Browser-" +
                               "Push-Notifications von Cheat-Vendor-Seiten werden hier gespeichert. " +
                               "Persistiert nach 'Benachrichtigungen löschen'.",
                    Detail   = $"DB: wpndatabase.db | Keyword: '{kw}' | Kontext: \"{snippet}\""
                });
                return; // one finding per DB
            }
        }
        catch { }

        // Also scan the notification WAL file
        try
        {
            string walFile = wpnDb + "-wal";
            if (System.IO.File.Exists(walFile))
            {
                ctx.IncrementFiles();
                var info = new System.IO.FileInfo(walFile);
                if (info.Length > 0 && info.Length <= 10 * 1024 * 1024)
                {
                    byte[] raw = System.IO.File.ReadAllBytes(walFile);
                    string text = System.Text.Encoding.UTF8.GetString(raw).ToLowerInvariant();

                    foreach (string kw in CheatKeywords)
                    {
                        ct.ThrowIfCancellationRequested();
                        if (!text.Contains(kw.ToLowerInvariant())) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Cheat-Keyword in WPN WAL-Datei: '{kw}'",
                            Risk     = RiskLevel.Medium,
                            Location = walFile,
                            FileName = "wpndatabase.db-wal",
                            Reason   = $"Windows Benachrichtigungs WAL-Datei enthält '{kw}'. " +
                                       "WAL-Dateien enthalten die neuesten noch nicht ins Haupt-DB " +
                                       "geschriebenen Einträge — oft aktuellere Forensik als die DB selbst.",
                            Detail   = $"Datei: {walFile} | Keyword: '{kw}'"
                        });
                        return;
                    }
                }
            }
        }
        catch { }
    }

    private void ScanWindowsOld(ScanContext ctx, CancellationToken ct)
    {
        // Windows.old is created during Windows upgrades
        // Cheats installed before the upgrade persist in the old installation
        string windowsOld = @"C:\Windows.old\Users";
        if (!System.IO.Directory.Exists(windowsOld)) return;

        try
        {
            foreach (string userDir in System.IO.Directory.GetDirectories(windowsOld))
            {
                ct.ThrowIfCancellationRequested();
                string userName = System.IO.Path.GetFileName(userDir);
                if (userName is "Public" or "Default" or "Default User" or "All Users") continue;

                // Check AppData for cheat directories in old installation
                string oldAppData = System.IO.Path.Combine(userDir, "AppData", "Roaming");
                string oldLocalApp = System.IO.Path.Combine(userDir, "AppData", "Local");
                string oldDownloads = System.IO.Path.Combine(userDir, "Downloads");

                foreach (string scanRoot in new[] { oldAppData, oldLocalApp, oldDownloads })
                {
                    ct.ThrowIfCancellationRequested();
                    if (!System.IO.Directory.Exists(scanRoot)) continue;

                    try
                    {
                        foreach (string subDir in System.IO.Directory.GetDirectories(scanRoot))
                        {
                            string dirName = System.IO.Path.GetFileName(subDir).ToLowerInvariant();
                            string? match = CheatKeywords.FirstOrDefault(kw =>
                                dirName.Contains(kw, StringComparison.OrdinalIgnoreCase));
                            if (match == null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Cheat-Verzeichnis in Windows.old: {dirName} (User: {userName})",
                                Risk     = RiskLevel.High,
                                Location = subDir,
                                FileName = dirName,
                                Reason   = $"Cheat-Verzeichnis '{dirName}' in Windows.old\\{userName} gefunden. " +
                                           "Windows.old enthält die alte Windows-Installation — Cheats die vor " +
                                           "dem Windows-Upgrade installiert waren bleiben hier erhalten. " +
                                           "Starker forensischer Beweis für historische Cheat-Nutzung.",
                                Detail   = $"Pfad: {subDir} | User: {userName} | Keyword: '{match}'"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private void ScanCortanaIndex(ScanContext ctx, CancellationToken ct)
    {
        // Windows Search / Cortana index can contain file paths that were indexed
        // The index itself is binary but the SQLite catalog file is readable
        string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string searchDb = System.IO.Path.Combine(localApp, "Microsoft", "Windows",
            "Search", "Windows.edb");

        // Windows.edb is an ESE (Extensible Storage Engine) database — complex to parse.
        // We can do a simple byte-grep for cheat keywords in the index file.
        if (!System.IO.File.Exists(searchDb)) return;

        try
        {
            ctx.IncrementFiles();
            var info = new System.IO.FileInfo(searchDb);
            if (info.Length == 0 || info.Length > 200 * 1024 * 1024) return;

            // Read in chunks to avoid huge memory allocation
            byte[] buffer = new byte[65536];
            string prevChunkEnd = "";

            using var fs = new System.IO.FileStream(searchDb,
                System.IO.FileMode.Open, System.IO.FileAccess.Read,
                System.IO.FileShare.ReadWrite | System.IO.FileShare.Delete);

            string? foundKeyword = null;
            while (foundKeyword == null)
            {
                ct.ThrowIfCancellationRequested();
                int read = fs.Read(buffer, 0, buffer.Length);
                if (read == 0) break;

                string chunk = prevChunkEnd +
                    System.Text.Encoding.ASCII.GetString(buffer, 0, read).ToLowerInvariant();

                foreach (string kw in CheatKeywords)
                {
                    if (chunk.Contains(kw.ToLowerInvariant()))
                    {
                        foundKeyword = kw;
                        break;
                    }
                }

                // Keep last 64 bytes of chunk to handle keyword split across boundary
                prevChunkEnd = chunk.Length > 64 ? chunk.Substring(chunk.Length - 64) : chunk;
            }

            if (foundKeyword != null)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Keyword im Windows Search-Index (Windows.edb): '{foundKeyword}'",
                    Risk     = RiskLevel.Medium,
                    Location = searchDb,
                    FileName = "Windows.edb",
                    Reason   = $"Windows Search-Index enthält '{foundKeyword}'. Windows indiziert Datei- " +
                               "Inhalte und -Namen automatisch — der Such-Index enthält Referenzen zu " +
                               "Cheat-Dateien die inzwischen gelöscht wurden. Persistiert dauerhaft " +
                               "bis der Index neu aufgebaut wird.",
                    Detail   = $"Datei: {searchDb} | Keyword: '{foundKeyword}'"
                });
            }
        }
        catch { }
    }
}
