using System.Text;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Forensic scan of the Windows Activity Timeline database (ActivitiesCache.db).
///
/// The Activity Timeline / Task View (introduced in Windows 10 1803) records every
/// application launch, document open, and browsing session into a SQLite database at:
///   %LOCALAPPDATA%\ConnectedDevicesPlatform\<AAD_ID>\ActivitiesCache.db
///
/// The database persists for ~30 days by default and survives normal cheat tool
/// uninstallation. Ocean and detect.ac use this as a forensic source because it
/// contains:
///   - Application IDs and command lines of recently launched executables
///   - Window titles (often including cheat tool names like "GameSense • Subscribe")
///   - URI paths for opened files (including cheat configs, ASI loaders)
///   - JSON payloads with content-type hints (e.g. "cheat.exe", "loader.dll")
///
/// This module does not parse SQLite — it greps the raw .db file bytes for
/// cheat-tool keywords in UTF-8 and UTF-16 LE encodings. Much faster than
/// loading System.Data.SQLite and equally effective at signature matching.
/// </summary>
public sealed class WindowsTimelineActivityScanModule : IScanModule
{
    public string Name => "Windows Activity Timeline Cheat Reference Scan";
    public double Weight => 0.55;
    public int ParallelGroup => 4;

    private static readonly string[] CheatKeywords =
    {
        // Universal markers
        "cheat", "aimbot", "wallhack", "esp_", "triggerbot",
        "norecoil", "spoofer", "hwidchanger",
        // CS / Source cheats
        "gamesense", "onetap", "fatality", "aimware", "limeware", "ev0lve",
        "neverlose", "skeet", "primordial", "weave.gg", "intellect",
        // GTA V menus
        "kiddion", "2take1", "stand_mod", "cherax", "midnight", "ozark",
        "menyoo", "scripthookv",
        // EFT
        "skycheats", "magicbullet", "skytap",
        // CoD / Apex
        "engineowning", "iniuria", "vapeflux", "interwebz",
        "apexlegit", "spectre.gg",
        // Valorant
        "tronix", "absolute_software", "lethal.gg",
        // Loaders / injectors
        "xenos", "extreme injector", "process hacker", "cheatengine",
        "x64dbg", "olly", "ghidra", "ida pro",
        // DMA / hardware
        "pcileech", "memprocfs", "memflow", "dma_radar",
        // BYOVD drivers (loaded via cheat tools)
        "mhyprot2", "rtcore64", "winring0", "iqvw64",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(localAppData)) return;

        string cdpRoot = System.IO.Path.Combine(localAppData, "ConnectedDevicesPlatform");
        if (!System.IO.Directory.Exists(cdpRoot)) return;

        string[] profileDirs;
        try { profileDirs = System.IO.Directory.GetDirectories(cdpRoot); }
        catch { return; }

        foreach (string profile in profileDirs)
        {
            ct.ThrowIfCancellationRequested();
            string dbPath = System.IO.Path.Combine(profile, "ActivitiesCache.db");
            if (!System.IO.File.Exists(dbPath)) continue;
            ScanDb(ctx, dbPath, ct);

            // Also scan WAL and SHM files for in-flight transactions
            string walPath = dbPath + "-wal";
            string shmPath = dbPath + "-shm";
            if (System.IO.File.Exists(walPath)) ScanDb(ctx, walPath, ct);
            if (System.IO.File.Exists(shmPath)) ScanDb(ctx, shmPath, ct);
        }
    }

    private void ScanDb(ScanContext ctx, string path, CancellationToken ct)
    {
        try
        {
            var info = new System.IO.FileInfo(path);
            if (info.Length == 0 || info.Length > 256 * 1024 * 1024) return;
            ctx.IncrementFiles();

            byte[] data = System.IO.File.ReadAllBytes(path);

            // Two passes: UTF-8 (SQLite text storage) and UTF-16 LE (JSON wide strings)
            string utf8  = Encoding.UTF8.GetString(data);
            string utf16 = Encoding.Unicode.GetString(data);
            string utf8Lower  = utf8.ToLowerInvariant();
            string utf16Lower = utf16.ToLowerInvariant();

            var hits = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string kw in CheatKeywords)
            {
                if (utf8Lower.Contains(kw) || utf16Lower.Contains(kw))
                {
                    hits.Add(kw);
                    if (hits.Count >= 6) break;
                }
            }

            if (hits.Count == 0) return;

            string context = ExtractContext(utf8, hits.First())
                          ?? ExtractContext(utf16, hits.First())
                          ?? hits.First();

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Cheat-Referenz in Windows-Timeline-DB: {System.IO.Path.GetFileName(path)}",
                Risk     = RiskLevel.High,
                Location = path,
                FileName = System.IO.Path.GetFileName(path),
                Reason   = $"Windows-Activity-Timeline-Datenbank enthält {hits.Count} Cheat-Keyword(s): " +
                           $"{string.Join(", ", hits)}. Die Timeline-DB protokolliert jeden " +
                           "Anwendungsstart, jedes geöffnete Dokument und besuchte Websites — " +
                           "Einträge persistieren standardmäßig ~30 Tage und überleben normale " +
                           "Cheat-Tool-Deinstallation. Ocean und detect.ac nutzen diese Quelle " +
                           "als forensische Standardprüfung.",
                Detail   = $"Datei: {path} | " +
                           $"Größe: {info.Length / 1024} KB | " +
                           $"Treffer: {string.Join(", ", hits)} | " +
                           $"Kontext: {context}"
            });
        }
        catch { }
    }

    private static string? ExtractContext(string text, string keyword)
    {
        int idx = text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;

        int start = Math.Max(0, idx - 50);
        int end   = Math.Min(text.Length, idx + keyword.Length + 50);

        var sb = new StringBuilder();
        for (int i = start; i < end; i++)
        {
            char c = text[i];
            if (c >= 0x20 && c < 0x7F) sb.Append(c);
            else if (c == '\\' || c == '/' || c == ':' || c == '_' || c == '-' || c == '.') sb.Append(c);
            else sb.Append(' ');
        }
        return sb.ToString().Trim();
    }
}
