using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans Discord's local storage and cache for cheat-community server artifacts.
///
/// Discord is the backbone of the cheat ecosystem: cheat vendors distribute license keys
/// via Discord bots, buyers join private cheat-vendor servers, and cheat support
/// happens in dedicated channels. Ocean and detect.ac mine Discord artifacts because:
///
///   - Discord's LevelDB stores (serialized) cached messages, server names, user data
///   - The HTTP cache holds API responses that contain server metadata
///   - Joined server IDs and invite URLs persist in LevelDB even after leaving
///
/// Files scanned:
///   %APPDATA%\discord\Local Storage\leveldb\*.ldb / *.log
///   %APPDATA%\discord\Cache\Cache_Data\data_*
///   %APPDATA%\discordptb\   (PTB and Canary variants)
///   %APPDATA%\discordcanary\
///
/// Method: byte-grep as UTF-8 text for known cheat vendor server names, invite
/// fragments, and cheat-domain URLs embedded in Discord's cached payloads.
/// </summary>
public sealed class DiscordCheatArtifactScanModule : IScanModule
{
    public string Name => "Discord Cheat-Community Artifact Scan";
    public double Weight => 0.6;
    public int ParallelGroup => 4;

    private static readonly string[] CheatKeywords =
    {
        // Major cheat vendor names as they appear in Discord server names / bot messages
        "gamesense", "onetap", "fatality", "aimware", "limeware",
        "ev0lve", "neverlose", "skeet.cc", "primordial",
        "kiddion", "2take1", "stand.sh", "cherax", "midnight.menu",
        "ozark.menu", "rampage.menu",
        "engineowning", "iniuria", "vapeflux",
        "apexlegit", "spectre.gg",
        "tronix.gg", "lethal.gg",
        "elitepvpers", "unknowncheats", "mpgh",
        "guidedhacking", "ownedcore",
        "pcileech", "memprocfs", "dma cheat",
        "permspoofer", "hwid spoofer",
        "cheat engine", "cheatengine",
        "aimbot", "wallhack", "esp hack", "rage hack",
        "no recoil", "triggerbot", "spinbot",
        "bhop", "bhop cheat", "movement hack",
        "lua cheat", "cheat script",
        "paid cheat", "private cheat", "undetected cheat",
        "cheat sub", "cheat invite", "cheat key",
        "cheat loader", "cheat injector",
    };

    private static readonly string[] DiscordAppDirs =
    {
        "discord", "discordptb", "discordcanary",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        foreach (string appDir in DiscordAppDirs)
        {
            ct.ThrowIfCancellationRequested();
            string discordRoot = System.IO.Path.Combine(roaming, appDir);
            if (!System.IO.Directory.Exists(discordRoot)) continue;

            ScanLevelDb(ctx, discordRoot, ct);
            ScanHttpCache(ctx, discordRoot, ct);
        }
    }

    private void ScanLevelDb(ScanContext ctx, string discordRoot, CancellationToken ct)
    {
        string leveldbDir = System.IO.Path.Combine(discordRoot, "Local Storage", "leveldb");
        if (!System.IO.Directory.Exists(leveldbDir)) return;

        try
        {
            foreach (string file in System.IO.Directory.EnumerateFiles(leveldbDir, "*.ldb")
                         .Concat(System.IO.Directory.EnumerateFiles(leveldbDir, "*.log")))
            {
                ct.ThrowIfCancellationRequested();

                var info = new System.IO.FileInfo(file);
                if (info.Length == 0 || info.Length > 64 * 1024 * 1024) continue;

                ctx.IncrementFiles();
                ScanFileForKeywords(ctx, file, "Discord LevelDB", ct);
            }
        }
        catch { }
    }

    private void ScanHttpCache(ScanContext ctx, string discordRoot, CancellationToken ct)
    {
        string cacheDir = System.IO.Path.Combine(discordRoot, "Cache", "Cache_Data");
        if (!System.IO.Directory.Exists(cacheDir)) return;

        try
        {
            int fileCount = 0;
            foreach (string file in System.IO.Directory.EnumerateFiles(cacheDir))
            {
                ct.ThrowIfCancellationRequested();
                if (++fileCount > 500) break; // cap: cache can have thousands of tiny files

                var info = new System.IO.FileInfo(file);
                if (info.Length == 0 || info.Length > 2 * 1024 * 1024) continue;

                ctx.IncrementFiles();
                ScanFileForKeywords(ctx, file, "Discord HTTP-Cache", ct);
            }
        }
        catch { }
    }

    private void ScanFileForKeywords(ScanContext ctx, string path, string sourceType, CancellationToken ct)
    {
        try
        {
            byte[] raw = System.IO.File.ReadAllBytes(path);
            string text = System.Text.Encoding.UTF8.GetString(raw).ToLowerInvariant();
            string fileName = System.IO.Path.GetFileName(path);

            foreach (string kw in CheatKeywords)
            {
                ct.ThrowIfCancellationRequested();
                if (!text.Contains(kw)) continue;

                // Extract a 120-char context snippet around the hit
                int idx = text.IndexOf(kw, StringComparison.Ordinal);
                int start = Math.Max(0, idx - 40);
                int end = Math.Min(text.Length, idx + kw.Length + 80);
                string snippet = text.Substring(start, end - start)
                                     .Replace('\0', ' ')
                                     .Replace('\n', ' ')
                                     .Trim();

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Discord-Cheat-Artefakt: '{kw}' in {sourceType}",
                    Risk     = RiskLevel.High,
                    Location = path,
                    FileName = fileName,
                    Reason   = $"Discord-Datei '{fileName}' enthält Cheat-Schlüsselwort '{kw}'. " +
                               $"Discord ist das primäre Kommunikationsmedium für Cheat-Communities; " +
                               $"Artefakte in LevelDB/Cache belegen Mitgliedschaft in Cheat-Servern " +
                               "oder Interaktion mit Cheat-Verkäufern. Ocean und detect.ac werten " +
                               "Discord-Daten als Standardsignal.",
                    Detail   = $"Quelle: {sourceType} | Datei: {fileName} | " +
                               $"Schlüsselwort: '{kw}' | Kontext: \"{snippet}\""
                });
                return; // one finding per file
            }
        }
        catch { }
    }
}
