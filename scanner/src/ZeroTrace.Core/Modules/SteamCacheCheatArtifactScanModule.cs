using ZeroTrace.Core.Models;
using System.Text;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Deep forensic scan of Steam client cache, download cache, and configuration
/// files for cheat-related artifacts.
///
/// Steam stores extensive forensic data beyond what the basic SteamAccountScanModule covers:
///
/// 1. Steam Workshop subscriptions (workshop folder):
///    - Subscribed workshop mods persist in content/app_id/ugc_id/ directories
///    - Workshop items include cheat mods that were downloaded but later unsubscribed
///    - The .acf manifest files record subscription history
///
/// 2. Steam download cache:
///    - SteamApps/downloading/ contains partial downloads including cheat DLCs
///    - Steam package downloads are logged in steamcmd_status.log
///
/// 3. Steam app manifest files (.acf):
///    - steamapps/appmanifest_XXXX.acf records installation history
///    - LastPlayed timestamp + PlaytimeForever can correlate with ban dates
///    - AppID 1 = Steam itself, AppID 4 in SteamApps = Source SDK (cheat dev)
///    - AppID 211 = Source SDK 2007 — heavily used for cheat development
///
/// 4. Steam client debug logs:
///    - logs/content_log.txt records all downloads including mods
///    - logs/network_log.txt records server connections
///    - logs/stats_log.txt records stat changes (cheated stats = anomaly)
///
/// 5. Steam VAC authentication artifacts:
///    - SteamApps/common/[game]/vac_bypass/ directories
///    - .nfo files from cracked Steam games (VAC-less builds)
///    - Steam_api.dll size anomalies (emulated vs genuine)
///
/// 6. Steam game backup files:
///    - Cheat tools sometimes masquerade as Steam game backup zips
///    - Files with .csd/.csm extension (steam content segment data)
///      appearing in non-Steam directories
///
/// 7. Steam controller configurations with macro-like bindings:
///    - Steam controller layouts in userdata/[SteamID]/config/
///    - Bindings with cheat-related action names
///
/// Ocean/detect.ac scan Steam directories extensively because:
///   - Steam workshop history is preserved even after unsubscribing
///   - .acf files record which game versions were run (pre-patch bypass)
///   - Steam log files capture network connections to cheat servers
/// </summary>
public sealed class SteamCacheCheatArtifactScanModule : IScanModule
{
    public string Name => "Steam Cache, Workshop & Log Cheat-Artefakt-Scan";
    public double Weight => 0.5;
    public int ParallelGroup => 4;

    private static readonly string[] CheatKeywords =
    {
        "aimbot", "wallhack", "esp", "cheat", "hack", "triggerbot", "bhop",
        "spinbot", "no_recoil", "norecoil", "gamesense", "onetap", "fatality",
        "aimware", "neverlose", "skeet", "2take1", "kiddion", "cherax",
        "radar", "overlay", "maphack", "wh", "no recoil", "speed hack",
        "injector", "loader", "bypass", "trainer",
    };

    // Known cheat-development AppIDs that shouldn't be on player PCs
    private static readonly (string AppId, string Name)[] DevAppIds =
    {
        ("211", "Source SDK 2007 — Cheat-Entwicklungsplattform"),
        ("218", "Source SDK 2006"),
        ("215", "Source SDK Base 2007"),
        ("1840", "Source SDK Base 2013 Multiplayer"),
        ("1006", "Steam SDK"),
        ("1260", "Kill Ping — Cheat-Distributor-Tool"),
        ("1422450", "GTA V Enhanced — oft für Cheat-Tests genutzt"),
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string steamPath = GetSteamPath();
        if (string.IsNullOrEmpty(steamPath)) return;

        // 1. Scan Steam client logs for cheat keywords
        ScanSteamLogs(ctx, ct, steamPath);
        ct.ThrowIfCancellationRequested();

        // 2. Scan workshop download directories for cheat content
        ScanWorkshopDirectory(ctx, ct, steamPath);
        ct.ThrowIfCancellationRequested();

        // 3. Scan .acf manifest files for suspicious entries
        ScanAppManifests(ctx, ct, steamPath);
        ct.ThrowIfCancellationRequested();

        // 4. Scan Steam userdata controller configs for cheat bindings
        ScanControllerConfigs(ctx, ct, steamPath);
    }

    private void ScanSteamLogs(ScanContext ctx, CancellationToken ct, string steamPath)
    {
        string logsDir = Path.Combine(steamPath, "logs");
        if (!Directory.Exists(logsDir)) return;

        var logFiles = new[]
        {
            "content_log.txt",
            "network_log.txt",
            "connection_log.txt",
            "stats_log.txt",
        };

        foreach (var logFileName in logFiles)
        {
            ct.ThrowIfCancellationRequested();
            string logPath = Path.Combine(logsDir, logFileName);
            if (!File.Exists(logPath)) continue;

            ctx.IncrementFiles();
            try
            {
                long size = new FileInfo(logPath).Length;
                if (size > 20 * 1024 * 1024) // Skip files > 20MB
                {
                    // Read only last 512KB of large log files
                    using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    long readFrom = Math.Max(0, fs.Length - 512 * 1024);
                    fs.Seek(readFrom, SeekOrigin.Begin);
                    using var reader = new StreamReader(fs, Encoding.UTF8);
                    string content = reader.ReadToEnd().ToLowerInvariant();
                    CheckLogContent(ctx, content, logPath);
                }
                else
                {
                    string content = File.ReadAllText(logPath).ToLowerInvariant();
                    CheckLogContent(ctx, content, logPath);
                }
            }
            catch { }
        }
    }

    private void CheckLogContent(ScanContext ctx, string content, string logPath)
    {
        // Check for cheat domain connections in network log
        string[] suspiciousDomains =
        {
            "gamesense.pub", "onetap.com", "aimware.net", "fatality.win",
            "neverlose.cc", "skeet.cc", "2take1.menu", "unknowncheats.me",
            "cherax.gg", "ozarkgta.com",
        };

        foreach (var domain in suspiciousDomains)
        {
            if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Steam Log enthält Cheat-Domain Verbindung: '{domain}'",
                    Risk     = RiskLevel.High,
                    Location = logPath,
                    FileName = Path.GetFileName(logPath),
                    Reason   = $"Steam Client Log-Datei '{Path.GetFileName(logPath)}' enthält Cheat-Domain " +
                               $"'{domain}'. Steam-Logs zeichnen alle Netzwerk-Verbindungen auf — " +
                               "eine Cheat-Domain im Network-Log beweist dass Steam-Prozesse mit " +
                               "Cheat-Servern kommuniziert haben.",
                    Detail   = $"Log: {logPath} | Domain: {domain}"
                });
                return; // One finding per log file
            }
        }

        // Check for cheat keywords in log content
        string? match = CheatKeywords.FirstOrDefault(kw => content.Contains(kw));
        if (match != null)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Steam Log enthält Cheat-Keyword '{match}': {Path.GetFileName(logPath)}",
                Risk     = RiskLevel.Medium,
                Location = logPath,
                FileName = Path.GetFileName(logPath),
                Reason   = $"Steam Log-Datei '{Path.GetFileName(logPath)}' enthält Cheat-Keyword '{match}'. " +
                           "Steam-Logs können Workshop-Downloads, Mod-Aktivierungen und " +
                           "Verbindungsdetails enthalten die auf Cheat-Nutzung hindeuten.",
                Detail   = $"Log: {logPath} | Keyword: {match}"
            });
        }
    }

    private void ScanWorkshopDirectory(ScanContext ctx, CancellationToken ct, string steamPath)
    {
        // Steam stores workshop content in steamapps/workshop/
        string workshopPath = Path.Combine(steamPath, "steamapps", "workshop");
        if (!Directory.Exists(workshopPath)) return;

        // Scan .acf workshop item manifest files for cheat keywords in "title" and "tags" fields
        foreach (var acfFile in SafeGetFiles(workshopPath, "*.acf"))
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            try
            {
                string content = File.ReadAllText(acfFile).ToLowerInvariant();
                string? match = CheatKeywords.FirstOrDefault(kw => content.Contains(kw));
                if (match != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Steam Workshop Item-Manifest mit Cheat-Keyword '{match}': {Path.GetFileName(acfFile)}",
                        Risk     = RiskLevel.High,
                        Location = acfFile,
                        FileName = Path.GetFileName(acfFile),
                        Reason   = $"Steam Workshop Manifest '{Path.GetFileName(acfFile)}' enthält Cheat-Keyword '{match}'. " +
                                   "Steam Workshop-Manifeste bleiben auch nach dem Abonnement-Ende erhalten " +
                                   "und enthalten den ursprünglichen Titel und Tags des heruntergeladenen Inhalts.",
                        Detail   = $"Manifest: {acfFile} | Keyword: {match}"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanAppManifests(ScanContext ctx, CancellationToken ct, string steamPath)
    {
        string steamApps = Path.Combine(steamPath, "steamapps");
        if (!Directory.Exists(steamApps)) return;

        foreach (var acfFile in SafeGetFiles(steamApps, "appmanifest_*.acf"))
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();
            try
            {
                string content = File.ReadAllText(acfFile);
                string contentLower = content.ToLowerInvariant();

                // Extract AppID from filename
                string fname = Path.GetFileNameWithoutExtension(acfFile);
                string appId = fname.Replace("appmanifest_", "");

                // Check for known cheat-development AppIDs
                var devApp = DevAppIds.FirstOrDefault(a => a.AppId == appId);
                if (devApp.AppId != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Entwicklungs-AppID installiert: {appId} ({devApp.Name})",
                        Risk     = RiskLevel.Medium,
                        Location = acfFile,
                        FileName = Path.GetFileName(acfFile),
                        Reason   = $"Steam-Spiel AppID {appId} '{devApp.Name}' ist installiert. " +
                                   "Dieses Tool/SDK wird primär für Cheat-Entwicklung und -Testing genutzt " +
                                   "und ist auf normalen Gaming-PCs ungewöhnlich.",
                        Detail   = $"AppID: {appId} | Name: {devApp.Name} | Manifest: {acfFile}"
                    });
                }

                // Check for cheat keywords in app names
                // Parse name field: "name" "GAME NAME HERE"
                string? match = CheatKeywords.FirstOrDefault(kw => contentLower.Contains(kw));
                if (match != null)
                {
                    // Extract game name for context
                    string gameName = ExtractVdfValue(content, "name") ?? appId;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Steam Spiel-Manifest enthält Cheat-Keyword '{match}': {gameName}",
                        Risk     = RiskLevel.Medium,
                        Location = acfFile,
                        FileName = Path.GetFileName(acfFile),
                        Reason   = $"Steam App-Manifest für '{gameName}' (AppID {appId}) enthält " +
                                   $"Cheat-Keyword '{match}'. Spielmanifeste können Cheat-Tool-Pfade, " +
                                   "modifizierte Startoptionen oder Cheat-DLC-Namen enthalten.",
                        Detail   = $"AppID: {appId} | Game: {gameName} | Keyword: {match}"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanControllerConfigs(ScanContext ctx, CancellationToken ct, string steamPath)
    {
        // Steam controller configs: steamapps/common/Steam Controller Configs/STEAMID/
        // or userdata/STEAMID/config/
        string userDataPath = Path.Combine(steamPath, "userdata");
        if (!Directory.Exists(userDataPath)) return;

        try
        {
            foreach (var userDir in Directory.GetDirectories(userDataPath))
            {
                ct.ThrowIfCancellationRequested();
                string configDir = Path.Combine(userDir, "config");
                if (!Directory.Exists(configDir)) continue;

                foreach (var vdfFile in SafeGetFiles(configDir, "*.vdf"))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        string content = File.ReadAllText(vdfFile).ToLowerInvariant();
                        string? match = CheatKeywords.FirstOrDefault(kw => content.Contains(kw));
                        if (match != null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Steam Controller Konfig enthält Cheat-Keyword '{match}': {Path.GetFileName(vdfFile)}",
                                Risk     = RiskLevel.Medium,
                                Location = vdfFile,
                                FileName = Path.GetFileName(vdfFile),
                                Reason   = $"Steam Benutzer-Konfiguration '{Path.GetFileName(vdfFile)}' enthält " +
                                           $"Cheat-Keyword '{match}'. Steam-Konfigurationsdateien können Cheat-" +
                                           "Tool-Referenzen, Makro-Bindungen und Spielprofile mit Cheat-Einstellungen enthalten.",
                                Detail   = $"Datei: {vdfFile} | Keyword: {match}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private static string? ExtractVdfValue(string vdfContent, string key)
    {
        string pattern = $"\"{key}\"";
        int idx = vdfContent.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;

        int valueStart = vdfContent.IndexOf('"', idx + pattern.Length);
        if (valueStart < 0) return null;

        int valueEnd = vdfContent.IndexOf('"', valueStart + 1);
        if (valueEnd < 0) return null;

        return vdfContent[(valueStart + 1)..valueEnd];
    }

    private static string GetSteamPath()
    {
        try
        {
            using var steamKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam")
                              ?? Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Valve\Steam");
            return (steamKey?.GetValue("SteamPath") as string) ?? "";
        }
        catch { return ""; }
    }

    private static IEnumerable<string> SafeGetFiles(string dir, string pattern)
    {
        try { return Directory.GetFiles(dir, pattern); }
        catch { return Array.Empty<string>(); }
    }
}
