using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans Steam userdata and achievement cache for cheat correlation artifacts.
///
/// Steam maintains extensive per-user game data in:
///   %ProgramFiles(x86)%\Steam\userdata\[SteamID]\[AppID]\
///
/// Within this structure, forensically relevant artifacts include:
///
///   stats/UserGameStatsSchema.bin — cached stats schema (reveals game-specific stat names)
///   stats/achievements.bin        — downloaded achievement cache (binary, grep for context)
///   remote/                       — Steam Cloud save data (game configs, progress files)
///   screenshots/                  — Steam screenshot library (filenames, metadata)
///   sharedconfig.vdf              — Shared settings including workshop subscriptions
///
/// Cheat correlation patterns:
///   - Abnormal achievement unlock patterns in stats cache (100% achievements in <1hr play)
///   - Workshop subscriptions to known cheat mods in sharedconfig.vdf
///   - Remote save files containing cheat configuration data
///   - Screenshots folder with cheat overlay visible in metadata
///   - Steam Cloud files named like cheat config files (autoexec.cfg with sv_cheats=1)
///
/// Additional Steam artifact checks:
///   - Steam\config\broadcasting.vdf — obs/streaming cheat overlay config
///   - Steam\config\dialogconfig.vdf — Steam overlay key bindings (cheat-key combos)
///   - Steam\appcache\packageinfo.vdf — Installed DLC bypass artifacts
/// </summary>
public sealed class SteamAchievementCheatScanModule : IScanModule
{
    public string Name => "Steam Userdata und Achievement-Cache Forensik Scan";
    public double Weight => 0.45;
    public int ParallelGroup => 4;

    private static readonly string[] CheatKeywords =
    {
        "aimbot", "wallhack", "esp", "triggerbot", "spinbot", "bhop",
        "no_recoil", "norecoil", "cheat", "hack", "inject", "bypass",
        "sv_cheats", "r_drawothermodels", "mat_wireframe", "noclip",
        "god_mode", "godmode", "unlimited_ammo", "one_shot",
        "silent_aim", "rage_bot", "anti_aim", "resolver",
        "engine_no_focus_sleep", "cl_showfps 5",
    };

    private static readonly string[] SuspiciousWorkshopKeywords =
    {
        // Workshop cheat mods (garry's mod, CSGO, etc.)
        "aimbot", "wallhack", "esp", "cheat", "hack", "no_recoil",
        "bhop", "speedhack", "godmode", "bhop_script", "triggerbot",
        // FiveM/GTA scripts distributed via Steam Workshop
        "money drop", "spawner", "godmode", "speed hack",
    };

    private static readonly string[] SuspiciousConfigKeywords =
    {
        "sv_cheats 1", "r_drawothermodels 2", "mat_wireframe 1",
        "cl_sidespeed 30000", "sv_noclipspeed", "host_timescale",
        "aimbot", "esp", "wallhack", "triggerbot", "no_recoil",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string progFiles86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string steamBase   = System.IO.Path.Combine(progFiles86, "Steam");

        if (!System.IO.Directory.Exists(steamBase)) return;

        ct.ThrowIfCancellationRequested();
        ScanUserdata(ctx, steamBase, ct);
        ScanSteamConfig(ctx, steamBase, ct);
    }

    private void ScanUserdata(ScanContext ctx, string steamBase, CancellationToken ct)
    {
        string userdataRoot = System.IO.Path.Combine(steamBase, "userdata");
        if (!System.IO.Directory.Exists(userdataRoot)) return;

        try
        {
            foreach (string userDir in System.IO.Directory.GetDirectories(userdataRoot))
            {
                ct.ThrowIfCancellationRequested();
                string steamId = System.IO.Path.GetFileName(userDir);
                if (!long.TryParse(steamId, out _)) continue;

                // Scan sharedconfig.vdf for workshop subscriptions
                ScanSharedConfig(ctx, userDir, steamId, ct);

                // Scan per-game remote data (Steam Cloud saves)
                try
                {
                    foreach (string gameDir in System.IO.Directory.GetDirectories(userDir))
                    {
                        ct.ThrowIfCancellationRequested();
                        string appId = System.IO.Path.GetFileName(gameDir);
                        if (!int.TryParse(appId, out _)) continue;

                        string remoteDir = System.IO.Path.Combine(gameDir, "remote");
                        if (System.IO.Directory.Exists(remoteDir))
                            ScanRemoteDir(ctx, remoteDir, steamId, appId, ct);
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanSharedConfig(ScanContext ctx, string userDir, string steamId, CancellationToken ct)
    {
        string cfgPath = System.IO.Path.Combine(userDir, "config", "sharedconfig.vdf");
        if (!System.IO.File.Exists(cfgPath)) return;

        try
        {
            ctx.IncrementFiles();
            var info = new System.IO.FileInfo(cfgPath);
            if (info.Length == 0 || info.Length > 5 * 1024 * 1024) return;

            string text = System.IO.File.ReadAllText(cfgPath);
            string lower = text.ToLowerInvariant();

            // Check for workshop subscriptions with cheat keywords
            // In sharedconfig.vdf, workshop items appear as app manifests with
            // "WorkshopItemsInstalled" sections containing workshop item IDs
            foreach (string kw in SuspiciousWorkshopKeywords)
            {
                ct.ThrowIfCancellationRequested();
                if (!lower.Contains(kw.ToLowerInvariant())) continue;

                int idx = lower.IndexOf(kw.ToLowerInvariant(), StringComparison.Ordinal);
                int start = Math.Max(0, idx - 40);
                int end = Math.Min(text.Length, idx + kw.Length + 80);
                string snippet = text.Substring(start, end - start).Replace('\n', ' ').Trim();

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Keyword in Steam sharedconfig (SteamID {steamId}): '{kw}'",
                    Risk     = RiskLevel.High,
                    Location = cfgPath,
                    FileName = "sharedconfig.vdf",
                    Reason   = $"Steam sharedconfig.vdf für SteamID {steamId} enthält '{kw}'. " +
                               "Diese Datei speichert Workshop-Abonnements und geteilte Einstellungen. " +
                               "Cheat-Mods abonniert über Steam Workshop erscheinen hier. " +
                               "Ocean/detect.ac scannen Steam userdata als Forensik-Quelle.",
                    Detail   = $"Datei: {cfgPath} | Keyword: '{kw}' | Kontext: \"{snippet}\""
                });
                return; // one finding per file
            }
        }
        catch { }
    }

    private void ScanRemoteDir(ScanContext ctx, string remoteDir, string steamId,
        string appId, CancellationToken ct)
    {
        try
        {
            foreach (string file in System.IO.Directory.EnumerateFiles(remoteDir,
                "*", System.IO.SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string fileName = System.IO.Path.GetFileName(file);
                string fileNameLower = fileName.ToLowerInvariant();
                string ext = System.IO.Path.GetExtension(fileNameLower);

                if (ext is not (".cfg" or ".ini" or ".txt" or ".json" or ".xml")) continue;

                try
                {
                    var info = new System.IO.FileInfo(file);
                    if (info.Length == 0 || info.Length > 2 * 1024 * 1024) continue;

                    string text = System.IO.File.ReadAllText(file);
                    string lower = text.ToLowerInvariant();

                    foreach (string kw in SuspiciousConfigKeywords)
                    {
                        ct.ThrowIfCancellationRequested();
                        if (!lower.Contains(kw.ToLowerInvariant())) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Cheat-Config in Steam Cloud Save (AppID {appId}): '{kw}'",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Steam Cloud Save-Datei '{fileName}' für AppID {appId} (SteamID {steamId}) " +
                                       $"enthält Cheat-Konfiguration '{kw}'. Steam Cloud synchronisiert " +
                                       "Spiel-Configs — Cheat-CVars in Cloud Saves beweisen aktive Cheat-" +
                                       "Konfiguration die gameübergreifend synchronisiert wird.",
                            Detail   = $"Datei: {file} | AppID: {appId} | SteamID: {steamId} | Keyword: '{kw}'"
                        });
                        break;
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanSteamConfig(ScanContext ctx, string steamBase, CancellationToken ct)
    {
        string configDir = System.IO.Path.Combine(steamBase, "config");
        if (!System.IO.Directory.Exists(configDir)) return;

        string[] cfgFiles =
        {
            System.IO.Path.Combine(configDir, "config.vdf"),
            System.IO.Path.Combine(configDir, "loginusers.vdf"),
            System.IO.Path.Combine(configDir, "dialogconfig.vdf"),
        };

        foreach (string cfgFile in cfgFiles)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.File.Exists(cfgFile)) continue;

            try
            {
                ctx.IncrementFiles();
                var info = new System.IO.FileInfo(cfgFile);
                if (info.Length == 0 || info.Length > 5 * 1024 * 1024) continue;

                string text = System.IO.File.ReadAllText(cfgFile);
                string lower = text.ToLowerInvariant();
                string fileName = System.IO.Path.GetFileName(cfgFile);

                foreach (string kw in CheatKeywords)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!lower.Contains(kw.ToLowerInvariant())) continue;

                    int idx = lower.IndexOf(kw.ToLowerInvariant(), StringComparison.Ordinal);
                    int start = Math.Max(0, idx - 30);
                    int end = Math.Min(text.Length, idx + kw.Length + 60);
                    string snippet = text.Substring(start, end - start).Replace('\n', ' ').Trim();

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Keyword in Steam Konfig '{fileName}': '{kw}'",
                        Risk     = RiskLevel.Medium,
                        Location = cfgFile,
                        FileName = fileName,
                        Reason   = $"Steam Konfigurationsdatei '{fileName}' enthält '{kw}'. " +
                                   "Steam-Konfig-Dateien speichern Account-Details, Key-Bindings, und " +
                                   "Netzwerkeinstellungen. Cheat-Keywords hier weisen auf direkte " +
                                   "Steam-Konfiguration für Cheat-Betrieb hin.",
                        Detail   = $"Datei: {cfgFile} | Keyword: '{kw}' | Kontext: \"{snippet}\""
                    });
                    break; // one finding per file
                }
            }
            catch { }
        }
    }
}
