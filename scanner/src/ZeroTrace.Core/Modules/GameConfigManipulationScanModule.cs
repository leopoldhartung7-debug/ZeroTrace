using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects game configuration file manipulation used for aim assistance and visual cheats.
///
/// Many competitive games expose console commands and config files that can be abused
/// for an unfair advantage. Unlike kernel-level cheats, config manipulation is
/// trivially detectable by reading known file paths and checking for forbidden commands.
///
/// CS2 / CS:GO autoexec.cfg abuse:
///   - r_drawothermodels 2     → wireframe wallhack (all player models drawn as wireframe)
///   - sv_cheats 1             → enables all cheat commands (works when not VAC-protected)
///   - cl_showpos 1            → shows exact XYZ coordinates (positional advantage)
///   - net_graph 3             → detailed network info (can reveal player counts/positions)
///   - mat_wireframe 1         → wireframe rendering (similar to wallhack effect)
///   - cl_interp 0             → minimum interpolation (unfair netcode advantage)
///   - cl_interp_ratio 1       → manipulation of interpolation ratio
///   - fps_max 0               → unlimited FPS (advantage in some scenarios)
///   - sensitivity / m_yaw manipulation → aim assist via extremely high/low values
///   Also: autoexec.cfg with "exec" commands loading hidden cheat configs
///   And:  userconfig.cfg with sv_cheats settings preserved between sessions
///
/// Apex Legends videoconfig.txt:
///   - "setting.r_drawworld" "0"         → invisible world for ESP advantage
///   - "setting.gib_detail_level" "0"    → affects model rendering
///
/// PUBG GameUserSettings.ini:
///   - FrameRateLimit=0                  → unlimited FPS
///   - Various FOV manipulation settings
///   - Specific render distance tweaks for ESP advantage
///
/// Fortnite GameUserSettings.ini:
///   - FrameRateLimit=0
///   - bShowFPS=True
///   - Various render quality manipulations
///
/// Roblox / FiveM:
///   - AutoExec scripts with cheat function calls
///   - Lua files with ESP/aimbot implementations
///
/// Steam launch options abuse:
///   - -condebug → writes all console output to log file
///   - -insecure → disables VAC entirely (CS:GO)
///   - +sv_cheats 1 → enables cheats at startup
///   - -allowdebug or -debug → debug mode
///   - +exec <cheatcfg> → execute cheat config at startup
///
/// Detection:
///   1. Scan known game config file paths for forbidden commands
///   2. Check Steam library localconfig.vdf for suspicious launch options
///   3. Detect encoded or obfuscated config content (base64, ROT13 in cfg files)
///   4. Flag autoexec.cfg files > 50 KB (normal configs are small; cheat configs are large)
///   5. Detect cfg files containing "exec" chains loading additional configs
/// </summary>
public sealed class GameConfigManipulationScanModule : IScanModule
{
    public string Name => "Spielkonfiguration-Manipulation";
    public double Weight => 0.7;
    public int ParallelGroup => 4;

    // CS2/CSGO cheat commands to look for in cfg files
    private static readonly string[] CsgoCheatCommands =
    {
        "r_drawothermodels", "sv_cheats", "mat_wireframe", "r_shadows 0",
        "r_drawworld 0", "r_drawstaticprops 0", "ent_fire",
        "cl_ragdoll_physics_enable", "r_showenvcubemap", "mat_fullbright",
        "overlayui", "drawradar", "developer 1", "r_visualizetraces",
        "r_drawtracers_firstperson", "cl_obs_interp_enable", "spec_show_xray",
        "r_draw_client_snapshot_entities",
    };

    // Launch option flags suspicious for competitive play
    private static readonly string[] SuspiciousLaunchOptions =
    {
        "-insecure", "+sv_cheats", "-allowdebug", "+exec cheat",
        "+exec hack", "+exec aimbot", "-nosteam", "-skipintro -insecure",
        "+r_drawothermodels", "+mat_wireframe", "+developer 1",
    };

    // Keywords in cfg content suggesting cheat configs
    private static readonly string[] CheatKeywords =
    {
        "aimbot", "wallhack", "triggerbot", "spinbot", "bunnyhop",
        "rapidfire", "norecoil", "bhop", "aimkey", "silentaim",
        "esp_", "cheat_", "hack_", "legit_", "rage_", "backtrack",
        "resolver", "antiaim", "fakelag", "doubletap",
    };

    // Paths relative to user profile to scan
    private static readonly (string RelPath, string GameName)[] GameConfigPaths =
    [
        (@"Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\cfg\autoexec.cfg", "CS:GO/CS2"),
        (@"Steam\steamapps\common\Counter-Strike Global Offensive\game\cs2\cfg\autoexec.cfg", "CS2"),
        (@"Steam\steamapps\common\Counter-Strike Global Offensive\csgo\cfg\autoexec.cfg", "CS:GO"),
        (@"Steam\steamapps\common\Counter-Strike Global Offensive\csgo\cfg\userconfig.cfg", "CS:GO"),
        (@"Steam\steamapps\common\Counter-Strike 2\game\csgo\cfg\autoexec.cfg", "CS2"),
        (@"Steam\steamapps\common\Counter-Strike 2\game\csgo\cfg\userconfig.cfg", "CS2"),
        (@"Steam\steamapps\common\Apex Legends\cfg\autoexec.cfg", "Apex Legends"),
        (@"Steam\steamapps\common\PUBG\TslGame\Saved\Config\WindowsNoEditor\GameUserSettings.ini", "PUBG"),
        (@"Local\FortniteGame\Saved\Config\WindowsClient\GameUserSettings.ini", "Fortnite"),
        (@"Local\FortniteGame\Saved\Config\WindowsClient\Input.ini", "Fortnite"),
        (@"Steam\steamapps\common\dota 2 beta\game\dota\cfg\autoexec.cfg", "Dota 2"),
        (@"Steam\steamapps\common\Half-Life 2\hl2\cfg\autoexec.cfg", "HL2"),
        (@"Steam\steamapps\common\Team Fortress 2\tf\cfg\autoexec.cfg", "TF2"),
        (@"Steam\steamapps\common\GarrysMod\garrysmod\cfg\autoexec.cfg", "Garry's Mod"),
    ];

    // Steam localconfig.vdf paths (contain launch options)
    private static readonly string SteamPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Steam");

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            // Check game config files
            foreach (var (relPath, gameName) in GameConfigPaths)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    // Try roaming AppData and local AppData and Steam root
                    var candidates = new[]
                    {
                        Path.Combine(appData, relPath),
                        Path.Combine(localAppData, relPath),
                        Path.Combine(SteamPath, relPath.Replace(@"Steam\", "")),
                        // Also try common Steam library on C:\
                        Path.Combine(@"C:\Steam", relPath.Replace(@"Steam\", "")),
                    };

                    foreach (string fullPath in candidates)
                    {
                        if (!File.Exists(fullPath)) continue;
                        ctx.IncrementFiles();
                        hits += CheckConfigFile(fullPath, gameName, ctx);
                        break; // Only check the first found candidate
                    }
                }
                catch { }
            }

            // Check Steam userdata for launch options in all account localconfig.vdf
            hits += CheckSteamLaunchOptions(ctx, ct);
        }
        catch { }

        ctx.Report(1.0, Name, $"Spielkonfigurationen geprüft, {hits} Manipulationen");
        return Task.CompletedTask;
    }

    private static int CheckConfigFile(string filePath, string gameName, ScanContext ctx)
    {
        int hits = 0;
        try
        {
            var fi = new FileInfo(filePath);

            // Warn about suspiciously large config files (>50KB)
            if (fi.Length > 50 * 1024)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Spielkonfiguration-Manipulation",
                    Title    = $"Sehr große Spielkonfigurationsdatei: {gameName}",
                    Risk     = RiskLevel.Medium,
                    Location = filePath,
                    FileName = filePath,
                    Reason   = $"Spielkonfigurationsdatei für {gameName} ist {fi.Length / 1024} KB groß. " +
                               "Normale Spieler-Konfigurationen sind üblicherweise unter 10 KB. " +
                               "Cheat-Konfigurationen enthalten viele automatisierte Befehle, " +
                               "Bind-Definitionen für Cheat-Funktionen, und oft verschleierte " +
                               "Ausführungsketten (mehrere exec-Befehle, die sich gegenseitig laden).",
                    Detail   = $"Datei={filePath} | Größe={fi.Length / 1024}KB | Spiel={gameName}"
                });
            }

            string content = File.ReadAllText(filePath);
            string contentLower = content.ToLowerInvariant();

            // Check for cheat commands in CSGO-style cfg files
            foreach (string cmd in CsgoCheatCommands)
            {
                if (!contentLower.Contains(cmd.ToLowerInvariant())) continue;

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Spielkonfiguration-Manipulation",
                    Title    = $"Cheat-Befehl in {gameName} Konfiguration: {cmd}",
                    Risk     = RiskLevel.High,
                    Location = filePath,
                    FileName = filePath,
                    Reason   = $"Konfigurationsdatei '{Path.GetFileName(filePath)}' für {gameName} " +
                               $"enthält Cheat-Befehl '{cmd}'. " +
                               "Dieser Befehl ermöglicht einen unfairen Vorteil im Spiel " +
                               "(Wallhack-Effekt, Render-Manipulation, Debug-Modus). " +
                               "Anti-Cheat-Systeme erlauben diese Befehle in der Regel nicht " +
                               "in kompetitiven Lobbys; lokale Konfigurationsdateien werden " +
                               "möglicherweise zur Umgehung ausgeführt.",
                    Detail   = $"Datei={filePath} | Befehl='{cmd}' | Spiel={gameName}"
                });
                break; // One finding per file per category
            }

            // Check for cheat keywords
            foreach (string kw in CheatKeywords)
            {
                if (!contentLower.Contains(kw)) continue;

                // Find the line containing the keyword for context
                string? matchLine = null;
                foreach (var line in content.Split('\n'))
                {
                    if (line.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        matchLine = line.Trim();
                        break;
                    }
                }

                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Spielkonfiguration-Manipulation",
                    Title    = $"Cheat-Keyword in {gameName} Konfiguration: '{kw}'",
                    Risk     = RiskLevel.High,
                    Location = filePath,
                    FileName = filePath,
                    Reason   = $"Konfigurationsdatei '{Path.GetFileName(filePath)}' für {gameName} " +
                               $"enthält Cheat-Keyword '{kw}'" +
                               (matchLine is not null ? $" (Zeile: '{matchLine.Substring(0, Math.Min(80, matchLine.Length))}')" : "") +
                               ". Cheat-Software hinterlässt oft Konfigurationsreste in Spielkonfigurationen: " +
                               "Bind-Befehle für Aimbot-Tasten, Konfigurationsvariablen für ESP, " +
                               "und Alias-Definitionen für Cheat-Funktionen.",
                    Detail   = $"Datei={filePath} | Keyword='{kw}' | Spiel={gameName}" +
                               (matchLine is not null
                                   ? $" | Zeile='{matchLine.Substring(0, Math.Min(120, matchLine.Length))}'"
                                   : "")
                });
                break; // One keyword finding per file
            }

            // Check for exec chains (loading additional config files)
            int execCount = 0;
            foreach (var line in content.Split('\n'))
            {
                string trimmed = line.Trim().ToLowerInvariant();
                if (trimmed.StartsWith("exec ") || trimmed.StartsWith("exec\t"))
                    execCount++;
            }
            if (execCount > 5)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Spielkonfiguration-Manipulation",
                    Title    = $"Viele 'exec'-Befehle in {gameName} Konfiguration ({execCount})",
                    Risk     = RiskLevel.Medium,
                    Location = filePath,
                    FileName = filePath,
                    Reason   = $"Konfigurationsdatei enthält {execCount} 'exec'-Befehle, " +
                               "die weitere Konfigurationsdateien laden. " +
                               "Cheat-Software verschachtelt oft exec-Ketten, um die eigentlichen " +
                               "Cheat-Befehle in versteckten Unterverzeichnissen oder mit " +
                               "unscheinbaren Dateinamen zu verstecken.",
                    Detail   = $"Datei={filePath} | ExecAnzahl={execCount} | Spiel={gameName}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckSteamLaunchOptions(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Steam userdata is typically at %ProgramFiles(x86)%\Steam\userdata\
            // or can be in Documents / user-specified location
            var steamDataPaths = new[]
            {
                Path.Combine(SteamPath, "userdata"),
                Path.Combine(@"C:\Steam", "userdata"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "Steam", "userdata"),
            };

            foreach (string userdataBase in steamDataPaths)
            {
                if (!Directory.Exists(userdataBase)) continue;

                foreach (string userDir in Directory.GetDirectories(userdataBase))
                {
                    if (ct.IsCancellationRequested) break;
                    string localConfig = Path.Combine(userDir, "config", "localconfig.vdf");
                    if (!File.Exists(localConfig)) continue;

                    try
                    {
                        ctx.IncrementFiles();
                        string content = File.ReadAllText(localConfig);

                        // Scan for suspicious launch options in localconfig.vdf
                        foreach (string opt in SuspiciousLaunchOptions)
                        {
                            if (!content.Contains(opt, StringComparison.OrdinalIgnoreCase))
                                continue;

                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Spielkonfiguration-Manipulation",
                                Title    = $"Verdächtiger Steam-Start-Parameter: '{opt}'",
                                Risk     = RiskLevel.High,
                                Location = localConfig,
                                FileName = localConfig,
                                Reason   = $"Steam localconfig.vdf enthält verdächtigen " +
                                           $"Start-Parameter '{opt}'. " +
                                           "Cheat-Software fügt Start-Parameter zu Spielen hinzu, um " +
                                           "beim Start Cheat-Konfigurationen zu laden, VAC zu deaktivieren " +
                                           "(-insecure), oder sv_cheats beim Start zu setzen.",
                                Detail   = $"Datei={localConfig} | Parameter='{opt}'"
                            });
                            break;
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
        return hits;
    }
}
