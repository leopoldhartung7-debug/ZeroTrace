using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans game configuration files for cheat-enabling console variables (CVars),
/// autoexec commands, and config file modifications that enable wallhack-like
/// features, ESP rendering tricks, or disable AC-triggering game checks.
///
/// Attack vectors:
///   - CS2/CSGO autoexec.cfg with mat_wireframe, r_drawothermodels, enable_skeleton_draw
///   - CS2 convars that expose player positions through walls via rendering tricks
///   - Apex Legends local.cfg with Pak_LoadOrderList / steam_nooverlap for bypasses
///   - Overwatch / Overwatch 2 custom game settings exported with hacks enabled
///   - Battlefield series: bIsClient_CheatEnabled, render.drawEntityBoundingBoxes
///   - Rust server.cfg / client.cfg with debug rendering CVars
///   - EFT (Escape From Tarkov) local game config patches
///   - Valorant portable config manipulation (val_cfg_* keys)
///   - FiveM (GTA V) resource configs that bypass AC scripts
///   - General pattern: any game config file with debug/render CVars known to be
///     used for visual cheating that are normally only exposed in dev builds
/// </summary>
public sealed class GameConfigCheatCommandScanModule : IScanModule
{
    public string Name => "Game Config Cheat Command / CVar Detection";
    public double Weight => 0.65;
    public int ParallelGroup => 4;

    private record ConfigEntry(string Game, string FileName, string[] SearchPaths,
        string[]? CheatCVars, string[]? CheatPatterns, bool IsHighRisk);

    private static readonly ConfigEntry[] GameConfigs =
    {
        new("CS2/CSGO", "autoexec.cfg",
            new[]
            {
                @"C:\Program Files (x86)\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\cfg",
                @"C:\Program Files\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\cfg",
                @"D:\Steam\steamapps\common\Counter-Strike Global Offensive\game\csgo\cfg",
                @"D:\Games\steamapps\common\Counter-Strike Global Offensive\game\csgo\cfg",
            },
            new[]
            {
                "r_drawothermodels",    // render wireframe through walls
                "mat_wireframe",        // wireframe mode (see through walls)
                "enable_skeleton_draw", // skeleton ESP
                "r_visualizetraces",    // bullet trace visualization
                "sv_cheats",            // enable cheat CVars server-side (also used in local bypass)
                "r_drawsprites",        // sprite visualization
                "cl_showpos",           // position reveal (minor, but cheat-associated)
                "r_showenvcubemap",     // environment map bypass
                "mat_fullbright",       // removes lighting (wallhack aid)
                "r_eyegloss",
                "bind_osx",             // obfuscated bind commands
                "exec cheat",           // explicit exec of cheat config
                "exec hack",
                "exec esp",
                "exec wh",
                "exec wallhack",
                "exec aimbot",
            },
            new[]
            {
                // Obfuscated base64-like exec patterns
                @"exec [a-zA-Z0-9+/]{20,}",
                @"alias ""[^""]{1,8}"" ""[^""]*cheat[^""]*""",
            },
            IsHighRisk: true),

        new("Apex Legends", "local.cfg",
            new[]
            {
                @"C:\Program Files (x86)\Steam\steamapps\common\Apex Legends\cfg",
                @"C:\Program Files\Steam\steamapps\common\Apex Legends\cfg",
                @"D:\Steam\steamapps\common\Apex Legends\cfg",
                @"D:\Games\steamapps\common\Apex Legends\cfg",
            },
            new[]
            {
                "r_drawworld",          // disable world rendering (helps ESP clarity)
                "r_flashlightlockposition", // flashlight cheat abuse
                "r_visualizeculling",   // culling bypass visibility
                "mat_wireframe",
                "r_drawothermodels",
                "steam_nooverlap",      // bypass Steam overlay AC hooks
                "Pak_LoadOrderList",    // custom PAK loading for modified game assets
                "cl_particle_max_count 0", // disable particles (FPS/visibility cheat)
                "cl_showpos",
            },
            null,
            IsHighRisk: true),

        new("Rust", "client.cfg",
            new[]
            {
                @"C:\Program Files (x86)\Steam\steamapps\common\Rust",
                @"C:\Program Files\Steam\steamapps\common\Rust",
                @"D:\Steam\steamapps\common\Rust",
                @"D:\Games\steamapps\common\Rust",
            },
            new[]
            {
                "debugcamera",          // free camera / ESP
                "global.debugoverlay",  // debug overlay rendering
                "admin.mutevoice",
                "vehicle.debug",
                "physics.paused",
                "global.wireframe",     // wireframe mode
                "debug.pathfinding",
                "global.debug",
            },
            null,
            IsHighRisk: false),

        new("GTA V / FiveM", "settings.xml",
            new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "Rockstar Games", "GTA V"),
            },
            null,
            new[]
            {
                "cheat", "noclip", "godmode", "freecam",
                "timescale", "wanted_level.*0",
            },
            IsHighRisk: false),

        new("Battlefield (BF1/BFV/BF2042)", "PROF_SAVE_profile",
            new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "Battlefield 1", "settings"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "Battlefield V", "settings"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "Battlefield 2042", "settings"),
            },
            new[]
            {
                "render.drawEntityBoundingBoxes",
                "render.drawFontScreenInfo",
                "DebugRender.DrawScreenInfo",
                "GstInput.MouseSensitivity 0", // sensitivity set to 0 = aimbot override
                "GstRender.ResolutionScale 0",
            },
            null,
            IsHighRisk: false),

        new("Escape From Tarkov", "local.ini",
            new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Battlestate Games", "EFT", "Local", "Sc"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Battlestate Games", "EFT"),
            },
            new[]
            {
                "NodeDebugEnabled",
                "ConsoleEnabled",
                "FrameRateLimit 0",
                "BSGLauncher_Cheat",
                "cheat",
            },
            null,
            IsHighRisk: false),

        new("Valorant", "GameUserSettings.ini",
            new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "VALORANT", "Saved", "Config"),
            },
            new[]
            {
                "bIsMouseSmoothingEnabled=False",   // aim assist tweak pattern
                "bForceFeedbackEnabled=False",
                "CheatEnabled",
                "VGK_DebugMode",
            },
            null,
            IsHighRisk: false),
    };

    // CVars that are high-signal cheat indicators across ALL games
    private static readonly HashSet<string> UniversalCheatCVars = new(StringComparer.OrdinalIgnoreCase)
    {
        "wallhack", "aimbot", "triggerbot", "spinbot", "bhop", "bunnyhop",
        "norecoil", "no_recoil", "no recoil", "noknockback", "speedhack",
        "rapidfire", "autofire", "silentaim", "silent_aim",
        "esp_enabled", "radar_enabled",
        "bypass_ac", "bypass ac", "anticheat_bypass",
        "cheat_enabled", "hack_enabled",
        "sv_cheats 1",
        "exec cheat", "exec hack", "exec esp", "exec wh",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            foreach (var config in GameConfigs)
            {
                ct.ThrowIfCancellationRequested();
                ScanGameConfig(config, ctx, ct);
            }

            // Also scan Steam userdata dirs for per-user game configs
            ScanSteamUserdata(ctx, ct);
        }, ct);
    }

    private static void ScanGameConfig(ConfigEntry config, ScanContext ctx, CancellationToken ct)
    {
        foreach (var searchPath in config.SearchPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(searchPath) && !File.Exists(searchPath)) continue;

            try
            {
                // Get all cfg files if directory, or just the specific file
                IEnumerable<string> files;
                if (Directory.Exists(searchPath))
                {
                    files = Directory.EnumerateFiles(searchPath, "*.cfg", SearchOption.TopDirectoryOnly)
                        .Concat(Directory.EnumerateFiles(searchPath, "*.ini", SearchOption.TopDirectoryOnly))
                        .Concat(Directory.EnumerateFiles(searchPath, "*.xml", SearchOption.TopDirectoryOnly));
                }
                else
                {
                    files = new[] { searchPath };
                }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    AnalyzeConfigFile(file, config, ctx);
                }
            }
            catch { }
        }
    }

    private static void AnalyzeConfigFile(string filePath, ConfigEntry config, ScanContext ctx)
    {
        try
        {
            var lines = File.ReadAllLines(filePath);
            var findings = new List<(string line, string cvar, int lineNum)>();

            for (int i = 0; i < lines.Length; i++)
            {
                string line    = lines[i];
                string lineLow = line.ToLowerInvariant().Trim();

                // Skip comments
                if (lineLow.StartsWith("//") || lineLow.StartsWith(";") || lineLow.StartsWith("#"))
                    continue;

                // Check game-specific CVars
                if (config.CheatCVars is not null)
                {
                    foreach (var cvar in config.CheatCVars)
                    {
                        if (lineLow.Contains(cvar.ToLowerInvariant()))
                        {
                            findings.Add((line.Trim(), cvar, i + 1));
                        }
                    }
                }

                // Check universal cheat CVars
                foreach (var universalCvar in UniversalCheatCVars)
                {
                    if (lineLow.Contains(universalCvar.ToLowerInvariant()))
                    {
                        findings.Add((line.Trim(), universalCvar, i + 1));
                    }
                }
            }

            foreach (var (line, cvar, lineNum) in findings)
            {
                bool isHighRisk = config.IsHighRisk ||
                                  UniversalCheatCVars.Contains(cvar);

                ctx.AddFinding(new Finding
                {
                    Module   = "Game Config Cheat Command / CVar Detection",
                    Title    = $"Cheat-CVar in {config.Game}-Konfiguration: {cvar}",
                    Risk     = isHighRisk ? RiskLevel.High : RiskLevel.Medium,
                    Location = filePath,
                    FileName = Path.GetFileName(filePath),
                    Reason   = $"Spiel-Konfigurationsdatei '{Path.GetFileName(filePath)}' für '{config.Game}' " +
                               $"enthält CVar/Befehl '{cvar}' (Zeile {lineNum}) — bekannt als Cheat-Aktivierungs-" +
                               "befehl, Wallhack-Render-Override oder AC-Umgehungs-CVar",
                    Detail   = $"Spiel: {config.Game} | Datei: {filePath} | Zeile {lineNum}: {line} | " +
                               $"CVar: {cvar}"
                });
            }
        }
        catch { }
    }

    private static void ScanSteamUserdata(ScanContext ctx, CancellationToken ct)
    {
        string[] steamRoots =
        {
            @"C:\Program Files (x86)\Steam\userdata",
            @"C:\Program Files\Steam\userdata",
            @"D:\Steam\userdata",
            @"D:\Games\userdata",
        };

        // CS2 app ID = 730, CSGO = 730
        string[] gameAppIds = { "730", "218620", "1172470", "359550", "1824220" };
        // CS2, Payday2, ApexLegends, RSiege, BF2042

        foreach (var root in steamRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var userDir in Directory.EnumerateDirectories(root))
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (var appId in gameAppIds)
                    {
                        ct.ThrowIfCancellationRequested();
                        string cfgPath = Path.Combine(userDir, appId, "local", "cfg");
                        if (!Directory.Exists(cfgPath)) continue;

                        try
                        {
                            foreach (var cfgFile in Directory.EnumerateFiles(cfgPath, "*.cfg"))
                            {
                                ct.ThrowIfCancellationRequested();
                                ctx.IncrementFiles();
                                AnalyzeConfigFile(cfgFile, GameConfigs[0], ctx); // Use CS2 config for all
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }
    }
}
