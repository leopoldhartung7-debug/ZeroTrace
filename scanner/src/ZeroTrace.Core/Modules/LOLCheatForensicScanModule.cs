using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class LOLCheatForensicScanModule : IScanModule
{
    public string Name => "League of Legends Cheat Forensic Scan";
    public double Weight => 3.7;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    // Known cheat executable and DLL artifact file names
    private static readonly string[] CheatExecutableNames =
    {
        "lol_aimbot.exe", "lol_scripts.exe", "lol_hack.exe", "lol_cheat.exe",
        "lolfixer.dll", "leaguebot.exe", "lol_script.exe", "evade.dll",
        "evade_aw.dll", "oriana_assist.exe", "lol_dodge.dll", "lol_maphack.dll",
        "leaguescript.exe", "leaguesharp.exe", "ensoulsharp.exe", "kensharp.exe",
        "sunchaser.exe", "elitegolds.exe", "lol_orbwalker.dll", "lol_orbwalker.exe",
        "aware.dll", "aware2.exe", "l_script.dll",
        // Vanguard bypass artifacts
        "lol_vanguard_bypass.dll", "riot_bypass.dll",
        // Riot client bypass tools
        "riot_client_bypass.dll", "riot_services_bypass.exe",
        // Additional known LoL cheat tools
        "lolhack.exe", "lolbot.exe", "lol_bot.exe", "lol_loader.exe",
        "lol_injector.exe", "league_hack.exe", "leaguehack.exe",
        "champion_hack.dll", "lol_esp.dll", "lol_wallhack.dll",
        "league_injector.exe", "lol_triggerbot.exe", "lol_spinbot.exe",
        "lol_skinchanger.dll", "lol_champion_scripts.dll", "lol_macro.exe",
        "lol_evade.dll", "lol_awareness.dll", "lol_prediction.dll",
        "lol_humanizer.dll", "lol_combo.dll", "lol_kite.dll",
        "lol_draw.dll", "lol_menu.dll", "lol_render.dll",
        "sharpmonkey.exe", "sharpmonkey.dll", "gorillascripts.exe",
        "gorebalance.dll", "lolscript.dll", "lolscript.exe",
        "apolloscripts.dll", "apolloscripts.exe",
        "jinxscripts.dll", "leecheonsoftware.dll",
        "scriptengine.dll", "lol_scriptengine.dll",
        "bruiser.dll", "bruiser.exe",
        "lolaio.exe", "lolaio.dll",
        "elitescript.exe", "elitescript.dll",
        "lol_timer.dll", "lol_wardtracker.dll",
        "leaguecoach_cheat.exe", "riot_client_hack.exe",
        "fantome.exe", "fantome.dll",
        "cslol_manager.exe",
        "custom_skin_loader.dll",
        "lol_skin_injector.dll",
        "lol_skin_changer.exe",
    };

    // Cheat-related keywords found in file names (partial match)
    private static readonly string[] CheatFileNameKeywords =
    {
        "lolhack", "lol_cheat", "leaguehack", "lol_aimbot", "lol_script",
        "lol_maphack", "lol_bypass", "riot_bypass", "lol_injector",
        "leaguesharp", "ensoulsharp", "kensharp", "lol_vanguard",
        "lol_spinbot", "lol_wallhack", "lol_orbwalk",
    };

    // Log scanning keywords indicating cheat injection
    private static readonly string[] LogCheatKeywords =
    {
        "injected", "injection", "hook installed", "hook detach", "bypass activated",
        "cheat engine", "script loaded", "lua loaded", "aimbot", "maphack",
        "wallhack", "orbwalker", "evade script", "prediction override",
        "fog bypass", "minimap hack", "esp enabled", "triggerbot",
        "vanguard bypass", "riot bypass", "dll injected", "memory patch",
        "anti-cheat disabled", "anticheat disabled", "eac bypass",
        "spectator bypass", "replay bypass", "packet manipulation",
        "damage hack", "gold hack", "cooldown hack",
    };

    // Lua script keywords indicating LoL cheat scripts
    private static readonly string[] LuaCheatKeywords =
    {
        "aimbot", "orbwalker", "evade", "prediction", "maphack", "esp",
        "wallhack", "fog_of_war", "FogOfWar", "GetMinimapObject",
        "DrawLine", "DrawCircle", "DrawText", "GetEnemyHeroes",
        "GetAllyHeroes", "IsVisible", "SpellBook", "GetCastInfo",
        "GetHeroByIndex", "GetBuffByIndex", "GetItemByIndex",
        "SetSpellCastState", "bypass", "inject", "hook", "detour",
        "memory.read", "memory.write", "WriteProcessMemory",
        "ReadProcessMemory", "VirtualAllocEx", "LoadLibraryA",
        "GetProcAddress", "CreateRemoteThread",
    };

    // IFEO hijack targets
    private static readonly string[] IfeoTargets =
    {
        "LeagueClient.exe", "RiotClientServices.exe", "LeagueClientUx.exe",
        "LeagueClientUxRender.exe", "RiotClient.exe", "League of Legends.exe",
    };

    // Registry Run key cheat loader names
    private static readonly string[] RunKeyCheatNames =
    {
        "lolscript", "lol_script", "leaguesharp", "ensoulsharp", "kensharp",
        "lol_loader", "lol_injector", "lol_hack", "lol_cheat", "leaguebot",
        "lol_aimbot", "lol_maphack", "lol_vanguard_bypass", "riot_bypass",
        "aware", "aware2", "evade", "sunchaser", "elitegolds",
        "lol_orbwalker", "lol_skinchanger", "fantome", "cslol_manager",
    };

    // Known MUICache cheat tool display names
    private static readonly string[] MuiCacheCheatNames =
    {
        "LeagueSharp", "EnsoulSharp", "KenSharp", "LoL Script",
        "LoL Hack", "LeagueBot", "LoL AimBot", "LoL MapHack",
        "Aware", "Evade", "SunChaser", "EliteGolds",
        "LoL Orbwalker", "LoL Skin Changer", "Fantome",
        "CS-LoL Manager", "Custom Skin Loader",
        "OrianAssist", "LoL Dodge", "LoL Fixer",
    };

    // Custom skin loader / Fantome config artifact paths
    private static readonly string[] FantomeArtifactPaths =
    {
        @"CustomSkinLoader\CustomSkinLoader.log",
        @"CustomSkinLoader\config.json",
        @"CustomSkinLoader\skins",
        @"cslol-manager\config.json",
        @"cslol-manager\installed",
        @"fantome\profiles",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting LoL cheat forensic scan");

        await Task.WhenAll(
            CheckCheatExecutablesOnDisk(ctx, ct),
            CheckTempFolderArtifacts(ctx, ct),
            CheckAppDataRiotArtifacts(ctx, ct),
            CheckLuaScriptArtifacts(ctx, ct),
            CheckMaphackConfigArtifacts(ctx, ct),
            CheckCustomSkinLoaderArtifacts(ctx, ct),
            CheckLogFilesForInjectionSignatures(ctx, ct),
            CheckRoflReplayArtifacts(ctx, ct),
            CheckRegistryUserAssist(ctx, ct),
            CheckRegistryMuiCache(ctx, ct),
            CheckRegistryRunKeys(ctx, ct),
            CheckIfeoHijack(ctx, ct),
            CheckVanguardBypassArtifacts(ctx, ct),
            CheckRiotClientBypassArtifacts(ctx, ct)
        );

        ctx.Report(1.0, Name, "LoL cheat forensic scan complete");
    }

    // ---------------------------------------------------------------------------
    // 1. Cheat executables on disk (common directories)
    // ---------------------------------------------------------------------------

    private Task CheckCheatExecutablesOnDisk(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var searchRoots = new List<string>();

            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            var downloads = Path.Combine(userProfile, "Downloads");
            var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            searchRoots.Add(appData);
            searchRoots.Add(localAppData);
            searchRoots.Add(programFiles);
            searchRoots.Add(programFilesX86);
            searchRoots.Add(desktop);
            searchRoots.Add(downloads);
            searchRoots.Add(documents);
            searchRoots.Add(Path.Combine(userProfile, "Games"));
            searchRoots.Add(Path.Combine(userProfile, "Cheats"));
            searchRoots.Add(Path.Combine(userProfile, "Hacks"));
            searchRoots.Add(Path.Combine(userProfile, "Scripts"));
            searchRoots.Add(Path.Combine(localAppData, "Riot Games"));
            searchRoots.Add(Path.Combine(appData, "Riot Games"));

            // Also check all drive roots for common install directories
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "LeagueSharp"));
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "EnsoulSharp"));
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "LoLScript"));
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "LOLScript"));
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "LoLHack"));
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "CheatEngine"));
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "Scripts"));
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "Hacks"));
            }

            var cheatNameSet = new HashSet<string>(CheatExecutableNames, StringComparer.OrdinalIgnoreCase);

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files = Enumerable.Empty<string>();
                try
                {
                    files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);

                    // Exact name match
                    if (cheatNameSet.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"LoL Cheat Artifact Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known League of Legends cheat executable or DLL artifact '{fileName}' " +
                                     "was found on disk. This file is associated with cheat tools, script engines, " +
                                     "aimbot loaders, maphack utilities, or anti-cheat bypass programs targeting League of Legends."
                        });
                        continue;
                    }

                    // Keyword match on file name
                    foreach (var kw in CheatFileNameKeywords)
                    {
                        if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious LoL-Related File: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"File name '{fileName}' matches the League of Legends cheat keyword '{kw}'. " +
                                         "May be a cheat tool, loader, injector, or bypass utility for LoL."
                            });
                            break;
                        }
                    }

                    try
                    {
                        // IOException per file
                    }
                    catch (IOException) { }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 2. Temp folder LoL cheat artifacts
    // ---------------------------------------------------------------------------

    private Task CheckTempFolderArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var tempPaths = new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            };

            var cheatNameSet = new HashSet<string>(CheatExecutableNames, StringComparer.OrdinalIgnoreCase);

            foreach (var tempDir in tempPaths)
            {
                if (!Directory.Exists(tempDir)) continue;

                IEnumerable<string> files = Enumerable.Empty<string>();
                try
                {
                    files = Directory.EnumerateFiles(tempDir, "*.*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);

                    if (cheatNameSet.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"LoL Cheat Artifact in Temp Folder: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known LoL cheat artifact '{fileName}' found in temporary folder '{tempDir}'. " +
                                     "Cheat loaders and injectors commonly stage files in temp directories before injection."
                        });
                        continue;
                    }

                    // Look for LoL-specific temp artifacts by keyword
                    foreach (var kw in CheatFileNameKeywords)
                    {
                        if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious LoL File in Temp: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"File '{fileName}' in temp folder matches LoL cheat keyword '{kw}'. " +
                                         "Cheat loaders often extract or stage components in temp directories."
                            });
                            break;
                        }
                    }

                    try { }
                    catch (IOException) { }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 3. AppData Riot Games folder scanning for cheat artifacts
    // ---------------------------------------------------------------------------

    private Task CheckAppDataRiotArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var riotPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Riot Games"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Riot Games"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Riot Games", "League of Legends"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Riot Games", "League of Legends"),
            };

            var cheatNameSet = new HashSet<string>(CheatExecutableNames, StringComparer.OrdinalIgnoreCase);

            foreach (var riotPath in riotPaths)
            {
                if (!Directory.Exists(riotPath)) continue;

                IEnumerable<string> files = Enumerable.Empty<string>();
                try
                {
                    files = Directory.EnumerateFiles(riotPath, "*.*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    if (cheatNameSet.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"LoL Cheat File in Riot AppData: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known LoL cheat artifact '{fileName}' found inside the Riot Games AppData folder. " +
                                     "This location is unusual for cheat tools and indicates an attempt to blend in with legitimate game files."
                        });
                        continue;
                    }

                    // Suspicious DLL or EXE in Riot folder that are not known legit files
                    if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (var kw in CheatFileNameKeywords)
                        {
                            if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Suspicious LoL-Keyword Binary in Riot AppData: {fileName}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"Binary '{fileName}' inside the Riot Games AppData directory contains " +
                                             $"the LoL cheat keyword '{kw}'. May indicate an injector or bypass tool " +
                                             "attempting to masquerade as a game component."
                                });
                                break;
                            }
                        }
                    }

                    try { }
                    catch (IOException) { }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 4. Lua script file scanning for LoL cheat keywords
    // ---------------------------------------------------------------------------

    private Task CheckLuaScriptArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var luaSearchRoots = new List<string>
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Riot Games"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Riot Games"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents", "League of Legends"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Scripts"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            };

            // Also check common cheat install directories
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                luaSearchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "LeagueSharp", "Scripts"));
                luaSearchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "EnsoulSharp", "Scripts"));
                luaSearchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "LoLScript", "Scripts"));
            }

            foreach (var root in luaSearchRoots)
            {
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files = Enumerable.Empty<string>();
                try
                {
                    files = Directory.EnumerateFiles(root, "*.lua", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var kw in LuaCheatKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"LoL Cheat Lua Script: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Lua script file '{Path.GetFileName(file)}' contains the cheat-related keyword '{kw}'. " +
                                         "League of Legends cheat engines such as LeagueSharp and EnsoulSharp " +
                                         "use Lua scripts to implement aimbot, orbwalker, evade, and maphack functionality.",
                                Detail = $"Matched keyword: {kw}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 5. Maphack / fog-of-war bypass config file artifacts
    // ---------------------------------------------------------------------------

    private Task CheckMaphackConfigArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            // Known maphack config file names / patterns
            var maphackConfigNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "maphack.cfg", "maphack.ini", "maphack.json", "maphack.xml",
                "fog_bypass.cfg", "fog_bypass.ini", "fog_bypass.json",
                "fog_of_war.cfg", "fog_of_war_bypass.cfg",
                "lol_maphack.cfg", "lol_maphack.ini", "lol_maphack.json",
                "minimap_hack.cfg", "minimap_hack.ini",
                "lol_config_cheat.cfg", "lol_settings_cheat.ini",
                "cheat_config.json", "cheat_settings.json",
                "hack_config.cfg", "hack_settings.ini",
                "lol_hack_config.cfg", "lol_hack_settings.ini",
                "orbwalker.cfg", "orbwalker.ini", "orbwalker.json",
                "prediction.cfg", "prediction.ini",
                "evade_config.cfg", "evade_settings.json",
                "aimbot_config.cfg", "aimbot_settings.ini",
            };

            // Keywords in cfg/ini/json that indicate maphack configuration
            var maphackConfigKeywords = new[]
            {
                "fog_of_war", "FogOfWar", "maphack", "MapHack", "map_hack",
                "fog_bypass", "minimap_hack", "vision_hack",
                "draw_fog", "disable_fog", "remove_fog",
                "show_enemies", "show_hidden", "reveal_map",
                "enemy_visibility", "ally_visibility",
                "maphack_enabled", "maphack_active",
            };

            var searchRoots = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            };

            foreach (var root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files = Enumerable.Empty<string>();
                try
                {
                    files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories)
                        .Where(f =>
                        {
                            var ext = Path.GetExtension(f);
                            return ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase)
                                || ext.Equals(".ini", StringComparison.OrdinalIgnoreCase)
                                || ext.Equals(".json", StringComparison.OrdinalIgnoreCase)
                                || ext.Equals(".xml", StringComparison.OrdinalIgnoreCase);
                        });
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);

                    // Direct name match for known maphack config files
                    if (maphackConfigNames.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"LoL Maphack Config Artifact: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Configuration file '{fileName}' matches known League of Legends maphack " +
                                     "or fog-of-war bypass config artifact names. This file was likely created by " +
                                     "a maphack tool that allows players to see through the fog of war."
                        });
                        continue;
                    }

                    // Content scan for maphack keywords in config files
                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    foreach (var kw in maphackConfigKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Maphack Config Keyword in File: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"Configuration file '{fileName}' contains the maphack-related keyword '{kw}'. " +
                                         "This indicates the file may be a configuration for a League of Legends " +
                                         "fog-of-war bypass or minimap hack tool.",
                                Detail = $"Matched keyword: {kw}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 6. Custom skin loader / Fantome artifact scanning
    // ---------------------------------------------------------------------------

    private Task CheckCustomSkinLoaderArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var lolInstallPaths = new List<string>();

            // Common LoL install locations
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                lolInstallPaths.Add(Path.Combine(drive.RootDirectory.FullName, "Riot Games", "League of Legends", "Game"));
                lolInstallPaths.Add(Path.Combine(drive.RootDirectory.FullName, "Program Files", "Riot Games", "League of Legends", "Game"));
                lolInstallPaths.Add(Path.Combine(drive.RootDirectory.FullName, "Program Files (x86)", "Riot Games", "League of Legends", "Game"));
                lolInstallPaths.Add(Path.Combine(drive.RootDirectory.FullName, "Games", "League of Legends", "Game"));
            }

            // Fantome / CSLoL artifact paths relative to LoL install
            var fantomeRelativePaths = new[]
            {
                @"CustomSkinLoader",
                @"cslol-manager",
                @"fantome",
                @"Plugins",
                @"mods",
            };

            // Check for Fantome profile directories and known artifact files
            foreach (var installPath in lolInstallPaths)
            {
                if (!Directory.Exists(installPath)) continue;

                foreach (var relPath in fantomeRelativePaths)
                {
                    var fullPath = Path.Combine(installPath, relPath);
                    if (!Directory.Exists(fullPath) && !File.Exists(fullPath)) continue;

                    if (Directory.Exists(fullPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Custom Skin Tool Directory Found: {relPath}",
                            Risk = RiskLevel.Medium,
                            Location = fullPath,
                            FileName = relPath,
                            Reason = $"Directory '{relPath}' inside the League of Legends installation folder " +
                                     "is associated with custom skin injection tools (Fantome, CSLoL Manager, " +
                                     "CustomSkinLoader). These tools modify game files and may violate ToS."
                        });
                    }
                }

                // Check for specific Fantome log files
                var fantomeLogPath = Path.Combine(installPath, "Plugins", "CustomSkinLoader", "CustomSkinLoader.log");
                if (File.Exists(fantomeLogPath))
                {
                    string logContent;
                    try
                    {
                        using var fs = new FileStream(fantomeLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        logContent = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    if (logContent.Length > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "CustomSkinLoader Activity Log Found",
                            Risk = RiskLevel.Medium,
                            Location = fantomeLogPath,
                            FileName = "CustomSkinLoader.log",
                            Reason = "The CustomSkinLoader activity log was found inside the League of Legends " +
                                     "game directory. CustomSkinLoader and Fantome are third-party tools that inject " +
                                     "custom champion and item skins into LoL, potentially violating the game's Terms of Service.",
                            Detail = $"Log size: {logContent.Length} characters"
                        });
                    }
                }
            }

            // Also check AppData for CSLoL manager config
            var appDataPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "cslol-manager"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "cslol-manager"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "fantome"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "fantome"),
            };

            foreach (var path in appDataPaths)
            {
                if (!Directory.Exists(path)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Custom Skin Tool AppData Directory: {Path.GetFileName(path)}",
                    Risk = RiskLevel.Medium,
                    Location = path,
                    FileName = Path.GetFileName(path),
                    Reason = $"AppData directory '{Path.GetFileName(path)}' was found, associated with the " +
                             "Fantome or CSLoL Manager custom skin injection tools for League of Legends."
                });
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 7. LoL log file scanning for cheat injection signatures
    // ---------------------------------------------------------------------------

    private Task CheckLogFilesForInjectionSignatures(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var logDirectories = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Riot Games", "League of Legends", "Logs"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Riot Games", "League of Legends", "Logs"),
            };

            // Also check standard drive LoL install log paths
            var extraLogDirs = new List<string>();
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                extraLogDirs.Add(Path.Combine(drive.RootDirectory.FullName, "Riot Games", "League of Legends", "Logs"));
                extraLogDirs.Add(Path.Combine(drive.RootDirectory.FullName, "Games", "League of Legends", "Logs"));
            }

            var allLogDirs = logDirectories.Concat(extraLogDirs);

            foreach (var logDir in allLogDirs)
            {
                if (!Directory.Exists(logDir)) continue;

                IEnumerable<string> logFiles = Enumerable.Empty<string>();
                try
                {
                    logFiles = Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var logFile in logFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var kw in LogCheatKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Cheat Injection Signature in LoL Log: {Path.GetFileName(logFile)}",
                                Risk = RiskLevel.High,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"League of Legends log file '{Path.GetFileName(logFile)}' contains the " +
                                         $"cheat-related keyword '{kw}'. This may indicate that a cheat tool, " +
                                         "script injector, or Vanguard bypass was active during a game session.",
                                Detail = $"Matched keyword: {kw}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 8. LoL replay file (.rofl) scanning for suspicious identifiers
    // ---------------------------------------------------------------------------

    private Task CheckRoflReplayArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var replayDirs = new List<string>
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Riot Games", "League of Legends", "Replays"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Riot Games", "League of Legends", "Replays"),
            };

            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                replayDirs.Add(Path.Combine(drive.RootDirectory.FullName, "Riot Games", "League of Legends", "Replays"));
            }

            // Keywords in .rofl metadata that indicate suspicious clients or modified clients
            var roflSuspiciousKeywords = new[]
            {
                "cheat", "hack", "script", "bot", "aimbot", "maphack",
                "leaguesharp", "ensoulsharp", "kensharp", "lolscript",
                "modified", "patched", "bypass", "injector",
                "customclient", "fake_client", "spoof",
            };

            foreach (var replayDir in replayDirs)
            {
                if (!Directory.Exists(replayDir)) continue;

                IEnumerable<string> replayFiles = Enumerable.Empty<string>();
                try
                {
                    replayFiles = Directory.EnumerateFiles(replayDir, "*.rofl", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var roflFile in replayFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    // .rofl files are binary but contain JSON metadata sections
                    string content;
                    try
                    {
                        using var fs = new FileStream(roflFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, System.Text.Encoding.Latin1);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var kw in roflSuspiciousKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious Identifier in LoL Replay: {Path.GetFileName(roflFile)}",
                                Risk = RiskLevel.Medium,
                                Location = roflFile,
                                FileName = Path.GetFileName(roflFile),
                                Reason = $"League of Legends replay file '{Path.GetFileName(roflFile)}' contains " +
                                         $"the suspicious identifier '{kw}' in its metadata. This may indicate " +
                                         "a match was played with a modified or cheat-enabled client.",
                                Detail = $"Matched keyword: {kw}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 9. Registry UserAssist scanning for LoL cheat EXE launches
    // ---------------------------------------------------------------------------

    private Task CheckRegistryUserAssist(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var cheatNameSet = new HashSet<string>(CheatExecutableNames, StringComparer.OrdinalIgnoreCase);

            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                using var ua = baseKey.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
                if (ua is null) return;

                foreach (var guid in ua.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    using var count = ua.OpenSubKey($@"{guid}\Count");
                    if (count is null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in count.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        var decoded = Rot13Decode(valueName);
                        if (string.IsNullOrWhiteSpace(decoded)) continue;

                        var fileName = SafeGetFileName(decoded);

                        // Exact cheat executable name match
                        if (cheatNameSet.Contains(fileName))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"LoL Cheat EXE UserAssist Entry: {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                                FileName = fileName,
                                Reason = $"UserAssist registry entry records that the known LoL cheat executable " +
                                         $"'{fileName}' was launched from the GUI. UserAssist tracks program " +
                                         "launches via Windows Explorer and the Start Menu, including deleted files.",
                                Detail = $"Decoded path: {decoded}"
                            });
                            continue;
                        }

                        // Keyword match on file name
                        foreach (var kw in CheatFileNameKeywords)
                        {
                            if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Suspicious LoL-Keyword EXE in UserAssist: {fileName}",
                                    Risk = RiskLevel.High,
                                    Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                                    FileName = fileName,
                                    Reason = $"UserAssist registry entry records a GUI launch of '{fileName}', " +
                                             $"which matches the LoL cheat keyword '{kw}'. This EXE was launched " +
                                             "from the user's session.",
                                    Detail = $"Decoded path: {decoded}"
                                });
                                break;
                            }
                        }
                    }
                }
            }
            catch { }
        }, ct);

    // ---------------------------------------------------------------------------
    // 10. Registry MUICache scanning for LoL cheat tool names
    // ---------------------------------------------------------------------------

    private Task CheckRegistryMuiCache(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var muiCacheKeys = new[]
            {
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                @"Software\Microsoft\Windows\ShellNoRoam\MUICache",
            };

            var cheatNameSet = new HashSet<string>(MuiCacheCheatNames, StringComparer.OrdinalIgnoreCase);
            var cheatExeSet = new HashSet<string>(CheatExecutableNames, StringComparer.OrdinalIgnoreCase);

            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);

                foreach (var keyPath in muiCacheKeys)
                {
                    if (ct.IsCancellationRequested) return;

                    using var muiKey = baseKey.OpenSubKey(keyPath);
                    if (muiKey is null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in muiKey.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        if (string.IsNullOrWhiteSpace(valueName)) continue;

                        var displayName = muiKey.GetValue(valueName)?.ToString() ?? string.Empty;
                        var fileName = SafeGetFileName(valueName);

                        // Check display name against known cheat tool names
                        foreach (var cheatName in cheatNameSet)
                        {
                            if (displayName.Contains(cheatName, StringComparison.OrdinalIgnoreCase) ||
                                valueName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"LoL Cheat Tool in MUICache: {cheatName}",
                                    Risk = RiskLevel.High,
                                    Location = @"HKCU\" + keyPath,
                                    FileName = fileName,
                                    Reason = $"MUICache registry entry references the known LoL cheat tool '{cheatName}'. " +
                                             "MUICache stores display names of executed applications and persists even " +
                                             "after the cheat tool has been uninstalled or deleted.",
                                    Detail = $"Value name: {valueName} | Display: {displayName}"
                                });
                                break;
                            }
                        }

                        // Check executable file name against known cheat executables
                        if (cheatExeSet.Contains(fileName))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"LoL Cheat EXE in MUICache: {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = @"HKCU\" + keyPath,
                                FileName = fileName,
                                Reason = $"MUICache contains an entry for the known LoL cheat executable '{fileName}'. " +
                                         "This entry was created when the application was executed and persists after deletion.",
                                Detail = $"Registered path: {valueName}"
                            });
                        }
                    }
                }
            }
            catch { }
        }, ct);

    // ---------------------------------------------------------------------------
    // 11. Registry Run keys for LoL cheat loaders
    // ---------------------------------------------------------------------------

    private Task CheckRegistryRunKeys(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var runKeyPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            };

            var cheatRunNames = new HashSet<string>(RunKeyCheatNames, StringComparer.OrdinalIgnoreCase);
            var cheatExeSet = new HashSet<string>(CheatExecutableNames, StringComparer.OrdinalIgnoreCase);

            var hives = new[]
            {
                (RegistryHive.LocalMachine, "HKLM"),
                (RegistryHive.CurrentUser, "HKCU"),
            };

            foreach (var (hive, hiveName) in hives)
            {
                if (ct.IsCancellationRequested) return;

                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);

                    foreach (var keyPath in runKeyPaths)
                    {
                        if (ct.IsCancellationRequested) return;

                        using var runKey = baseKey.OpenSubKey(keyPath);
                        if (runKey is null) continue;
                        ctx.IncrementRegistryKeys();

                        foreach (var valueName in runKey.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            if (string.IsNullOrWhiteSpace(valueName)) continue;

                            var valueData = runKey.GetValue(valueName)?.ToString() ?? string.Empty;
                            var fileName = SafeGetFileName(valueData);

                            // Check value name against known cheat loader names
                            foreach (var cheatName in cheatRunNames)
                            {
                                if (valueName.Contains(cheatName, StringComparison.OrdinalIgnoreCase) ||
                                    valueData.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"LoL Cheat Loader in Run Key: {valueName}",
                                        Risk = RiskLevel.Critical,
                                        Location = $@"{hiveName}\{keyPath}",
                                        FileName = fileName,
                                        Reason = $"Registry Run key '{hiveName}\\{keyPath}\\{valueName}' references " +
                                                 $"the LoL cheat loader keyword '{cheatName}'. Run keys cause programs " +
                                                 "to launch automatically at system startup, indicating persistent cheat installation.",
                                        Detail = $"Value data: {valueData}"
                                    });
                                    break;
                                }
                            }

                            // Check executable name in Run key value data
                            if (cheatExeSet.Contains(fileName))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Known LoL Cheat EXE in Run Key: {fileName}",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"{hiveName}\{keyPath}",
                                    FileName = fileName,
                                    Reason = $"Registry Run key '{hiveName}\\{keyPath}' is configured to launch " +
                                             $"the known LoL cheat executable '{fileName}' at system startup. " +
                                             "This indicates a persistent cheat loader installation.",
                                    Detail = $"Value name: {valueName} | Value data: {valueData}"
                                });
                            }
                        }
                    }
                }
                catch { }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 12. IFEO hijack of LeagueClient.exe / RiotClientServices.exe
    // ---------------------------------------------------------------------------

    private Task CheckIfeoHijack(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string ifeoKeyPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

            foreach (var target in IfeoTargets)
            {
                if (ct.IsCancellationRequested) return;

                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                    using var ifeoKey = baseKey.OpenSubKey($@"{ifeoKeyPath}\{target}");
                    if (ifeoKey is null) continue;
                    ctx.IncrementRegistryKeys();

                    // Check for Debugger value (the primary IFEO hijack vector)
                    var debugger = ifeoKey.GetValue("Debugger")?.ToString();
                    if (!string.IsNullOrWhiteSpace(debugger))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"IFEO Debugger Hijack on {target}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{ifeoKeyPath}\{target}",
                            FileName = target,
                            Reason = $"Image File Execution Options (IFEO) registry key for '{target}' contains " +
                                     $"a Debugger value pointing to '{debugger}'. IFEO hijacking is a technique used " +
                                     "by cheat loaders and bypass tools to intercept League of Legends or Riot Client " +
                                     "process launch and inject malicious code before the game starts.",
                            Detail = $"Debugger: {debugger}"
                        });
                    }

                    // Check for GlobalFlag that might indicate a cheat loader exploit
                    var globalFlag = ifeoKey.GetValue("GlobalFlag")?.ToString();
                    if (!string.IsNullOrWhiteSpace(globalFlag) && globalFlag != "0")
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"IFEO GlobalFlag Set on {target}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{ifeoKeyPath}\{target}",
                            FileName = target,
                            Reason = $"IFEO registry key for '{target}' has a non-zero GlobalFlag value '{globalFlag}'. " +
                                     "Non-standard GlobalFlag settings may be used by cheat tools to manipulate " +
                                     "the startup behavior of the League of Legends or Riot client process.",
                            Detail = $"GlobalFlag: {globalFlag}"
                        });
                    }
                }
                catch { }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 13. Vanguard-specific bypass artifact scanning
    // ---------------------------------------------------------------------------

    private Task CheckVanguardBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var vanguardBypassFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "lol_vanguard_bypass.dll", "riot_bypass.dll",
                "vanguard_bypass.dll", "vanguard_bypass.exe",
                "vgk_bypass.dll", "vgk_bypass.exe",
                "vanguard_spoof.dll", "vanguard_spoof.exe",
                "riot_vanguard_bypass.dll", "riot_vanguard_bypass.exe",
                "vanguard_disable.exe", "vanguard_kill.exe",
                "vgk_unload.exe", "vgk_spoof.dll",
                "anticheat_bypass.dll", "ac_bypass.dll",
                "vanguard_unhook.dll", "vanguard_patch.dll",
                "lol_anticheat_bypass.dll", "lol_bypass.dll",
                "disable_vanguard.bat", "disable_vanguard.ps1",
                "disable_vgk.bat", "disable_vgk.ps1",
                "vgk_bypass.bat", "vgk_bypass.ps1",
            };

            var vanguardBypassKeywords = new[]
            {
                "vanguard_bypass", "vgk_bypass", "riot_bypass", "lol_vanguard",
                "vanguard_spoof", "disable_vangrd", "unhook_vanguard",
            };

            var searchRoots = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
            };

            foreach (var root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files = Enumerable.Empty<string>();
                try
                {
                    files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);

                    if (vanguardBypassFiles.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Vanguard Bypass Artifact: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known Riot Vanguard anti-cheat bypass artifact '{fileName}' was found on disk. " +
                                     "Vanguard bypass tools are specifically designed to disable or circumvent Riot's " +
                                     "kernel-level anti-cheat system to allow cheating in League of Legends and other Riot titles."
                        });
                        continue;
                    }

                    foreach (var kw in vanguardBypassKeywords)
                    {
                        if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Vanguard Bypass Keyword in File: {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason = $"File '{fileName}' matches the Vanguard bypass keyword '{kw}'. " +
                                         "This file may be part of a toolkit designed to disable or evade " +
                                         "Riot Vanguard's anti-cheat detection in League of Legends.",
                                Detail = $"Matched keyword: {kw}"
                            });
                            break;
                        }
                    }

                    try { }
                    catch (IOException) { }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 14. Riot Client bypass artifact scanning
    // ---------------------------------------------------------------------------

    private Task CheckRiotClientBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var riotClientBypassFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "riot_client_bypass.dll", "riot_services_bypass.exe",
                "riot_client_hack.exe", "riot_client_patch.dll",
                "riotclient_bypass.dll", "riotservices_bypass.exe",
                "riot_client_spoof.dll", "riot_auth_bypass.dll",
                "riot_login_bypass.dll", "riot_client_inject.dll",
                "riotclient_inject.exe", "riot_client_loader.exe",
                "league_client_bypass.dll", "leagueclient_bypass.exe",
                "leagueclientux_bypass.dll", "leagueclientuxrender_bypass.dll",
                "riot_account_bypass.exe", "riot_ban_bypass.exe",
                "lol_hwid_bypass.dll", "lol_hwid_spoofer.exe",
                "riot_hwid_bypass.dll", "riot_hwid_spoofer.exe",
                "hwid_changer_lol.exe", "hwid_spoofer_lol.exe",
            };

            // Content keywords in config/script files indicating Riot client bypass
            var riotClientBypassKeywords = new[]
            {
                "riot_client_bypass", "riotclient_bypass", "riot_services_bypass",
                "league_client_bypass", "riot_auth_bypass", "riot_login_bypass",
                "riot_hwid_bypass", "hwid_spoofer_lol",
                "RiotClientServices.exe bypass", "LeagueClient.exe bypass",
                "ban bypass", "hwid bypass", "hwid spoof",
            };

            var searchRoots = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
            };

            foreach (var root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files = Enumerable.Empty<string>();
                try
                {
                    files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    if (riotClientBypassFiles.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Riot Client Bypass Artifact: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known Riot Client bypass tool '{fileName}' found on disk. " +
                                     "Riot Client bypass tools intercept, patch, or spoof the Riot authentication and " +
                                     "client services to circumvent bans, HWID restrictions, or client-side anti-cheat checks."
                        });
                        continue;
                    }

                    // For script/config files, also scan content for bypass keywords
                    if (ext.Equals(".bat", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".vbs", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".js", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".py", StringComparison.OrdinalIgnoreCase))
                    {
                        string content;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }
                        catch (UnauthorizedAccessException) { continue; }

                        foreach (var kw in riotClientBypassKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Riot Client Bypass Script: {fileName}",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"Script file '{fileName}' contains the Riot Client bypass keyword '{kw}'. " +
                                             "This script may automate the bypass of Riot Games account restrictions, " +
                                             "HWID bans, or client authentication in League of Legends.",
                                    Detail = $"Matched keyword: {kw}"
                                });
                                break;
                            }
                        }
                    }

                    try { }
                    catch (IOException) { }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // Helper methods
    // ---------------------------------------------------------------------------

    private static string Rot13Decode(string s)
    {
        var a = s.ToCharArray();
        for (int i = 0; i < a.Length; i++)
        {
            char c = a[i];
            if (c is >= 'A' and <= 'Z') a[i] = (char)('A' + (c - 'A' + 13) % 26);
            else if (c is >= 'a' and <= 'z') a[i] = (char)('a' + (c - 'a' + 13) % 26);
        }
        return new string(a);
    }

    private static string SafeGetFileName(string path)
    {
        try { return Path.GetFileName(path.TrimEnd('\\', '/', ' ', '"')) ?? string.Empty; }
        catch { return path; }
    }
}
