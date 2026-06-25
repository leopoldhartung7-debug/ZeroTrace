using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class Dota2CheatArtifactScanModule : IScanModule
{
    public string Name => "Dota 2 Cheat Forensic Scan";
    public double Weight => 3.5;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    // Known Dota 2 cheat executable and DLL artifact file names
    private static readonly string[] CheatExecutableNames =
    {
        "dota2_hack.exe", "dota2_aimbot.exe", "dota2_maphack.exe", "dota2_cheat.exe",
        "dota2esp.dll", "dota_maphack.dll", "dota2_script.exe", "skadistats.dll",
        "dawgware.dll", "dota2clarity.dll", "d2hack.exe", "ensuredota.dll",
        "dota2trainer.exe", "dota2_orbwalker.dll",
        // VAC bypass artifacts
        "dota2_vac_bypass.dll", "vac_dota2.exe", "dota2_steam_bypass.dll",
        // Garena bypass tools
        "garena_bypass.exe", "garena_dota2.dll",
        // Additional known Dota 2 cheat tools
        "dota2_loader.exe", "dota2_injector.exe", "dota2_esp.dll",
        "dota2_wallhack.dll", "dota2_nohaze.dll", "dota2_zoom.dll",
        "dota2_speed.dll", "dota2_gold.dll", "dota2_hero_hack.dll",
        "dota2_item_hack.dll", "dota2_cooldown.dll", "dota2_range.dll",
        "dota2_menu.dll", "dota2_draw.dll", "dota2_render.dll",
        "dota2_humanizer.dll", "dota2_combo.dll", "dota2_kite.dll",
        "dota2hack.exe", "dota2hack.dll", "d2aimbot.exe", "d2aimbot.dll",
        "d2maphack.exe", "d2maphack.dll", "d2esp.exe", "d2esp.dll",
        "dota_esp.dll", "dota_aimbot.exe", "dota_hack.exe", "dota_cheat.exe",
        "dota2_bypass.dll", "dota2_bypass.exe",
        "dota2_vac_spoof.dll", "dota2_steam_spoof.dll",
        "vac_bypass.dll", "vac_bypass.exe",
        "dota2_awareness.dll", "dota2_prediction.dll",
        "dota2_lastorder.dll", "dota2_auto_rune.dll",
        "dota2_auto_last.dll", "dota2_orbwalk.dll",
        "dota2_invoker.dll", "dota2_storm.dll",
        "dota2_pudge.dll", "dota2_sniper.dll",
        "dota2_io.dll", "dota2_io.exe",
        "dota2_clarity.exe", "clarity_dota2.dll",
        "d2botsharp.exe", "d2botsharp.dll",
        "dota2clarity.exe", "dota2_lens.dll",
        "gaben_hack.dll", "purgehack.dll",
        "dota2cheater.exe", "d2cheater.dll",
        "overtimer.dll", "overtimer.exe",
        "dota2_spellbot.dll", "dota2_laneparty.dll",
        "dota2_ally_spy.dll", "dota2_enemy_spy.dll",
    };

    // Cheat-related keywords found in file names (partial match)
    private static readonly string[] CheatFileNameKeywords =
    {
        "dota2hack", "dota2_hack", "dota2_cheat", "dota2_aimbot",
        "dota2_maphack", "dota2_esp", "dota2_bypass", "dota2_vac",
        "dota_hack", "dota_cheat", "dota_aimbot", "dota_maphack",
        "d2hack", "d2cheat", "d2aimbot", "d2maphack", "d2esp",
        "dota2_inject", "dota2_loader", "vac_bypass", "dota2_steam_bypass",
        "garena_bypass", "garena_dota",
    };

    // Dota 2 config cheat keywords
    private static readonly string[] ConfigCheatKeywords =
    {
        "maphack_enabled", "hero_esp", "item_esp", "auto_rune", "auto_rune_enabled",
        "maphack", "map_hack", "fog_bypass", "fog_of_war_bypass",
        "hero_visibility", "item_visibility", "courier_esp",
        "auto_last_hit", "auto_deny", "orbwalker_enabled",
        "spell_dodge", "auto_spell", "auto_combo",
        "tower_range_draw", "draw_range", "draw_attack_range",
        "aimbot_enabled", "aim_assist", "aimbot_fov",
        "wallhack_enabled", "wallhack", "no_haze",
        "zoom_hack", "camera_hack", "no_camera_limit",
        "speed_hack", "speedhack", "speed_multiplier",
        "gold_hack", "resource_hack", "no_cooldown",
        "reveal_hero", "reveal_creep", "show_hidden",
        "auto_rune_control", "rune_sniper",
        "enemy_hero_pos", "reveal_ward",
        "anti_detect", "bypass_vac", "bypass_anticheat",
        "steam_bypass", "vac_bypass", "vac_disable",
    };

    // Dota 2 Lua script cheat keywords
    private static readonly string[] LuaCheatKeywords =
    {
        "maphack", "hero_esp", "item_esp", "auto_rune",
        "fog_bypass", "FogOfWar", "GetAllHeroMinimapIcons",
        "GetHeroByIndex", "GetItemByIndex", "GetSpellByIndex",
        "DrawCircle", "DrawLine", "DrawText", "DrawFilledRect",
        "GetAbilityByIndex", "GetModifierByIndex",
        "SetCameraTarget", "SetCameraPosition",
        "bypass", "inject", "hook", "detour",
        "WriteProcessMemory", "ReadProcessMemory",
        "VirtualAllocEx", "LoadLibraryA", "GetProcAddress",
        "CreateRemoteThread", "memory.read", "memory.write",
        "aimbot", "orbwalker", "lastorder", "auto_cast",
        "GetNearbyHeroes", "GetNearbyCreeps",
        "IsVisible", "IsInvisible", "IsChanneling",
        "TriggerAutoAttack", "ForceAttack",
        "dota_camera_distance", "cl_fog_of_war",
    };

    // VAC bypass and Steam bypass keywords for file content scanning
    private static readonly string[] VacBypassKeywords =
    {
        "vac_bypass", "VAC bypass", "bypass VAC", "disable VAC",
        "vac_disable", "vac_disable_modules", "VAC_Disable",
        "steam_bypass", "steam_auth_bypass", "SteamAuth bypass",
        "dota2_vac_bypass", "vac_dota2", "dota2_steam_bypass",
        "VACSteam", "SteamBypass", "VACBypass",
        "sv_cheats 1", "sv_cheats=1",
        "disable_anticheat", "anticheat_bypass",
        "vac_modules_bypass", "vac_unhook",
    };

    // Registry MUICache cheat tool display names
    private static readonly string[] MuiCacheCheatNames =
    {
        "Dota2Hack", "Dota 2 Hack", "Dota2 MapHack", "Dota2MapHack",
        "Dota2 Aimbot", "Dota2Aimbot", "Dota2 ESP", "Dota2ESP",
        "Dota2 Cheat", "Dota2Cheat", "D2Hack", "D2Cheat",
        "DotaClarity", "Dota2Clarity", "Dawgware", "Skadistats",
        "EnsureDota", "Dota2Trainer", "GarenaBypass", "VACBypass",
        "Dota2VACBypass", "SteamBypass", "Dota2SteamBypass",
    };

    // Registry Run key cheat loader names
    private static readonly string[] RunKeyCheatNames =
    {
        "dota2hack", "dota2_hack", "dota2_cheat", "dota2_aimbot",
        "dota2_maphack", "dota2_loader", "dota2_injector",
        "dota2_vac_bypass", "dota2_steam_bypass", "vac_bypass",
        "garena_bypass", "garena_dota", "dota2clarity", "dawgware",
        "d2hack", "d2cheat", "d2aimbot", "d2maphack",
        "dota2trainer", "ensuredota",
    };

    // IFEO hijack targets for Dota 2
    private static readonly string[] IfeoTargets =
    {
        "dota2.exe", "steam.exe", "steamwebhelper.exe",
        "GameOverlayUI.exe", "GameOverlayRenderer.dll",
    };

    // Known Dota 2 Steam Workshop exploit script patterns
    private static readonly string[] WorkshopExploitKeywords =
    {
        "exploit", "cheat", "hack", "bypass",
        "Entities:FindByClassname", "GetPlayerEntIndex",
        "backdoor", "remote_exec", "rcon",
        "sv_cheats", "net_fakelag", "net_fakeloss",
        "cl_cmdrate 0", "cl_updaterate 0",
        "WriteByte", "WriteShort", "WriteLong",
        "SendPacket", "ReceivePacket",
    };

    // Known Dota 2 overlay abuse indicator paths
    private static readonly string[] OverlayAbuseArtifacts =
    {
        "dota2_overlay_hack.dll",
        "steam_overlay_bypass.dll",
        "steamoverlay_inject.dll",
        "overlay_esp.dll",
        "dota2_overlay_esp.dll",
        "dota2_overlay_aimbot.dll",
        "steam_overlay_hack.dll",
        "GameOverlayHack.dll",
        "dota2_overlay_cheat.dll",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Dota 2 cheat forensic scan");

        await Task.WhenAll(
            CheckCheatExecutablesOnDisk(ctx, ct),
            CheckTempFolderArtifacts(ctx, ct),
            CheckDota2ConfigFolderArtifacts(ctx, ct),
            CheckLuaScriptArtifacts(ctx, ct),
            CheckVacBypassArtifacts(ctx, ct),
            CheckGarenaBypassArtifacts(ctx, ct),
            CheckCustomGameExploitArtifacts(ctx, ct),
            CheckWorkshopExploitScripts(ctx, ct),
            CheckRegistryUserAssist(ctx, ct),
            CheckRegistryMuiCache(ctx, ct),
            CheckRegistryRunKeys(ctx, ct),
            CheckIfeoHijack(ctx, ct),
            CheckSteamOverlayAbuseArtifacts(ctx, ct),
            CheckVacLogArtifacts(ctx, ct)
        );

        ctx.Report(1.0, Name, "Dota 2 cheat forensic scan complete");
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

            // Steam library paths and common game directories
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "Steam", "steamapps", "common", "dota 2 beta"));
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "Program Files", "Steam", "steamapps", "common", "dota 2 beta"));
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "Program Files (x86)", "Steam", "steamapps", "common", "dota 2 beta"));
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "Dota2Hack"));
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "DotaHack"));
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "D2Hack"));
                searchRoots.Add(Path.Combine(drive.RootDirectory.FullName, "Cheats"));
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

                    if (cheatNameSet.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Dota 2 Cheat Artifact Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known Dota 2 cheat executable or DLL artifact '{fileName}' was found on disk. " +
                                     "This file is associated with Dota 2 cheat tools including aimbot, maphack, " +
                                     "ESP, VAC bypass, orbwalker, or auto-rune utilities."
                        });
                        continue;
                    }

                    foreach (var kw in CheatFileNameKeywords)
                    {
                        if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious Dota 2 Cheat-Keyword File: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"File name '{fileName}' matches the Dota 2 cheat keyword '{kw}'. " +
                                         "May be a cheat tool, loader, injector, or bypass utility targeting Dota 2.",
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
    // 2. Temp folder Dota 2 cheat artifacts
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
                            Title = $"Dota 2 Cheat Artifact in Temp Folder: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known Dota 2 cheat artifact '{fileName}' found in temporary folder '{tempDir}'. " +
                                     "Cheat loaders and injectors commonly stage components in temp directories " +
                                     "before injection into the game process."
                        });
                        continue;
                    }

                    foreach (var kw in CheatFileNameKeywords)
                    {
                        if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious Dota 2 File in Temp Folder: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"File '{fileName}' in temp folder matches Dota 2 cheat keyword '{kw}'. " +
                                         "Cheat loaders often extract and stage components in temp directories.",
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
    // 3. Dota 2 config folder scanning for cheat keywords
    // ---------------------------------------------------------------------------

    private Task CheckDota2ConfigFolderArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            // Dota 2 cfg directories across known Steam library roots
            var dota2ConfigRoots = new List<string>();

            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                var steamRoots = new[]
                {
                    Path.Combine(drive.RootDirectory.FullName, "Steam"),
                    Path.Combine(drive.RootDirectory.FullName, "Program Files", "Steam"),
                    Path.Combine(drive.RootDirectory.FullName, "Program Files (x86)", "Steam"),
                    Path.Combine(drive.RootDirectory.FullName, "Games", "Steam"),
                };

                foreach (var steamRoot in steamRoots)
                {
                    var dota2Base = Path.Combine(steamRoot, "steamapps", "common", "dota 2 beta", "game", "dota");
                    dota2ConfigRoots.Add(Path.Combine(dota2Base, "cfg"));
                    dota2ConfigRoots.Add(Path.Combine(dota2Base, "custom_games"));
                    dota2ConfigRoots.Add(Path.Combine(dota2Base, "scripts"));
                    dota2ConfigRoots.Add(Path.Combine(steamRoot, "steamapps", "common", "dota 2 beta", "game", "dota", "addons"));
                }
            }

            // Also check user cfg directories
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            dota2ConfigRoots.Add(Path.Combine(localAppData, "dota 2 beta", "cfg"));

            // Config file names that are known maphack/cheat configs
            var knownCheatConfigNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "maphack.cfg", "maphack.ini", "cheat.cfg", "cheat.ini",
                "aimbot.cfg", "aimbot.ini", "esp.cfg", "esp.ini",
                "hack.cfg", "hack.ini", "dota2_hack.cfg", "dota2_cheat.cfg",
                "dota2_maphack.cfg", "dota2_aimbot.cfg", "dota2_esp.cfg",
                "auto_rune.cfg", "autorun_hack.cfg", "auto_last_hit.cfg",
                "fog_bypass.cfg", "wallhack.cfg", "speedhack.cfg",
                "vac_bypass.cfg", "bypass.cfg",
                "dota2_config_cheat.cfg", "dota2_settings_cheat.cfg",
            };

            foreach (var configDir in dota2ConfigRoots)
            {
                if (!Directory.Exists(configDir)) continue;

                IEnumerable<string> files = Enumerable.Empty<string>();
                try
                {
                    files = Directory.EnumerateFiles(configDir, "*.*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    // Direct name match
                    if (knownCheatConfigNames.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Dota 2 Cheat Config File: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known Dota 2 cheat configuration file '{fileName}' found in the Dota 2 " +
                                     "config directory. This file is associated with maphack, aimbot, ESP, " +
                                     "or other cheat configurations for Dota 2."
                        });
                        continue;
                    }

                    // Content scan for config/script files
                    if (ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".ini", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".json", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".lua", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".txt", StringComparison.OrdinalIgnoreCase))
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

                        foreach (var kw in ConfigCheatKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Cheat Keyword in Dota 2 Config: {fileName}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"Dota 2 configuration file '{fileName}' contains the cheat-related " +
                                             $"keyword '{kw}'. This may indicate an active cheat configuration " +
                                             "for maphack, hero ESP, item ESP, auto-rune, or other cheats.",
                                    Detail = $"Matched keyword: {kw}"
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 4. Lua script artifact scanning for Dota 2 cheat keywords
    // ---------------------------------------------------------------------------

    private Task CheckLuaScriptArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var luaSearchRoots = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            };

            // Dota 2 addon/custom game script locations
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                var steamRoots = new[]
                {
                    Path.Combine(drive.RootDirectory.FullName, "Steam"),
                    Path.Combine(drive.RootDirectory.FullName, "Program Files", "Steam"),
                    Path.Combine(drive.RootDirectory.FullName, "Program Files (x86)", "Steam"),
                };

                foreach (var steamRoot in steamRoots)
                {
                    var dota2Scripts = Path.Combine(steamRoot, "steamapps", "common", "dota 2 beta", "game", "dota", "scripts", "vscripts");
                    luaSearchRoots.Add(dota2Scripts);

                    var dota2Addons = Path.Combine(steamRoot, "steamapps", "common", "dota 2 beta", "game", "dota", "addons");
                    luaSearchRoots.Add(dota2Addons);

                    var workshopScripts = Path.Combine(steamRoot, "steamapps", "workshop", "content", "570");
                    luaSearchRoots.Add(workshopScripts);
                }
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
                                Title = $"Dota 2 Cheat Lua Script: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Lua script '{Path.GetFileName(file)}' contains the Dota 2 cheat keyword '{kw}'. " +
                                         "Dota 2 cheat scripts leverage the Lua/VScript API to implement maphack, " +
                                         "aimbot, auto-rune, ESP, and orbwalker functionality.",
                                Detail = $"Matched keyword: {kw}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 5. VAC bypass artifact scanning
    // ---------------------------------------------------------------------------

    private Task CheckVacBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var vacBypassFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "dota2_vac_bypass.dll", "vac_dota2.exe", "dota2_steam_bypass.dll",
                "vac_bypass.dll", "vac_bypass.exe",
                "vac_bypass_x64.dll", "vac_bypass_x86.dll",
                "vac_spoof.dll", "vac_spoof.exe",
                "steam_bypass.dll", "steam_bypass.exe",
                "steam_emu.dll", "steam_api_bypass.dll",
                "steamclient_bypass.dll", "steamclient_spoof.dll",
                "vac_disable.exe", "vac_disable.dll",
                "vac_unhook.dll", "vac_unhook.exe",
                "vac_patch.dll", "vac_patch.exe",
                "steamapi_bypass.dll", "steam_api64_bypass.dll",
                "dota2_steam_spoof.dll", "dota2_vac_spoof.dll",
                "vac_dota2_bypass.dll", "vac_dota2_bypass.exe",
                "disable_vac.bat", "disable_vac.ps1",
                "vac_bypass.bat", "vac_bypass.ps1",
                "vac_bypass.cfg", "vac_bypass.ini",
                "steam_bypass_loader.exe",
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

                    if (vacBypassFiles.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VAC Bypass Artifact for Dota 2: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known VAC (Valve Anti-Cheat) bypass artifact '{fileName}' found on disk. " +
                                     "VAC bypass tools are specifically designed to disable or circumvent Valve's " +
                                     "anti-cheat system to allow cheating in Dota 2 and other Steam/VAC-protected games."
                        });
                        continue;
                    }

                    // Keyword match on file name
                    foreach (var kw in VacBypassKeywords)
                    {
                        var simpleKw = kw.ToLowerInvariant().Replace(" ", "_");
                        if (fileName.Contains(simpleKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"VAC Bypass Keyword in File: {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason = $"File '{fileName}' matches the VAC bypass keyword pattern '{kw}'. " +
                                         "This file may be part of a VAC bypass toolkit targeting Dota 2.",
                                Detail = $"Matched keyword: {kw}"
                            });
                            break;
                        }
                    }

                    // Content scan for script/config VAC bypass keywords
                    var ext = Path.GetExtension(file);
                    if (ext.Equals(".bat", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".ini", StringComparison.OrdinalIgnoreCase))
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

                        foreach (var kw in VacBypassKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"VAC Bypass Keyword in Script/Config: {fileName}",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"Script or config file '{fileName}' contains the VAC bypass keyword '{kw}'. " +
                                             "This file may automate the disabling or circumventing of VAC protection " +
                                             "in Dota 2 or other Valve games.",
                                    Detail = $"Matched keyword: {kw}"
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 6. Garena Dota 2 bypass tool scanning
    // ---------------------------------------------------------------------------

    private Task CheckGarenaBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var garenaBypassFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "garena_bypass.exe", "garena_dota2.dll",
                "garena_bypass.dll", "garena_hack.exe",
                "garena_hack.dll", "garena_cheat.exe",
                "garena_dota2_bypass.exe", "garena_dota2_bypass.dll",
                "garena_dota2_hack.exe", "garena_dota2_hack.dll",
                "garena_inject.exe", "garena_inject.dll",
                "garena_loader.exe", "garena_loader.dll",
                "garena_patch.dll", "garena_spoof.dll",
                "garena_auth_bypass.dll", "garena_auth_bypass.exe",
                "garena_bypass_x64.dll", "garena_bypass_x86.dll",
            };

            var garenaKeywords = new[]
            {
                "garena_bypass", "garena_hack", "garena_cheat",
                "garena_dota", "garena_inject", "garena_loader",
                "garena_patch", "garena_spoof",
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

                    if (garenaBypassFiles.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Garena Dota 2 Bypass Artifact: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known Garena platform bypass tool '{fileName}' found on disk. " +
                                     "Garena bypass tools are designed to circumvent the Garena platform's " +
                                     "authentication and anti-cheat protection for Dota 2 on the Garena server region."
                        });
                        continue;
                    }

                    foreach (var kw in garenaKeywords)
                    {
                        if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Garena Bypass Keyword in File: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"File '{fileName}' matches the Garena bypass keyword '{kw}'. " +
                                         "May be a Garena platform bypass or cheat tool for Dota 2.",
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
    // 7. Custom game exploit artifacts (.vmap, .vscript exploit patterns)
    // ---------------------------------------------------------------------------

    private Task CheckCustomGameExploitArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var customGameRoots = new List<string>();

            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                var steamRoots = new[]
                {
                    Path.Combine(drive.RootDirectory.FullName, "Steam"),
                    Path.Combine(drive.RootDirectory.FullName, "Program Files", "Steam"),
                    Path.Combine(drive.RootDirectory.FullName, "Program Files (x86)", "Steam"),
                };

                foreach (var steamRoot in steamRoots)
                {
                    customGameRoots.Add(Path.Combine(
                        steamRoot, "steamapps", "common", "dota 2 beta", "game", "dota", "custom_games"));
                    customGameRoots.Add(Path.Combine(
                        steamRoot, "steamapps", "common", "dota 2 beta", "content", "dota_addons"));
                    customGameRoots.Add(Path.Combine(
                        steamRoot, "steamapps", "workshop", "content", "570"));
                }
            }

            // .vmap exploit keywords (Dota 2 map format)
            var vmapExploitKeywords = new[]
            {
                "cheat", "exploit", "hack", "bypass", "sv_cheats",
                "noclip", "god", "aimbot", "maphack",
                "infinite_gold", "infinite_mana", "cooldown_reduction",
                "deny_cooldown", "attack_speed_max",
            };

            foreach (var root in customGameRoots)
            {
                if (!Directory.Exists(root)) continue;

                // Scan .vmap files
                IEnumerable<string> vmapFiles = Enumerable.Empty<string>();
                try
                {
                    vmapFiles = Directory.EnumerateFiles(root, "*.vmap", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in vmapFiles)
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

                    foreach (var kw in vmapExploitKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Exploit Keyword in Dota 2 Map File: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Dota 2 map file '{Path.GetFileName(file)}' (.vmap) contains the exploit " +
                                         $"keyword '{kw}'. Custom game maps with cheat keywords may implement " +
                                         "exploit mechanics, sv_cheats abuse, or unfair game modifiers.",
                                Detail = $"Matched keyword: {kw}"
                            });
                            break;
                        }
                    }
                }

                // Scan .vscript files
                IEnumerable<string> vscriptFiles = Enumerable.Empty<string>();
                try
                {
                    vscriptFiles = Directory.EnumerateFiles(root, "*.vscript", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in vscriptFiles)
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

                    foreach (var kw in WorkshopExploitKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Exploit Keyword in Dota 2 VScript: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Dota 2 VScript file '{Path.GetFileName(file)}' contains the exploit " +
                                         $"keyword '{kw}'. VScript files power custom game logic; exploit patterns " +
                                         "indicate potential abuse of server-side Lua APIs for cheating purposes.",
                                Detail = $"Matched keyword: {kw}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 8. Steam Workshop malicious Lua script scanning
    // ---------------------------------------------------------------------------

    private Task CheckWorkshopExploitScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var workshopRoots = new List<string>();

            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                var steamRoots = new[]
                {
                    Path.Combine(drive.RootDirectory.FullName, "Steam"),
                    Path.Combine(drive.RootDirectory.FullName, "Program Files", "Steam"),
                    Path.Combine(drive.RootDirectory.FullName, "Program Files (x86)", "Steam"),
                };

                foreach (var steamRoot in steamRoots)
                {
                    // Dota 2 AppID is 570
                    workshopRoots.Add(Path.Combine(steamRoot, "steamapps", "workshop", "content", "570"));
                }
            }

            // Malicious workshop Lua keywords (server-side exploit patterns)
            var maliciousWorkshopKeywords = new[]
            {
                "SendToServer", "SendToAllClients",
                "Entities:FindByClassname", "Entities:FindAllByClassname",
                "DoUniqueString", "RollPercentage",
                "remote_exec", "RunScript", "DoIncludeScript",
                "HTTP", "HTTPAsync", "GetHTTP", "PostHTTP",
                "io.open", "io.write", "os.execute",
                "loadstring", "load(", "rawget", "rawset",
                "debug.getinfo", "debug.sethook",
                "backdoor", "c2_server", "command_center",
                "exfil", "exfiltrate", "data_steal",
                "keylogger", "clipboard",
                "exploit", "cheat", "hack", "bypass",
            };

            foreach (var root in workshopRoots)
            {
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> luaFiles = Enumerable.Empty<string>();
                try
                {
                    luaFiles = Directory.EnumerateFiles(root, "*.lua", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in luaFiles)
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

                    foreach (var kw in maliciousWorkshopKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious Dota 2 Workshop Script: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Dota 2 Steam Workshop Lua script '{Path.GetFileName(file)}' contains " +
                                         $"the suspicious pattern '{kw}'. Workshop scripts with these patterns may " +
                                         "perform data exfiltration, server-side exploitation, or implement " +
                                         "cheat mechanics through the custom game scripting system.",
                                Detail = $"Matched keyword: {kw}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 9. Registry UserAssist scanning for Dota 2 cheat EXE launches
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

                        if (cheatNameSet.Contains(fileName))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Dota 2 Cheat EXE UserAssist Entry: {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                                FileName = fileName,
                                Reason = $"UserAssist registry entry records that the known Dota 2 cheat executable " +
                                         $"'{fileName}' was launched from the GUI. UserAssist tracks program launches " +
                                         "via Windows Explorer and persists records even after the cheat file is deleted.",
                                Detail = $"Decoded path: {decoded}"
                            });
                            continue;
                        }

                        foreach (var kw in CheatFileNameKeywords)
                        {
                            if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Suspicious Dota 2 EXE in UserAssist: {fileName}",
                                    Risk = RiskLevel.High,
                                    Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                                    FileName = fileName,
                                    Reason = $"UserAssist registry entry records a GUI launch of '{fileName}', " +
                                             $"which matches the Dota 2 cheat keyword '{kw}'. " +
                                             "This EXE was previously launched from this user session.",
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
    // 10. Registry MUICache scanning for Dota 2 cheat tool names
    // ---------------------------------------------------------------------------

    private Task CheckRegistryMuiCache(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var muiCacheKeys = new[]
            {
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                @"Software\Microsoft\Windows\ShellNoRoam\MUICache",
            };

            var cheatDisplayNames = new HashSet<string>(MuiCacheCheatNames, StringComparer.OrdinalIgnoreCase);
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

                        foreach (var cheatName in cheatDisplayNames)
                        {
                            if (displayName.Contains(cheatName, StringComparison.OrdinalIgnoreCase) ||
                                valueName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Dota 2 Cheat Tool in MUICache: {cheatName}",
                                    Risk = RiskLevel.High,
                                    Location = @"HKCU\" + keyPath,
                                    FileName = fileName,
                                    Reason = $"MUICache registry entry references the known Dota 2 cheat tool '{cheatName}'. " +
                                             "MUICache stores display names of executed applications and persists " +
                                             "even after the cheat tool has been uninstalled or deleted.",
                                    Detail = $"Value name: {valueName} | Display: {displayName}"
                                });
                                break;
                            }
                        }

                        if (cheatExeSet.Contains(fileName))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Dota 2 Cheat EXE in MUICache: {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = @"HKCU\" + keyPath,
                                FileName = fileName,
                                Reason = $"MUICache contains an entry for the known Dota 2 cheat executable '{fileName}'. " +
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
    // 11. Registry Run keys for Dota 2 cheat loaders
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

                            foreach (var cheatName in cheatRunNames)
                            {
                                if (valueName.Contains(cheatName, StringComparison.OrdinalIgnoreCase) ||
                                    valueData.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"Dota 2 Cheat Loader in Run Key: {valueName}",
                                        Risk = RiskLevel.Critical,
                                        Location = $@"{hiveName}\{keyPath}",
                                        FileName = fileName,
                                        Reason = $"Registry Run key '{hiveName}\\{keyPath}\\{valueName}' references " +
                                                 $"the Dota 2 cheat loader keyword '{cheatName}'. Run keys cause programs " +
                                                 "to launch automatically at system startup, indicating a persistent " +
                                                 "Dota 2 cheat loader installation.",
                                        Detail = $"Value data: {valueData}"
                                    });
                                    break;
                                }
                            }

                            if (cheatExeSet.Contains(fileName))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Known Dota 2 Cheat EXE in Run Key: {fileName}",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"{hiveName}\{keyPath}",
                                    FileName = fileName,
                                    Reason = $"Registry Run key '{hiveName}\\{keyPath}' is configured to launch " +
                                             $"the known Dota 2 cheat executable '{fileName}' at system startup. " +
                                             "This indicates persistent cheat loader installation.",
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
    // 12. IFEO hijack of dota2.exe / steam.exe
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
                                     $"a Debugger value pointing to '{debugger}'. IFEO hijacking is used by Dota 2 " +
                                     "cheat loaders and VAC bypass tools to intercept the game or Steam process launch " +
                                     "and inject malicious code before VAC initializes.",
                            Detail = $"Debugger: {debugger}"
                        });
                    }

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
                                     "the startup behavior of Dota 2 or the Steam client process.",
                            Detail = $"GlobalFlag: {globalFlag}"
                        });
                    }

                    // Also check for VerifierDlls, used for DLL injection via application verifier
                    var verifierDlls = ifeoKey.GetValue("VerifierDlls")?.ToString();
                    if (!string.IsNullOrWhiteSpace(verifierDlls))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"IFEO VerifierDlls Injection on {target}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{ifeoKeyPath}\{target}",
                            FileName = target,
                            Reason = $"IFEO key for '{target}' has VerifierDlls set to '{verifierDlls}'. " +
                                     "Application Verifier DLL injection is an advanced technique used by cheat loaders " +
                                     "to inject DLLs into Dota 2 or Steam before VAC anti-cheat scanning begins.",
                            Detail = $"VerifierDlls: {verifierDlls}"
                        });
                    }
                }
                catch { }
            }
        }, ct);

    // ---------------------------------------------------------------------------
    // 13. Steam overlay abuse artifact scanning
    // ---------------------------------------------------------------------------

    private Task CheckSteamOverlayAbuseArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var overlayAbuseSet = new HashSet<string>(OverlayAbuseArtifacts, StringComparer.OrdinalIgnoreCase);

            var overlayKeywords = new[]
            {
                "overlay_hack", "overlay_esp", "overlay_aimbot",
                "overlay_cheat", "steam_overlay_bypass", "overlay_inject",
                "gameoverlay_hack", "overlay_bypass", "steam_overlay_hack",
            };

            // Steam GameOverlayRenderer paths
            var steamOverlayPaths = new List<string>();
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                var steamRoots = new[]
                {
                    Path.Combine(drive.RootDirectory.FullName, "Steam"),
                    Path.Combine(drive.RootDirectory.FullName, "Program Files", "Steam"),
                    Path.Combine(drive.RootDirectory.FullName, "Program Files (x86)", "Steam"),
                };
                foreach (var steamRoot in steamRoots)
                    steamOverlayPaths.Add(steamRoot);
            }

            // General user directories
            steamOverlayPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            steamOverlayPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            steamOverlayPaths.Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            steamOverlayPaths.Add(Path.GetTempPath());

            foreach (var root in steamOverlayPaths)
            {
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files = Enumerable.Empty<string>();
                try
                {
                    files = Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);

                    if (overlayAbuseSet.Contains(fileName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Dota 2 Steam Overlay Abuse DLL: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Known Steam overlay abuse DLL '{fileName}' found on disk. " +
                                     "Steam overlay abuse DLLs hook into the Steam overlay rendering system " +
                                     "to draw ESP overlays, aimbot crosshairs, or other cheat visualizations " +
                                     "on top of the Dota 2 game window without triggering screenshot detection."
                        });
                        continue;
                    }

                    foreach (var kw in overlayKeywords)
                    {
                        if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Steam Overlay Abuse Keyword in DLL: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"DLL '{fileName}' matches the Steam overlay abuse keyword '{kw}'. " +
                                         "May be a cheat DLL exploiting the Steam overlay for Dota 2 ESP rendering.",
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
    // 14. VAC log scanning in Dota 2 game folder
    // ---------------------------------------------------------------------------

    private Task CheckVacLogArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var dota2LogRoots = new List<string>();

            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady) continue;
                var steamRoots = new[]
                {
                    Path.Combine(drive.RootDirectory.FullName, "Steam"),
                    Path.Combine(drive.RootDirectory.FullName, "Program Files", "Steam"),
                    Path.Combine(drive.RootDirectory.FullName, "Program Files (x86)", "Steam"),
                };

                foreach (var steamRoot in steamRoots)
                {
                    dota2LogRoots.Add(Path.Combine(steamRoot, "steamapps", "common", "dota 2 beta", "game", "dota", "logs"));
                    dota2LogRoots.Add(Path.Combine(steamRoot, "logs"));
                    dota2LogRoots.Add(Path.Combine(steamRoot, "steamapps", "common", "dota 2 beta", "game", "bin", "win64"));
                    dota2LogRoots.Add(Path.Combine(steamRoot, "steamapps", "common", "dota 2 beta", "game", "bin", "win32"));
                }
            }

            // Also check localappdata Steam logs
            dota2LogRoots.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Steam", "htmlcache", "Cache"));

            // Keywords in logs indicating VAC events or cheat activity
            var vacLogKeywords = new[]
            {
                "VAC banned", "VAC ban", "VAC_Banned",
                "cheat detected", "cheat_detected", "CheatDetected",
                "anti-cheat violation", "AC violation",
                "injection detected", "dll injection",
                "bypass detected", "bypass_detected",
                "module removed", "module_removed",
                "suspicious module", "suspicious_module",
                "GameActionState_error", "VAC authentication error",
                "steam_api.dll mismatch", "steamclient.dll mismatch",
                "VAC module error", "VAC_Module_Error",
                "Failed to load VAC", "VAC load failed",
                "sv_cheats is active", "sv_cheats enabled",
                "cheat engine detected", "ce detected",
                "memory scan", "memory_scan",
                "process scanner", "process_scanner",
                "signature scan failed", "sig scan",
            };

            foreach (var logRoot in dota2LogRoots)
            {
                if (!Directory.Exists(logRoot)) continue;

                IEnumerable<string> logFiles = Enumerable.Empty<string>();
                try
                {
                    logFiles = Directory.EnumerateFiles(logRoot, "*.log", SearchOption.AllDirectories)
                        .Concat(Directory.EnumerateFiles(logRoot, "*.txt", SearchOption.AllDirectories));
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

                    foreach (var kw in vacLogKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"VAC/Cheat Activity in Dota 2 Log: {Path.GetFileName(logFile)}",
                                Risk = RiskLevel.High,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"Dota 2 log file '{Path.GetFileName(logFile)}' contains the VAC or cheat " +
                                         $"activity keyword '{kw}'. This may indicate a past VAC detection event, " +
                                         "a cheat injection attempt, or suspicious module activity logged during " +
                                         "a Dota 2 session.",
                                Detail = $"Matched keyword: {kw}"
                            });
                            break;
                        }
                    }
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
