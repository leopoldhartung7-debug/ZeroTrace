using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class ApexLegendsCheatScanModule : IScanModule
{
    public string Name => "Apex Legends Cheat Deep Scan";
    public double Weight => 3.9;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    // -------------------------------------------------------------------------
    // Known EAC bypass filenames for Apex Legends
    // -------------------------------------------------------------------------
    private static readonly string[] EacBypassFiles =
    {
        "apex_eac_bypass.dll", "eac_apex.dll", "eac_bypass.dll", "easyanticheat_bypass.dll",
        "eac_loader.dll", "eac_hook.dll", "eac_patch.dll", "eac_inject.dll",
        "eac_disable.dll", "eac_killer.dll", "eac_unload.dll", "eac_spoofer.dll",
        "r5apex_eac.dll", "r5apex_eac_bypass.dll", "apex_eac.dll",
        "eac_apex_bypass.exe", "apex_eac_bypass.exe", "eac_bypass_apex.exe",
        "easyanticheat_bypass_apex.exe", "disable_eac.exe", "eac_patcher.exe",
        "eac_remover.exe", "eac_disabler.exe", "bypass_eac.exe",
        "anticheat_bypass.dll", "anticheat_bypass.exe",
        "eac_hook.exe", "eac_spoof.exe", "apex_ac_bypass.dll", "apex_ac_bypass.exe",
    };

    // -------------------------------------------------------------------------
    // Known aimbot filenames for Apex Legends
    // -------------------------------------------------------------------------
    private static readonly string[] AimbotFiles =
    {
        "apex_aim.exe", "aim_apex.dll", "apexaimbot.exe", "apex_aimbot.exe",
        "apex_aimbot.dll", "apex_aim.dll", "aim_apex.exe", "aimbot_apex.exe",
        "aimbot_apex.dll", "silent_aim_apex.exe", "silent_aim_apex.dll",
        "triggerbot_apex.exe", "apex_trigger.exe", "triggerbot_apex.dll",
        "aimassist_apex.exe", "apexaimassist.exe", "apex_aimassist.dll",
        "apex_silent_aim.exe", "apex_silent_aim.dll",
        "aim_at_head_apex.exe", "headshot_apex.exe", "headshot_apex.dll",
        "auto_aim_apex.exe", "auto_aim_apex.dll", "bone_aim_apex.dll",
        "fov_aimbot_apex.exe", "smooth_aim_apex.exe", "prediction_apex.dll",
        "aim_prediction_apex.exe", "apex_aim_key.dll", "apex_triggerbot.dll",
    };

    // -------------------------------------------------------------------------
    // Known wallhack / ESP filenames for Apex Legends
    // -------------------------------------------------------------------------
    private static readonly string[] WallhackEspFiles =
    {
        "apex_esp.dll", "apex_wh.exe", "wall_apex.dll", "apex_wallhack.exe",
        "apex_wallhack.dll", "apex_esp.exe", "wh_apex.dll", "wh_apex.exe",
        "esp_apex.dll", "esp_apex.exe", "apex_external_esp.dll",
        "apex_external_esp.exe", "apex_player_esp.dll", "apex_player_esp.exe",
        "apex_loot_esp.dll", "apex_loot_esp.exe", "apex_item_esp.dll",
        "apex_item_esp.exe", "apex_health_esp.dll", "apex_health_esp.exe",
        "apex_shield_esp.dll", "apex_shield_esp.exe", "apex_distance_esp.dll",
        "apex_ammo_esp.dll", "apex_skeleton_esp.dll", "apex_glow.dll",
        "apex_chams.dll", "apex_glow.exe", "apex_chams.exe",
        "apex_box_esp.dll", "apex_snapline_esp.dll", "apex_radar_esp.dll",
    };

    // -------------------------------------------------------------------------
    // Known no-recoil filenames
    // -------------------------------------------------------------------------
    private static readonly string[] NoRecoilFiles =
    {
        "apex_recoil.exe", "no_recoil_apex.dll", "apex_no_recoil.exe",
        "apex_no_recoil.dll", "recoil_apex.exe", "recoil_apex.dll",
        "no_recoil_apex.exe", "apex_norecoil.exe", "apex_norecoil.dll",
        "recoil_control_apex.dll", "recoil_script_apex.exe",
        "norecoil_apex.exe", "norecoil_apex.dll",
        "apex_recoil_reducer.dll", "anti_recoil_apex.dll",
        "spray_control_apex.dll",
    };

    // -------------------------------------------------------------------------
    // Known radar hack filenames
    // -------------------------------------------------------------------------
    private static readonly string[] RadarHackFiles =
    {
        "radar_apex.exe", "apex_radar.dll", "apex_radar.exe",
        "apexradar.exe", "apex_map_hack.exe", "apexmaphack.exe",
        "radar_hack_apex.exe", "radar_hack_apex.dll",
        "apex_radar_server.exe", "r5_radar.exe", "r5radar.exe",
        "apex_minimap_hack.dll", "apex_minimap.exe",
        "apex_enemy_radar.dll", "apex_squad_radar.dll",
        "apex_loot_radar.dll",
    };

    // -------------------------------------------------------------------------
    // Known movement hack filenames
    // -------------------------------------------------------------------------
    private static readonly string[] MovementHackFiles =
    {
        "apex_move.dll", "speed_apex.dll", "apex_speed.exe",
        "apex_speed.dll", "apex_bhop.exe", "apex_bhop.dll",
        "bunnyhop_apex.exe", "bunnyhop_apex.dll", "apex_bunnyhop.dll",
        "apex_movement.exe", "movement_hack_apex.dll",
        "apex_strafe.dll", "apex_strafe.exe",
        "apex_superglide.dll", "apex_superglide.exe",
        "apex_mantle_jump.dll", "apex_zipline_hack.dll",
        "apex_infinite_stamina.dll", "speedhack_apex.dll",
        "speedhack_apex.exe", "apex_fast_move.dll",
    };

    // -------------------------------------------------------------------------
    // Known cheat loader filenames
    // -------------------------------------------------------------------------
    private static readonly string[] CheatLoaderFiles =
    {
        "apex_cheats.exe", "apexhack.exe", "apex_legend_cheat.exe",
        "loaderApex.exe", "InternalApex.exe", "apex_loader.exe",
        "apexloader.exe", "apex_injector.exe", "apexinjector.exe",
        "apex_cheat_loader.exe", "cheatloader_apex.exe",
        "loadercheat_apex.exe", "loadercheat.exe",
        "apex_internal.exe", "apex_external.exe",
        "r5apex_cheat.exe", "r5apexhack.exe", "r5apex_loader.exe",
        "apex_cheat_menu.exe", "apex_menu.exe", "apex_mod.exe",
        "apex_mod_menu.exe", "apex_hack_menu.exe",
        "apex_universal_hack.exe", "apex_premium_hack.exe",
        "apex_free_hack.exe", "apex_undetected.exe",
        "apex_paid_cheat.exe", "apex_private_cheat.exe",
        "TriggerBot.exe", "AimAssist.exe", "RadarHack.exe",
        "apexcheatengine.exe", "apex_cheat_engine.exe",
    };

    // -------------------------------------------------------------------------
    // Known cheat DLL names (injectable)
    // -------------------------------------------------------------------------
    private static readonly string[] CheatDllNames =
    {
        "r5apex.dll", "apex_cheat.dll", "apex_hook.dll",
        "r5apex_internal.dll", "apexinternal.dll", "apexhook.dll",
        "apex_memory.dll", "apex_offsets.dll", "apexloader.dll",
        "apex_internal.dll", "apex_inject.dll",
        "ea_bypass.dll", "origin_bypass.dll",
        "apex_dma.dll", "apex_external.dll",
        "apex_helper.dll", "apex_core.dll",
        "apex_base.dll", "apex_sdk.dll",
        "apex_features.dll", "apex_menu.dll",
        "apex_render.dll", "apex_draw.dll",
        "apex_network.dll", "apex_patch.dll",
        "apex_scan.dll", "apex_input.dll",
    };

    // -------------------------------------------------------------------------
    // Cheat config keywords found in autoexec / config files
    // -------------------------------------------------------------------------
    private static readonly string[] CheatConfigKeywords =
    {
        "aimbot_smoothing_apex", "aimbot_fov_apex", "aimbot_bone_apex",
        "esp_boxes_apex", "esp_health_apex", "esp_shield_apex",
        "esp_ammo_apex", "esp_distance_apex", "no_recoil_apex",
        "silent_aim_apex", "triggerbot_apex", "item_esp", "loot_esp_apex",
        "speedhack_apex", "bhop_apex", "spinbot_apex", "wallhack_apex",
        "movement_hack_apex", "healing_esp", "teammate_check",
        "r5apex_aimbot", "r5apex_esp", "r5apex_wallhack",
        "apex_aim_key", "apex_esp_key", "apex_triggerbot_key",
        "aimbot_enabled_apex", "esp_enabled_apex", "wallhack_enabled_apex",
        "no_recoil_enabled", "silent_aim_enabled", "spinbot_enabled",
        "loot_esp_enabled", "item_filter_apex", "auto_heal_enabled",
        "aim_at_head_apex", "aim_at_body_apex", "aim_at_closest",
        "aimbot_prediction_apex", "movement_prediction_apex",
        "apex_player_list", "apex_bone_list", "apex_hitbox",
        "apex_team_filter", "apex_visibility_check", "apex_aim_step",
        "apex_smooth_factor", "draw_fov_circle_apex", "draw_crosshair_apex",
        "triggerbot_enabled", "triggerbot_delay", "triggerbot_key",
        "esp_skeleton", "esp_snapline", "esp_distance", "esp_name",
        "esp_weapon", "esp_armor", "esp_knocked",
        "aimbot_fov", "aimbot_smooth", "aimbot_prediction",
        "no_spread_apex", "rapid_fire_apex", "fast_looting_apex",
    };

    // -------------------------------------------------------------------------
    // Apex memory offset / SDK identifiers (DMA/external cheat artifacts)
    // -------------------------------------------------------------------------
    private static readonly string[] OffsetKeywords =
    {
        "LocalPlayer", "EntityList", "ViewMatrix", "Health", "Shield",
        "TeamNum", "WorldToScreen", "m_iHealth", "m_iShieldHealth",
        "m_iTeamNum", "m_vecOrigin", "m_vecVelocity", "m_bAlive",
        "m_Anim", "m_nModelIndex", "r5apex", "r5apex.exe",
        "PlayerArray", "RootComponent", "RelativeLocation",
        "AbsoluteLocation", "Bones", "BoneArray", "BoneMatrix",
        "CL_IsGamePaused", "ClientGameContext", "GameSurvivalMode",
        "PlayerWeapon", "ZiplineEnabled", "HighSpeedPackage",
        "name_list_ptr", "apex_player_ptr", "last_visible_time",
        "abs_velocity", "breath_scale", "zoom_fov",
    };

    // -------------------------------------------------------------------------
    // Suspicious DLL name fragments in Origin/EA game directory
    // -------------------------------------------------------------------------
    private static readonly string[] SuspiciousGameDirDllFragments =
    {
        "bypass", "inject", "hook", "cheat", "hack", "aim", "esp",
        "wallhack", "recoil", "radar", "spoof", "loader", "patch",
        "internal", "external", "memory", "offset", "trainer",
        "triggerbot", "aimassist", "modmenu", "menu_dll",
    };

    // -------------------------------------------------------------------------
    // Hosts file entries that indicate blocking of EA/EAC servers
    // -------------------------------------------------------------------------
    private static readonly string[] EaHostsBlockPatterns =
    {
        "easyanticheat.net", "easyanticheat.io",
        "api.easyanticheat.net", "download.easyanticheat.net",
        "ea.com", "origin.com", "eaassets-a.akamaihd.net",
        "r5apex.ea.com", "accounts.ea.com", "apex.ea.com",
        "telemetry.easyanticheat.net", "updates.easyanticheat.net",
        "ea-network.com", "ea-login.com",
    };

    // -------------------------------------------------------------------------
    // Registry run keys to check for cheat loaders
    // -------------------------------------------------------------------------
    private static readonly string[] ApexCheatRunKeywords =
    {
        "apexhack", "apex_cheat", "apex_aim", "apex_esp",
        "apex_bypass", "apex_loader", "apexloader", "apexinjector",
        "eac_bypass", "apex_eac", "loadercheat", "apexmod",
        "apex_radar", "apex_recoil", "triggerbot_apex", "aim_apex",
        "apex_wallhack", "apexwallhack", "apexaimbot",
    };

    // -------------------------------------------------------------------------
    // UserAssist / MUICache keywords for Apex cheats
    // -------------------------------------------------------------------------
    private static readonly string[] ApexCheatExecutionKeywords =
    {
        "apexhack", "apexcheat", "apex_cheat", "apex_aim", "apex_esp",
        "apex_bypass", "apexloader", "apex_loader", "apexinjector",
        "eac_bypass", "loaderApex", "InternalApex", "apex_radar",
        "apex_recoil", "triggerbot_apex", "aim_apex", "apex_wallhack",
        "apexaimbot", "radar_apex", "apexesp", "apex_bhop",
        "apex_speed", "apex_move", "apex_trigger", "wall_apex",
        "no_recoil_apex", "speed_apex", "apexmod",
    };

    // -------------------------------------------------------------------------
    // EAC log tampering indicators
    // -------------------------------------------------------------------------
    private static readonly string[] EacTamperKeywords =
    {
        "bypass", "patch", "disabled", "tampered", "modified",
        "hook", "injected", "spoofed", "killed", "unloaded",
        "exception", "access denied", "invalid signature",
        "module mismatch", "integrity failed",
    };

    // -------------------------------------------------------------------------
    // Known RTSS / MSI Afterburner profile names modified for Apex cheating
    // -------------------------------------------------------------------------
    private static readonly string[] SuspiciousRtssProfileKeywords =
    {
        "apex_esp_overlay", "apex_aim_overlay", "apex_cheat_overlay",
        "apexhack", "apex_external_esp", "overlay_cheat_apex",
        "apex overlay", "cheat overlay apex",
    };

    // -------------------------------------------------------------------------
    // Paths to scan for Apex-related cheat artifacts
    // -------------------------------------------------------------------------
    private static string[] GetApexScanPaths()
    {
        var appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localApp     = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var temp         = Path.GetTempPath();
        var programX86   = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

        return new[]
        {
            Path.Combine(appData, "Respawn", "Apex"),
            Path.Combine(localApp, "Respawn", "Apex"),
            Path.Combine(programX86, "Origin Games", "Apex"),
            Path.Combine(programX86, "EA Games", "Apex Legends"),
            Path.Combine(programFiles, "EA Games", "Apex Legends"),
            Path.Combine(programFiles, "Origin Games", "Apex"),
            @"C:\Program Files (x86)\Origin Games\Apex",
            @"C:\Program Files\EA Games\Apex Legends",
            @"D:\Origin Games\Apex",
            @"D:\EA Games\Apex Legends",
            @"D:\Games\Apex Legends",
            @"E:\Games\Apex Legends",
            Path.Combine(userProfile, "Downloads"),
            temp,
            Path.Combine(localApp, "Temp"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
        };
    }

    private static string[] GetSteamApexPaths()
    {
        var list = new List<string>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Valve\Steam", writable: false);
            var steamPath = key?.GetValue("InstallPath") as string;
            if (!string.IsNullOrEmpty(steamPath))
                list.Add(Path.Combine(steamPath, "steamapps", "common", "Apex Legends"));
        }
        catch { }

        foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed))
        {
            list.Add(Path.Combine(drive.RootDirectory.FullName, "SteamLibrary", "steamapps", "common", "Apex Legends"));
            list.Add(Path.Combine(drive.RootDirectory.FullName, "Steam", "steamapps", "common", "Apex Legends"));
        }
        return list.ToArray();
    }

    // -------------------------------------------------------------------------
    // ROT13 for UserAssist decoding
    // -------------------------------------------------------------------------
    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if      (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    // -------------------------------------------------------------------------
    // Entry point
    // -------------------------------------------------------------------------
    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Apex Legends cheat deep scan...");

        await Task.WhenAll(
            CheckApexGameDirectoryFiles(ctx, ct),
            CheckKnownCheatLoaderFiles(ctx, ct),
            CheckAimbotAndEspFiles(ctx, ct),
            CheckNoRecoilAndMovementFiles(ctx, ct),
            CheckRadarHackFiles(ctx, ct),
            CheckEacBypassFiles(ctx, ct),
            CheckApexProcesses(ctx, ct),
            CheckEacLogTampering(ctx, ct),
            CheckApexConfigFiles(ctx, ct),
            CheckApexOffsetFiles(ctx, ct),
            CheckRegistryRunKeys(ctx, ct),
            CheckEacServiceRegistry(ctx, ct),
            CheckUserAssistApexCheats(ctx, ct),
            CheckMuiCacheApexCheats(ctx, ct),
            CheckHostsFileEaBlocking(ctx, ct),
            CheckRtssOverlayProfiles(ctx, ct),
            CheckOriginLaunchOptions(ctx, ct),
            CheckApexAppDataExecutables(ctx, ct),
            CheckDownloadsFolderApex(ctx, ct),
            CheckSuspiciousGameDirDlls(ctx, ct)
        );

        ctx.Report(1.0, Name, "Apex Legends cheat deep scan complete.");
    }

    // -------------------------------------------------------------------------
    // Check 1: Game directory for known cheat EXEs and DLLs
    // -------------------------------------------------------------------------
    private Task CheckApexGameDirectoryFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var allPaths = GetApexScanPaths().Concat(GetSteamApexPaths()).ToArray();

            foreach (var root in allPaths)
            {
                if (!Directory.Exists(root)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    foreach (var cheatFile in CheatLoaderFiles)
                    {
                        if (fn.Equals(cheatFile, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Apex Legends Cheat Loader: {fn}",
                                Risk     = RiskLevel.Critical,
                                Location = file,
                                FileName = fn,
                                Reason   = $"Known Apex Legends cheat loader executable '{fn}' found in scan path. " +
                                           "This executable is used to inject or load cheat modules targeting " +
                                           "Apex Legends and its EasyAntiCheat protection.",
                                Detail   = $"Path: {file}"
                            });
                            break;
                        }
                    }

                    foreach (var dll in CheatDllNames)
                    {
                        if (fn.Equals(dll, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Apex Legends Cheat DLL: {fn}",
                                Risk     = RiskLevel.Critical,
                                Location = file,
                                FileName = fn,
                                Reason   = $"Known Apex Legends cheat DLL '{fn}' found. These libraries are " +
                                           "injected into the r5apex.exe process or used for DMA-based cheating " +
                                           "to provide aimbot, ESP, and memory-reading capabilities.",
                                Detail   = $"Path: {file}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 2: Standalone cheat loader executables in common paths
    // -------------------------------------------------------------------------
    private Task CheckKnownCheatLoaderFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            };

            var allCheatFiles = CheatLoaderFiles
                .Concat(CheatDllNames)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!allCheatFiles.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Apex Cheat File in User Directory: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Apex Legends cheat file '{fn}' found in user-accessible directory '{dir}'. " +
                                   "Cheat tools are commonly stored in Desktop, Downloads, or Temp before use.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 3: Aimbot and ESP/wallhack specific files
    // -------------------------------------------------------------------------
    private Task CheckAimbotAndEspFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var allAimbotEsp = AimbotFiles
                .Concat(WallhackEspFiles)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Respawn", "Apex"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Respawn", "Apex"),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!allAimbotEsp.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    bool isAimbot = AimbotFiles.Any(a => a.Equals(fn, StringComparison.OrdinalIgnoreCase));
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = isAimbot
                            ? $"Apex Legends Aimbot File: {fn}"
                            : $"Apex Legends ESP/Wallhack File: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = isAimbot
                            ? $"Known Apex Legends aimbot file '{fn}' found. Aimbot tools auto-target enemies, " +
                              "reducing skill requirements and providing an unfair competitive advantage."
                            : $"Known Apex Legends ESP/wallhack file '{fn}' found. ESP (Extra Sensory Perception) " +
                              "tools render enemy positions, health, and loot through walls.",
                        Detail   = $"Path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 4: No-recoil and movement hack files
    // -------------------------------------------------------------------------
    private Task CheckNoRecoilAndMovementFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var allFiles = NoRecoilFiles
                .Concat(MovementHackFiles)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!allFiles.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    bool isRecoil = NoRecoilFiles.Any(r => r.Equals(fn, StringComparison.OrdinalIgnoreCase));
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = isRecoil
                            ? $"Apex Legends No-Recoil Hack: {fn}"
                            : $"Apex Legends Movement Hack: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = isRecoil
                            ? $"Known Apex Legends no-recoil hack '{fn}' found. No-recoil scripts eliminate weapon " +
                              "recoil patterns, providing significantly improved accuracy during sustained fire."
                            : $"Known Apex Legends movement hack '{fn}' found. Movement cheats include bunny-hop " +
                              "automation, speed hacks, and superglide assists that bypass intended movement limits.",
                        Detail   = $"Path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 5: Radar hack files
    // -------------------------------------------------------------------------
    private Task CheckRadarHackFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var radarSet = RadarHackFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!radarSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Apex Legends Radar Hack: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Apex Legends radar hack executable '{fn}' found. Radar hacks expose all " +
                                   "player and loot positions on an external map display, completely removing " +
                                   "information asymmetry that is fundamental to Apex Legends gameplay.",
                        Detail   = $"Path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 6: EAC bypass tool files
    // -------------------------------------------------------------------------
    private Task CheckEacBypassFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var eacSet = EacBypassFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

            var scanDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Respawn", "Apex"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EasyAntiCheat"),
            };

            foreach (var dir in scanDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);

                    if (eacSet.Contains(fn))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"EAC Bypass Tool for Apex: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Known EasyAntiCheat bypass tool '{fn}' found. EAC bypass tools disable " +
                                       "or circumvent the EasyAntiCheat kernel-mode protection used by Apex Legends, " +
                                       "allowing cheat injection without triggering standard detection.",
                            Detail   = $"Path: {file}"
                        });
                        continue;
                    }

                    // Fuzzy match: look for eac bypass keywords in any exe/dll filename in scan dirs
                    var fnLower = fn.ToLowerInvariant();
                    if ((fnLower.Contains("eac") || fnLower.Contains("easyanticheat")) &&
                        (fnLower.Contains("bypass") || fnLower.Contains("patch") ||
                         fnLower.Contains("disable") || fnLower.Contains("hook") ||
                         fnLower.Contains("kill") || fnLower.Contains("inject")) &&
                        (fn.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                         fn.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                         fn.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Suspicious EAC Bypass File: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"File '{fn}' combines EasyAntiCheat-related and bypass-related name components. " +
                                       "This naming pattern is characteristic of anti-cheat evasion tools targeting Apex Legends.",
                            Detail   = $"Path: {file}"
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 7: Running processes matching known Apex cheat tools
    // -------------------------------------------------------------------------
    private Task CheckApexProcesses(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var allCheatNames = CheatLoaderFiles
                .Concat(AimbotFiles)
                .Concat(WallhackEspFiles)
                .Concat(NoRecoilFiles)
                .Concat(RadarHackFiles)
                .Concat(MovementHackFiles)
                .Concat(EacBypassFiles)
                .Select(f => Path.GetFileNameWithoutExtension(f))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var proc in ctx.GetProcessSnapshot())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementProcesses();
                try
                {
                    var pname = proc.ProcessName;
                    if (!allCheatNames.Contains(pname)) continue;

                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Apex Cheat Process Active: {pname}",
                        Risk     = RiskLevel.Critical,
                        Location = string.IsNullOrEmpty(procPath) ? $"PID {proc.Id}" : procPath,
                        FileName = pname + ".exe",
                        Reason   = $"Known Apex Legends cheat process '{pname}' is currently running. " +
                                   "An active cheat tool represents an immediate ongoing cheating risk.",
                        Detail   = $"PID: {proc.Id} | Path: {procPath}"
                    });
                }
                catch { }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 8: EAC log folder for tampering signs
    // -------------------------------------------------------------------------
    private Task CheckEacLogTampering(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var eacLogDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "EasyAntiCheat");

            if (!Directory.Exists(eacLogDir)) return;

            string[] files;
            try { files = Directory.GetFiles(eacLogDir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                var fn = Path.GetFileName(file);
                var ext = Path.GetExtension(file).ToLowerInvariant();

                // Unexpected executables or DLLs in the EAC folder are highly suspicious
                if (ext == ".exe" || ext == ".dll" || ext == ".sys")
                {
                    // Legitimate EAC files are known names — flag unknowns
                    bool isLegitEac = fn.StartsWith("EasyAntiCheat", StringComparison.OrdinalIgnoreCase) ||
                                      fn.Equals("SteamStub.dll", StringComparison.OrdinalIgnoreCase);
                    if (!isLegitEac)
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Unexpected Executable in EAC Folder: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Unexpected executable/DLL '{fn}' found in EasyAntiCheat directory. " +
                                       "EAC bypass tools may plant modified or replacement files in this directory " +
                                       "to subvert Apex Legends anti-cheat protection.",
                            Detail   = $"EAC directory: {eacLogDir}"
                        });
                    }
                }

                // Scan log files for tampering signatures
                if (ext == ".log" || ext == ".txt")
                {
                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    foreach (var keyword in EacTamperKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"EAC Log Tampering Indicator: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"EasyAntiCheat log file '{fn}' contains tampering indicator '{keyword}'. " +
                                           "This may indicate EAC was patched, bypassed, or forced into a " +
                                           "non-protective state prior to launching Apex Legends.",
                                Detail   = $"Keyword: {keyword} | Log: {file}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 9: Apex config files for cheat keywords
    // -------------------------------------------------------------------------
    private Task CheckApexConfigFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var configDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Respawn", "Apex"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Respawn", "Apex"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Apex"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Apex Legends"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Saved Games", "Respawn", "Apex"),
            };

            foreach (var dir in configDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext != ".cfg" && ext != ".ini" && ext != ".json" &&
                        ext != ".txt" && ext != ".xml" && ext != ".lua") continue;

                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hits = CheatConfigKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Apex Cheat Configuration File: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"Apex config file '{Path.GetFileName(file)}' contains {hits.Count} cheat-related " +
                                       "configuration keywords. This is highly indicative of a cheat tool " +
                                       "configuration file for Apex Legends.",
                            Detail   = "Keywords: " + string.Join(", ", hits.Take(8))
                        });
                    }
                    else if (hits.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Apex Config Cheat Keyword: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"Apex config/script file '{Path.GetFileName(file)}' contains the keyword " +
                                       $"'{hits[0]}' associated with Apex Legends cheat tools. " +
                                       "Cheat tools often use config files to store settings between sessions.",
                            Detail   = "Matched: " + string.Join(", ", hits)
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 10: Memory offset / SDK files (DMA cheat artifacts)
    // -------------------------------------------------------------------------
    private Task CheckApexOffsetFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    if (ext != ".json" && ext != ".hpp" && ext != ".h" &&
                        ext != ".cpp" && ext != ".txt" && ext != ".ini") continue;

                    bool nameRelevant = fn.Contains("offset", StringComparison.OrdinalIgnoreCase)
                        || fn.Contains("apex", StringComparison.OrdinalIgnoreCase)
                        || fn.Contains("r5apex", StringComparison.OrdinalIgnoreCase)
                        || fn.Contains("dump", StringComparison.OrdinalIgnoreCase)
                        || fn.Contains("sdk", StringComparison.OrdinalIgnoreCase);

                    if (!nameRelevant) continue;

                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hits = OffsetKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count >= 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Apex Memory Offset / SDK File: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"File '{fn}' contains {hits.Count} Apex Legends memory offset identifiers. " +
                                       "Memory offset files are used by DMA cheats and external hacks to locate " +
                                       "game entities in memory without requiring code injection.",
                            Detail   = "Offsets found: " + string.Join(", ", hits.Take(8))
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 11: Registry Run keys for Apex cheat loaders
    // -------------------------------------------------------------------------
    private Task CheckRegistryRunKeys(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var runKeys = new[]
            {
                (Registry.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
            };

            foreach (var (hive, keyPath) in runKeys)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var key = hive.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();
                        var value = key.GetValue(valueName)?.ToString() ?? string.Empty;

                        foreach (var keyword in ApexCheatRunKeywords)
                        {
                            if (valueName.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                                value.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"Apex Cheat Autostart in Registry: {valueName}",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKLM/HKCU\{keyPath}\{valueName}",
                                    Reason   = $"Registry Run key '{valueName}' references Apex cheat-related keyword '{keyword}'. " +
                                               "This indicates a cheat tool is configured to launch automatically with Windows, " +
                                               "a persistence technique used by advanced Apex cheat loaders.",
                                    Detail   = $"Value: {value} | Key: {keyPath}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch { }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 12: EAC service and EA/Origin registry for bypass indicators
    // -------------------------------------------------------------------------
    private Task CheckEacServiceRegistry(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            // EasyAntiCheat service state
            var eacServiceKeys = new[]
            {
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat",
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS",
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_Apex",
            };

            foreach (var svcKey in eacServiceKeys)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(svcKey, writable: false);
                    if (key is null) continue;
                    ctx.IncrementRegistryKeys();

                    var start = key.GetValue("Start") as int?;
                    if (start == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"EasyAntiCheat Service Disabled: {Path.GetFileName(svcKey)}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{svcKey}",
                            Reason   = $"EasyAntiCheat service '{Path.GetFileName(svcKey)}' has Start=4 (disabled). " +
                                       "Disabling the EAC service allows Apex Legends cheats to run without " +
                                       "triggering anti-cheat kernel-mode protections.",
                            Detail   = "Start=4 means SERVICE_DISABLED in Windows SCM"
                        });
                    }

                    var imagePath = key.GetValue("ImagePath") as string ?? string.Empty;
                    if (!string.IsNullOrEmpty(imagePath))
                    {
                        var fn = Path.GetFileName(imagePath);
                        foreach (var bypassFrag in EacBypassFiles)
                        {
                            if (fn.Contains(bypassFrag, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"EAC Service Points to Bypass Binary: {fn}",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKLM\{svcKey}",
                                    Reason   = $"EasyAntiCheat service ImagePath references a known bypass binary '{fn}'. " +
                                               "This is a strong indicator that the EAC service was replaced with a " +
                                               "bypass shim that appears legitimate but does not enforce protection.",
                                    Detail   = $"ImagePath: {imagePath}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch { }
            }

            // EA/Origin registry for Apex bypass-related keys
            var eaKeys = new[]
            {
                @"SOFTWARE\EA Games\Apex Legends",
                @"SOFTWARE\Electronic Arts\EA Desktop",
                @"SOFTWARE\Origin",
                @"SOFTWARE\Respawn Entertainment\Apex Legends",
            };

            foreach (var eaKey in eaKeys)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var k = Registry.CurrentUser.OpenSubKey(eaKey, writable: false)
                               ?? Registry.LocalMachine.OpenSubKey(eaKey, writable: false);
                    if (k is null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valName in k.GetValueNames())
                    {
                        if (valName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("crack", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Suspicious EA/Origin Registry Value: {valName}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKCU/HKLM\{eaKey}",
                                Reason   = $"EA/Origin registry key '{eaKey}' contains suspicious value name '{valName}'. " +
                                           "Cheat tools sometimes write configuration into legitimate EA registry paths " +
                                           "to blend in with normal game installation data.",
                                Detail   = $"Value name: {valName} | Key: {eaKey}"
                            });
                        }
                    }
                }
                catch { }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 13: UserAssist records for Apex cheat execution history
    // -------------------------------------------------------------------------
    private Task CheckUserAssistApexCheats(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            const string userAssistBase =
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

            try
            {
                using var baseKey = Registry.CurrentUser.OpenSubKey(userAssistBase, writable: false);
                if (baseKey is null) return;

                foreach (var guidName in baseKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var countKey = baseKey.OpenSubKey($@"{guidName}\Count", writable: false);
                        if (countKey is null) continue;

                        foreach (var encodedName in countKey.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementRegistryKeys();

                            var decoded = Rot13Decode(encodedName);
                            var decodedLower = decoded.ToLowerInvariant();

                            var hit = ApexCheatExecutionKeywords.FirstOrDefault(k =>
                                decodedLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (hit is null) continue;

                            int runCount = 0;
                            DateTime? lastRun = null;
                            try
                            {
                                var data = countKey.GetValue(encodedName) as byte[];
                                if (data is { Length: >= 16 })
                                {
                                    runCount = BitConverter.ToInt32(data, 4);
                                    var ft = BitConverter.ToInt64(data, 8);
                                    if (ft > 0) lastRun = DateTime.FromFileTimeUtc(ft);
                                }
                            }
                            catch { }

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"UserAssist: Apex Cheat Executed — {hit}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason   = $"UserAssist forensic record (ROT13 decoded: '{Path.GetFileName(decoded)}') " +
                                           $"shows an Apex Legends cheat tool was executed on this machine " +
                                           $"({runCount} time(s)" +
                                           (lastRun.HasValue ? $", last seen {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                           $"). Matched keyword: '{hit}'. UserAssist entries persist after file deletion.",
                                Detail   = $"Decoded: {decoded} | Runs: {runCount} | Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 14: MUICache for Apex cheat execution records
    // -------------------------------------------------------------------------
    private Task CheckMuiCacheApexCheats(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            const string muiCacheKey =
                @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(muiCacheKey, writable: false);
                if (key is null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    var lowerValue = valueName.ToLowerInvariant();
                    var friendlyName = key.GetValue(valueName) as string ?? string.Empty;
                    var combined = lowerValue + " " + friendlyName.ToLowerInvariant();

                    var hit = ApexCheatExecutionKeywords.FirstOrDefault(k =>
                        combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hit is null) continue;

                    var fn = Path.GetFileName(valueName.Split('.')[0]);
                    bool fileExists = File.Exists(valueName.Split('.')[0]);

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"MUICache: Apex Cheat Executed — {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKCU\{muiCacheKey}",
                        FileName = fn,
                        Reason   = $"MUICache record '{valueName}' matches Apex cheat keyword '{hit}'. " +
                                   "This registry hive caches display names of previously launched executables, " +
                                   $"confirming this Apex cheat tool ran on this system. " +
                                   (fileExists ? "File still present." : "File was deleted but execution record remains."),
                        Detail   = $"Registry value: {valueName} | Description: {friendlyName} | Keyword: {hit}"
                    });
                }
            }
            catch { }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 15: Hosts file blocking EA/EAC servers
    // -------------------------------------------------------------------------
    private Task CheckHostsFileEaBlocking(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var hostsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "drivers", "etc", "hosts");

            if (!File.Exists(hostsPath)) return;

            string content;
            try
            {
                using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            var blockedDomains = new List<string>();
            foreach (var pattern in EaHostsBlockPatterns)
            {
                foreach (var line in content.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith('#')) continue;
                    if (trimmed.Contains(pattern, StringComparison.OrdinalIgnoreCase) &&
                        (trimmed.StartsWith("0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
                         trimmed.StartsWith("127.0.0.1", StringComparison.OrdinalIgnoreCase)))
                    {
                        blockedDomains.Add(pattern);
                        break;
                    }
                }
            }

            if (blockedDomains.Count == 0) return;

            bool blocksEac = blockedDomains.Any(d =>
                d.Contains("easyanticheat", StringComparison.OrdinalIgnoreCase));
            bool blocksEa = blockedDomains.Any(d =>
                d.Contains("ea.com", StringComparison.OrdinalIgnoreCase) ||
                d.Contains("origin.com", StringComparison.OrdinalIgnoreCase));

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = blocksEac
                    ? "Hosts File Blocks EasyAntiCheat Servers (Apex)"
                    : "Hosts File Blocks EA/Origin Servers",
                Risk     = blocksEac ? RiskLevel.Critical : RiskLevel.High,
                Location = hostsPath,
                FileName = "hosts",
                Reason   = $"Windows hosts file redirects or blocks {blockedDomains.Count} EA/EAC server domain(s). " +
                           (blocksEac ? "Blocking EasyAntiCheat servers prevents EAC from validating its integrity and receiving " +
                                        "updated cheat signatures, effectively disabling protection for Apex Legends. "
                                      : "") +
                           "This is a known cheat setup technique.",
                Detail   = "Blocked domains: " + string.Join(", ", blockedDomains)
            });
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 16: RTSS / MSI Afterburner profiles modified for Apex cheating
    // -------------------------------------------------------------------------
    private Task CheckRtssOverlayProfiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var rtssDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "RivaTuner Statistics Server"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "RivaTuner Statistics Server"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "MSI Afterburner"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "MSI Afterburner"),
            };

            foreach (var dir in rtssDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.cfg", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);

                    foreach (var kw in SuspiciousRtssProfileKeywords)
                    {
                        if (fn.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Suspicious RTSS/Afterburner Apex Profile: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"RTSS/MSI Afterburner configuration file '{fn}' contains Apex cheat-related " +
                                           $"keyword '{kw}'. Overlay cheats sometimes use modified RTSS profiles to " +
                                           "render ESP and aimbot information as a GPU overlay without code injection.",
                                Detail   = $"Profile directory: {dir}"
                            });
                            break;
                        }
                    }

                    // Also scan file content
                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    foreach (var kw in SuspiciousRtssProfileKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"RTSS Profile Content References Apex Cheat: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"RTSS/Afterburner profile '{fn}' references Apex cheat overlay keyword '{kw}'. " +
                                           "This suggests the overlay tool may have been configured to display cheat information " +
                                           "during Apex Legends gameplay.",
                                Detail   = $"Keyword: {kw}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 17: Origin launch options for Apex with -dev or cheat flags
    // -------------------------------------------------------------------------
    private Task CheckOriginLaunchOptions(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            // Origin/EA stores launch options in XML game manifests
            var originDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Origin", "LocalContent"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Origin", "games"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Origin"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Origin"),
            };

            var suspiciousLaunchArgs = new[]
            {
                "-dev", "-cheats", "-noeac", "-noeasyanticheat",
                "-disable_eac", "-bypasseac", "+developer 1",
                "-allowdebug", "-debug", "-testapp", "-insecure",
                "eac_bypass", "no_eac",
            };

            foreach (var dir in originDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.xml", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!file.Contains("apex", StringComparison.OrdinalIgnoreCase) &&
                        !file.Contains("r5", StringComparison.OrdinalIgnoreCase)) continue;

                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    foreach (var arg in suspiciousLaunchArgs)
                    {
                        if (content.Contains(arg, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Suspicious Apex Launch Argument: {arg}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason   = $"Apex Legends Origin/EA launch manifest '{Path.GetFileName(file)}' contains " +
                                           $"suspicious launch argument '{arg}'. Developer/debug/no-EAC flags in game " +
                                           "launch options can bypass anti-cheat enforcement or enable cheat-friendly modes.",
                                Detail   = $"Argument: {arg} | File: {file}"
                            });
                            break;
                        }
                    }
                }
            }

            // Also check registry for Origin/EA launch options
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Origin\Games", writable: false);
                if (key is null) return;

                foreach (var gameName in key.GetSubKeyNames())
                {
                    if (!gameName.Contains("apex", StringComparison.OrdinalIgnoreCase) &&
                        !gameName.Contains("titanfall", StringComparison.OrdinalIgnoreCase)) continue;
                    try
                    {
                        using var gameKey = key.OpenSubKey(gameName, writable: false);
                        if (gameKey is null) continue;
                        ctx.IncrementRegistryKeys();

                        var launchOpts = gameKey.GetValue("LaunchOptions") as string ?? string.Empty;
                        foreach (var arg in suspiciousLaunchArgs)
                        {
                            if (launchOpts.Contains(arg, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"Apex Registry Launch Option: {arg}",
                                    Risk     = RiskLevel.High,
                                    Location = $@"HKCU\SOFTWARE\Origin\Games\{gameName}",
                                    Reason   = $"Origin registry launch options for '{gameName}' contain suspicious " +
                                               $"argument '{arg}' which may bypass EasyAntiCheat for Apex Legends.",
                                    Detail   = $"LaunchOptions: {launchOpts}"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 18: Apex AppData directory for unexpected executables
    // -------------------------------------------------------------------------
    private Task CheckApexAppDataExecutables(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var savedPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Respawn", "Apex"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Respawn", "Apex"),
            };

            foreach (var savedPath in savedPaths)
            {
                if (!Directory.Exists(savedPath)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(savedPath, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    // No .exe/.dll/.sys should legitimately be in Apex saved game dirs
                    if (ext == ".exe" || ext == ".dll" || ext == ".sys")
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Executable in Apex Saved Game Directory: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Executable or system file '{fn}' found in Apex Legends saved game directory. " +
                                       "Legitimate Apex Legends saved data does not include executable files. " +
                                       "This is a common technique to hide cheat components near game data.",
                            Detail   = $"Path: {file}"
                        });
                        continue;
                    }

                    if (ext == ".cfg" || ext == ".ini" || ext == ".json" || ext == ".xml")
                    {
                        string content;
                        try
                        {
                            ctx.IncrementFiles();
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }

                        var hits = CheatConfigKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (hits.Count > 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Cheat Keywords in Apex App Data: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"Apex app data config file '{fn}' contains {hits.Count} cheat-related " +
                                           "keyword(s). Cheat tools sometimes store configuration alongside legitimate " +
                                           "game save data to evade detection.",
                                Detail   = "Keywords: " + string.Join(", ", hits.Take(5))
                            });
                        }
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 19: Downloads folder for Apex cheat archives and executables
    // -------------------------------------------------------------------------
    private Task CheckDownloadsFolderApex(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var downloads = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

            if (!Directory.Exists(downloads)) return;

            var allCheatKeywords = ApexCheatExecutionKeywords
                .Concat(new[] { "apex_cheat", "apexhack", "eac_bypass_apex", "apexaimbot",
                                 "apex_esp", "apex_aim", "apex_wallhack", "apex_loader",
                                 "apex_bypass", "apex_eac", "radar_apex", "apex_radar",
                                 "apex_recoil", "no_recoil_apex", "apex_speed", "apex_bhop" })
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            string[] files;
            try { files = Directory.GetFiles(downloads, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                var fn = Path.GetFileName(file).ToLowerInvariant();
                var ext = Path.GetExtension(file).ToLowerInvariant();

                foreach (var kw in allCheatKeywords)
                {
                    if (fn.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        bool isExec = ext == ".exe" || ext == ".dll" || ext == ".sys";
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Apex Cheat Download: {Path.GetFileName(file)}",
                            Risk     = isExec ? RiskLevel.Critical : RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"File '{Path.GetFileName(file)}' in Downloads folder contains Apex cheat keyword '{kw}'. " +
                                       "Cheat tools are commonly downloaded and stored in the Downloads directory " +
                                       "before being executed or installed.",
                            Detail   = $"Keyword: {kw} | Extension: {ext}"
                        });
                        break;
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 20: Suspicious DLL names in Origin/EA game directories
    // -------------------------------------------------------------------------
    private Task CheckSuspiciousGameDirDlls(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var apexGameDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Origin Games", "Apex"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "EA Games", "Apex Legends"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "EA Games", "Apex Legends"),
                @"C:\Program Files (x86)\Origin Games\Apex",
                @"C:\Program Files\EA Games\Apex Legends",
            };
            var steamPaths = GetSteamApexPaths();
            var allDirs = apexGameDirs.Concat(steamPaths).ToArray();

            foreach (var dir in allDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] dlls;
                try { dlls = Directory.GetFiles(dir, "*.dll", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var dll in dlls)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(dll).ToLowerInvariant();
                    ctx.IncrementFiles();

                    foreach (var fragment in SuspiciousGameDirDllFragments)
                    {
                        if (fn.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Suspicious DLL in Apex Game Directory: {Path.GetFileName(dll)}",
                                Risk     = RiskLevel.High,
                                Location = dll,
                                FileName = Path.GetFileName(dll),
                                Reason   = $"DLL '{Path.GetFileName(dll)}' in the Apex Legends game directory contains " +
                                           $"suspicious fragment '{fragment}'. Legitimate Apex game DLLs do not include " +
                                           "cheat-related terms in their names. This may indicate DLL injection staging " +
                                           "or an EAC bypass shim placed inside the game folder.",
                                Detail   = $"Fragment: {fragment} | Game dir: {dir}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);
    }
}
