using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class DeadByDaylightCheatScanModule : IScanModule
{
    public string Name => "Dead By Daylight Cheat Forensic Scan";
    public double Weight => 3.2;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    // -------------------------------------------------------------------------
    // Known DBD cheat executable filenames
    // -------------------------------------------------------------------------
    private static readonly string[] DbdCheatExecutables =
    {
        "dbd_cheat.exe", "dbd_hack.exe", "dbd_aimbot.exe", "dbd_noclip.exe",
        "dbd_speed.exe", "dbd_hook_esp.exe", "dbd_aura_read.exe", "dbd_nocd.exe",
        "dbdcheat.exe", "deadbydaylight_cheat.exe", "dbd_trainer.exe",
        "dbd_loader.exe", "dbd_injector.exe", "dbd_internal.exe",
        "dbd_external.exe", "dbd_wallhack.exe", "dbd_godmode.exe",
        "dbd_speedhack.exe", "dbd_teleport.exe", "dbd_menu.exe",
        "deadbydaylight_hack.exe", "deadbydaylight_trainer.exe",
        "dbd_mod.exe", "dbd_premium.exe", "dbd_private.exe",
        "dbd_undetected.exe", "dbd_fly.exe", "dbd_lag_switch.exe",
        "dbd_dc_exploit.exe", "dbd_hatch_hack.exe", "dbd_infinite_sprint.exe",
        "dbd_killer_hack.exe", "dbd_survivor_hack.exe", "dbd_perk_hack.exe",
        "dbd_item_hack.exe", "dbd_mori_hack.exe", "dbd_dc_tool.exe",
        "dbd_crash.exe", "dbd_desync.exe", "dbd_lag_exploit.exe",
        "dbd_rank_hack.exe", "dbd_bloodpoint_hack.exe", "dbd_bp_hack.exe",
        "dbd_prestige_hack.exe", "dbd_locker_hack.exe",
    };

    // -------------------------------------------------------------------------
    // Known DBD cheat DLL filenames
    // -------------------------------------------------------------------------
    private static readonly string[] DbdCheatDlls =
    {
        "dbd_esp.dll", "dbd_survivor_esp.dll", "dbd_killer_esp.dll",
        "dbd_gen_esp.dll", "dbd_aura_read.dll", "dbd_cheat.dll",
        "dbd_hack.dll", "dbd_internal.dll", "dbd_inject.dll",
        "dbd_hook.dll", "dbd_memory.dll", "dbd_offsets.dll",
        "dbd_overlay.dll", "dbd_render.dll", "dbd_draw.dll",
        "dbd_input.dll", "dbd_aimbot.dll", "dbd_aim.dll",
        "deadbydaylight_esp.dll", "deadbydaylight_cheat.dll",
        "dbd_hook_esp.dll", "dbd_totem_esp.dll", "dbd_hex_esp.dll",
        "dbd_pallet_esp.dll", "dbd_locker_esp.dll", "dbd_hatch_esp.dll",
        "dbd_gen_progress.dll", "dbd_aura.dll", "dbd_blueprint.dll",
        "dbd_terror_radius.dll", "dbd_killer_instinct.dll",
        "dbd_obsession_hack.dll", "dbd_basement_esp.dll",
    };

    // -------------------------------------------------------------------------
    // EAC bypass artifacts targeting Dead by Daylight
    // -------------------------------------------------------------------------
    private static readonly string[] DbdEacBypassFiles =
    {
        "dbd_eac_bypass.dll", "eac_dbd.exe", "easyanticheat_bypass_dbd.dll",
        "eac_dbd_bypass.dll", "dbd_eac.dll", "eac_bypass_dbd.exe",
        "dbd_eac_patch.dll", "dbd_anticheat_bypass.dll", "dbd_eac_hook.dll",
        "eac_hook_dbd.dll", "eac_disable_dbd.exe", "dbd_eac_killer.exe",
        "dbd_eac_disable.dll", "dbd_eac_spoofer.dll",
        "deadbydaylight_eac_bypass.dll", "deadbydaylight_eac.exe",
        "dbd_anticheat_disable.dll", "dbd_eac_bypass.exe",
        "bhvr_eac_bypass.dll", "bhvr_anticheat_bypass.dll",
    };

    // -------------------------------------------------------------------------
    // DBD speed hack specific artifacts
    // -------------------------------------------------------------------------
    private static readonly string[] DbdSpeedHackFiles =
    {
        "speed_dbd.dll", "dbd_sprint.exe", "dbd_speed.dll",
        "dbd_speedhack.dll", "dbd_fast_move.dll", "dbd_movement_hack.dll",
        "dbd_infinite_sprint.dll", "dbd_run_speed.dll", "speedhack_dbd.dll",
        "speedhack_dbd.exe", "dbd_super_speed.dll", "dbd_speed_modifier.dll",
        "dbd_velocity_hack.dll", "dbd_killer_speed.dll", "dbd_survivor_speed.dll",
        "dbd_blink_hack.dll", "dbd_phase_walk_hack.dll",
    };

    // -------------------------------------------------------------------------
    // DBD totem and hex reveal artifact files
    // -------------------------------------------------------------------------
    private static readonly string[] DbdTotemHexFiles =
    {
        "dbd_totem_reveal.exe", "dbd_hex_reveal.exe", "dbd_totem_esp.exe",
        "dbd_hex_tracker.exe", "dbd_totem_finder.exe", "dbd_hex_finder.exe",
        "totem_reveal_dbd.exe", "hex_reveal_dbd.exe", "dbd_dull_totem.exe",
        "dbd_lit_totem.exe", "dbd_bone_chill_hack.exe", "dbd_devour_hope_hack.exe",
        "dbd_hex_hunter_hack.exe", "dbd_thrill_hack.exe", "dbd_ruin_hack.exe",
        "totem_dbd.dll", "hex_dbd.dll", "dbd_perk_reveal.dll",
        "dbd_totem_reveal.dll", "dbd_hex_reveal.dll", "dbd_totem_map.html",
    };

    // -------------------------------------------------------------------------
    // DBD memory offset / SDK files
    // -------------------------------------------------------------------------
    private static readonly string[] DbdOffsetFiles =
    {
        "dbd_offsets.json", "dbd_addresses.txt", "dbd_patterns.txt",
        "dbd_offsets.txt", "dbd_offsets.hpp", "dbd_offsets.h",
        "dbd_sdk.hpp", "dbd_sdk.h", "dbd_dump.json",
        "dbd_classes.hpp", "dbd_structs.hpp", "dbd_pointers.json",
        "deadbydaylight_offsets.json", "deadbydaylight_offsets.txt",
        "dbd_memory_addresses.txt", "dbd_pointer_map.json",
        "dbd_sdk_dump.hpp", "bhvr_offsets.json", "bhvr_sdk.hpp",
    };

    // -------------------------------------------------------------------------
    // DBD external overlay tool artifacts for aura reading
    // -------------------------------------------------------------------------
    private static readonly string[] DbdOverlayFiles =
    {
        "dbd_overlay.exe", "dbd_aura_overlay.exe", "dbd_external_overlay.exe",
        "dbd_esp_overlay.exe", "dbd_hud_overlay.exe", "dbd_killer_overlay.exe",
        "dbd_survivor_overlay.exe", "dbd_radar_overlay.exe",
        "dbd_gen_tracker.exe", "dbd_hook_tracker.exe", "dbd_state_tracker.exe",
        "dbd_game_state.exe", "dbd_external_esp.exe", "dbd_external_aura.exe",
        "dbd_minimap.exe", "dbd_map_overlay.exe", "dbd_totem_overlay.exe",
        "dbd_overlay.dll", "dbd_aura_overlay.dll", "dbd_external_overlay.dll",
    };

    // -------------------------------------------------------------------------
    // Epic Games Launcher / Behavior bypass artifacts for DBD
    // -------------------------------------------------------------------------
    private static readonly string[] DbdEpicBypassFiles =
    {
        "dbd_epic_bypass.dll", "epic_bypass_dbd.dll", "dbd_egs_bypass.dll",
        "egs_bypass_dbd.exe", "dbd_epic_games_bypass.exe",
        "dbd_epicstore_bypass.dll", "epic_games_launcher_bypass.dll",
        "egs_hook_dbd.dll", "dbd_epic_hook.dll", "dbd_drm_bypass.dll",
        "bhvr_drm_bypass.dll", "dbd_protection_bypass.dll",
        "dbd_launcher_bypass.exe", "dbd_platform_bypass.dll",
        "dbd_ownership_bypass.dll", "dbd_entitlement_bypass.dll",
    };

    // -------------------------------------------------------------------------
    // DBD cheat configuration keywords
    // -------------------------------------------------------------------------
    private static readonly string[] DbdCheatConfigKeywords =
    {
        "dbd_aimbot", "dbd_esp", "dbd_wallhack", "dbd_survivor_esp",
        "dbd_killer_esp", "dbd_gen_esp", "dbd_hook_esp", "dbd_aura_read",
        "dbd_totem_esp", "dbd_hex_esp", "dbd_noclip", "dbd_godmode",
        "dbd_speedhack", "dbd_teleport", "dbd_nocd", "dbd_infinite_sprint",
        "dbd_lag_switch", "dbd_disconnect_exploit", "dbd_hatch_hack",
        "dbd_rank_hack", "dbd_bloodpoint_hack", "dbd_bp_hack",
        "dbd_perk_reveal", "dbd_obsession_reveal", "dbd_basement_esp",
        "dbd_pallet_esp", "dbd_locker_esp", "dbd_hatch_esp",
        "dbd_terror_radius_hack", "dbd_killer_instinct_reveal",
        "survivor_esp_dbd", "killer_esp_dbd", "aimbot_dbd", "wallhack_dbd",
        "esp_dbd", "noclip_dbd", "godmode_dbd", "speedhack_dbd",
        "aura_read_dbd", "totem_reveal_dbd", "hex_reveal_dbd",
        "dbd_draw_survivors", "dbd_draw_killer", "dbd_draw_totems",
        "dbd_draw_generators", "dbd_draw_hooks", "dbd_draw_lockers",
        "dbd_draw_pallets", "dbd_draw_hatches", "dbd_draw_gates",
        "dbd_draw_chests", "dbd_draw_basements", "dbd_health_bar",
        "dbd_distance_check", "dbd_fov_circle", "dbd_smooth_aim",
        "dbd_aim_key", "dbd_esp_key", "dbd_menu_key", "dbd_panic_key",
        "aimbot_enabled_dbd", "esp_enabled_dbd", "noclip_enabled_dbd",
        "aura_enabled_dbd", "totem_enabled_dbd",
        "dbd_gen_progress_esp", "dbd_gen_timer", "dbd_repair_speed",
        "dbd_sabotage_speed", "dbd_cleanse_speed",
    };

    // -------------------------------------------------------------------------
    // DBD memory offset identifiers (DMA / external cheat artifact keywords)
    // -------------------------------------------------------------------------
    private static readonly string[] DbdOffsetKeywords =
    {
        "LocalPlayer", "PlayerArray", "SurvivorArray", "KillerArray",
        "GeneratorArray", "HookArray", "TotemArray", "PalletArray",
        "HatchArray", "LockerArray", "WorldToScreen", "ViewMatrix",
        "CameraManager", "m_iHealth", "m_vecOrigin", "m_vecLocation",
        "m_bIsKiller", "m_bIsSurvivor", "m_pKiller", "m_pSurvivor",
        "DeadByDaylight", "DBD", "BHVR", "BhvrGame",
        "UDeadByDaylightCharacter", "ADBDPlayer", "AKillerInstinct",
        "AGlobalGameState", "ADBDGameMode", "ABaseGameMode",
        "GeneratorProgress", "HookState", "TotemState",
        "m_bAlive", "PlayerController", "APlayerState",
        "ActorArray", "GObjects", "GNames", "UWorld",
        "KillerPawn", "SurvivorPawn", "CharacterMovement",
        "AuraReadComponent", "TerrorRadius", "KillerInstinct",
    };

    // -------------------------------------------------------------------------
    // UserAssist / MUICache execution keywords for DBD cheats
    // -------------------------------------------------------------------------
    private static readonly string[] DbdCheatExecutionKeywords =
    {
        "dbd_cheat", "dbd_hack", "dbd_esp", "dbd_aimbot", "dbd_loader",
        "dbd_injector", "dbd_bypass", "dbd_eac", "dbdcheat", "dbdhack",
        "deadbydaylight_cheat", "deadbydaylight_hack", "dbd_trainer",
        "dbd_godmode", "dbd_noclip", "dbd_speedhack", "dbd_teleport",
        "dbd_mod", "dbd_menu", "dbd_premium", "dbd_aura",
        "dbd_totem", "dbd_survivor_esp", "dbd_killer_esp",
        "dbd_gen_esp", "dbd_hook_esp", "dbd_overlay",
        "dbd_external", "dbd_internal", "dbd_radar",
        "dbd_sprint", "speed_dbd", "totem_reveal_dbd",
        "dbd_rank_hack", "dbd_bp_hack", "dbd_bloodpoint",
    };

    // -------------------------------------------------------------------------
    // Registry Run key keywords for DBD cheats
    // -------------------------------------------------------------------------
    private static readonly string[] DbdCheatRunKeywords =
    {
        "dbd_cheat", "dbd_hack", "dbd_esp", "dbd_aimbot", "dbd_loader",
        "dbd_injector", "dbd_bypass", "dbd_eac", "dbdcheat", "dbdhack",
        "deadbydaylight_cheat", "dbd_trainer", "dbd_godmode",
        "dbd_noclip", "dbd_speedhack", "dbd_overlay", "dbd_mod",
        "dbd_aura", "dbd_totem", "speed_dbd", "dbd_sprint",
    };

    // -------------------------------------------------------------------------
    // DBD log tampering / cheat pattern keywords found in game logs
    // -------------------------------------------------------------------------
    private static readonly string[] DbdLogCheatPatterns =
    {
        "SpeedHack", "speed hack", "NoClip", "noclip", "GodMode", "god mode",
        "TeleportHack", "teleport hack", "AuraRead", "aura read",
        "EACBypass", "eac bypass", "AntiCheat bypass", "anticheat bypass",
        "CheatDetected", "cheat detected", "InvalidMovement", "invalid movement",
        "PlayerTeleport", "player teleport", "SpeedViolation", "speed violation",
        "SurvivorESP", "KillerESP", "GeneratorESP", "TotemESP",
        "HookESP", "AuraHack", "aura hack", "AimbotActive", "aimbot active",
        "InjectedModule", "injected module", "MemoryRead", "memory read",
        "ProcessHack", "process hack", "DebuggerAttached", "debugger attached",
        "ModuleInjected", "module injected", "HookInstalled", "hook installed",
        "KernelHook", "kernel hook", "DriverHook", "driver hook",
        "InputSimulation", "input simulation", "MouseSimulation",
        "RapidFire", "rapid fire", "AutoClick", "auto click",
        "InfiniteItems", "infinite items", "InfiniteHeal", "infinite heal",
        "InfiniteSprint", "infinite sprint", "LockedPerks", "locked perks",
        "UnlockAll", "unlock all", "FogOfWarDisabled", "fog of war disabled",
        "WallhackActive", "wallhack active", "ESPActive", "esp active",
    };

    // -------------------------------------------------------------------------
    // Suspicious EAC / BHVr-related registry value keywords
    // -------------------------------------------------------------------------
    private static readonly string[] DbdRegistrySuspiciousKeywords =
    {
        "bypass", "cheat", "hack", "crack", "patch", "disable",
        "inject", "hook", "spoof", "trainer", "aimbot", "esp",
    };

    // -------------------------------------------------------------------------
    // Hosts file block patterns for DBD / EAC / Epic Games servers
    // -------------------------------------------------------------------------
    private static readonly string[] DbdHostsBlockPatterns =
    {
        "easyanticheat.net", "easyanticheat.io",
        "api.easyanticheat.net", "download.easyanticheat.net",
        "telemetry.easyanticheat.net", "updates.easyanticheat.net",
        "deadbydaylight.com", "bhvr.com", "behaviourentertainment.com",
        "epicgames.com", "epicgamesonline.com",
        "epicgames-download1.akamaized.net",
        "tracking.epicgames.com", "analytics.epicgames.com",
        "ol.epicgames.com", "account-public-service-prod.ol.epicgames.com",
        "euserv.epicgames.com", "usserv.epicgames.com",
    };

    // -------------------------------------------------------------------------
    // Path builders
    // -------------------------------------------------------------------------
    private static string[] GetDbdScanPaths()
    {
        var localApp    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var temp        = Path.GetTempPath();
        var documents   = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var desktop     = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programX86   = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        return new[]
        {
            Path.Combine(localApp, "DeadByDaylight"),
            Path.Combine(localApp, "DeadByDaylight", "Saved"),
            Path.Combine(localApp, "DeadByDaylight", "Saved", "Logs"),
            Path.Combine(appData, "DeadByDaylight"),
            Path.Combine(appData, "dbd"),
            Path.Combine(localApp, "Temp"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(documents, "Dead by Daylight"),
            Path.Combine(documents, "DeadByDaylight"),
            Path.Combine(documents, "dbd"),
            temp,
            desktop,
            Path.Combine(programFiles, "Epic Games", "DeadByDaylight"),
            Path.Combine(programX86, "Epic Games", "DeadByDaylight"),
            @"C:\Program Files\Epic Games\DeadByDaylight",
            @"C:\Program Files (x86)\Epic Games\DeadByDaylight",
            @"D:\Games\DeadByDaylight",
            @"D:\Epic Games\DeadByDaylight",
            @"E:\Games\DeadByDaylight",
        };
    }

    private static List<string> GetDbdSteamPaths()
    {
        var list = new List<string>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Valve\Steam", writable: false);
            var steamPath = key?.GetValue("InstallPath") as string;
            if (!string.IsNullOrEmpty(steamPath))
                list.Add(Path.Combine(steamPath, "steamapps", "common", "Dead by Daylight"));
        }
        catch { }

        foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed))
        {
            list.Add(Path.Combine(drive.RootDirectory.FullName, "SteamLibrary", "steamapps", "common", "Dead by Daylight"));
            list.Add(Path.Combine(drive.RootDirectory.FullName, "Steam", "steamapps", "common", "Dead by Daylight"));
        }
        return list;
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
        ctx.Report(0.0, Name, "Starting Dead by Daylight cheat forensic scan...");

        await Task.WhenAll(
            CheckDbdCheatExecutables(ctx, ct),
            CheckDbdCheatDlls(ctx, ct),
            CheckEacBypassFiles(ctx, ct),
            CheckDbdSpeedHackFiles(ctx, ct),
            CheckDbdTotemHexFiles(ctx, ct),
            CheckDbdOffsetFiles(ctx, ct),
            CheckDbdOverlayFiles(ctx, ct),
            CheckEpicBypassFiles(ctx, ct),
            CheckDbdLogFilesForCheatPatterns(ctx, ct),
            CheckRegistryRunKeys(ctx, ct),
            CheckUserAssistDbdCheats(ctx, ct),
            CheckMuiCacheDbdCheats(ctx, ct),
            CheckTempFolderDbdArtifacts(ctx, ct),
            CheckHostsFileDbdBlocking(ctx, ct),
            CheckDbdEacServiceRegistry(ctx, ct),
            CheckDbdProcesses(ctx, ct)
        );

        ctx.Report(1.0, Name, "Dead by Daylight cheat forensic scan complete.");
    }

    // -------------------------------------------------------------------------
    // Check 1: Known DBD cheat executables across common directories
    // -------------------------------------------------------------------------
    private Task CheckDbdCheatExecutables(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var exeSet = DbdCheatExecutables.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var allPaths = GetDbdScanPaths().Concat(GetDbdSteamPaths()).ToArray();

            foreach (var dir in allPaths)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.exe", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!exeSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Dead by Daylight Cheat Executable: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Dead by Daylight cheat executable '{fn}' found. This is a known " +
                                   "cheat tool targeting DBD, providing capabilities such as survivor/killer " +
                                   "ESP, aimbot, speedhack, noclip, aura reading, hook and generator ESP, " +
                                   "or EAC bypass functionality violating Behaviour Interactive's ToS.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 2: Known DBD cheat DLLs across common directories
    // -------------------------------------------------------------------------
    private Task CheckDbdCheatDlls(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var dllSet = DbdCheatDlls.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var allPaths = GetDbdScanPaths().Concat(GetDbdSteamPaths()).ToArray();

            foreach (var dir in allPaths)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.dll", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!dllSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Dead by Daylight Cheat DLL: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Dead by Daylight cheat DLL '{fn}' found. These libraries are " +
                                   "injected into the DeadByDaylight-Win64-Shipping.exe process or used " +
                                   "externally to render ESP overlays, read aura data, hook game functions, " +
                                   "or provide speedhack and noclip capabilities.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 3: EAC bypass artifacts for Dead by Daylight
    // -------------------------------------------------------------------------
    private Task CheckEacBypassFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var eacSet = DbdEacBypassFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EasyAntiCheat"),
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

                    if (eacSet.Contains(fn))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"EAC Bypass Tool for Dead by Daylight: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Known EasyAntiCheat bypass artifact '{fn}' found for Dead by Daylight. " +
                                       "EAC bypass tools disable or circumvent the kernel-mode anti-cheat " +
                                       "protection used by DBD, allowing cheat injection and operation without " +
                                       "triggering standard EAC detection mechanisms.",
                            Detail   = $"Full path: {file}"
                        });
                        continue;
                    }

                    // Fuzzy: eac + bypass + dbd context
                    var fnLower = fn.ToLowerInvariant();
                    if ((fnLower.Contains("eac") || fnLower.Contains("easyanticheat")) &&
                        (fnLower.Contains("bypass") || fnLower.Contains("patch") ||
                         fnLower.Contains("disable") || fnLower.Contains("hook") ||
                         fnLower.Contains("kill") || fnLower.Contains("inject")) &&
                        (fnLower.Contains("dbd") || fnLower.Contains("deadbydaylight") ||
                         fnLower.Contains("daylight") || fnLower.Contains("bhvr")) &&
                        (fn.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                         fn.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                         fn.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Suspicious EAC Bypass File (DBD): {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"File '{fn}' combines EasyAntiCheat-related, bypass-related, and " +
                                       "Dead by Daylight-related name components. This naming pattern is " +
                                       "characteristic of anti-cheat evasion tools targeting DBD.",
                            Detail   = $"Full path: {file}"
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 4: DBD speed hack artifact files
    // -------------------------------------------------------------------------
    private Task CheckDbdSpeedHackFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var speedSet = DbdSpeedHackFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

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
                    if (!speedSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Dead by Daylight Speed Hack Artifact: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Dead by Daylight speed hack artifact '{fn}' found. DBD speed hacks " +
                                   "manipulate movement velocity values in process memory to allow survivors " +
                                   "to run faster than intended, make killers walk at abnormal speeds, " +
                                   "or enable infinite sprint without exhaustion. This directly impacts " +
                                   "game balance and is a bannable offense under Behaviour Interactive ToS.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 5: DBD totem and hex perk reveal artifact files
    // -------------------------------------------------------------------------
    private Task CheckDbdTotemHexFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var totemSet = DbdTotemHexFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

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
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!totemSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Dead by Daylight Totem/Hex Reveal Tool: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Dead by Daylight totem or hex perk reveal tool '{fn}' found. " +
                                   "Totem reveal cheats expose the locations of all totems on the map, " +
                                   "including lit Hex perks like Devour Hope, Ruin, and Thrill of the Hunt. " +
                                   "This nullifies entire killer perk strategies and constitutes cheating " +
                                   "under Behaviour Interactive's Terms of Service.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 6: DBD memory offset / SDK artifact files with content scanning
    // -------------------------------------------------------------------------
    private Task CheckDbdOffsetFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var offsetFileSet = DbdOffsetFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

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
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    // Exact filename match against known offset files
                    if (offsetFileSet.Contains(fn))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Dead by Daylight Offset/Address File: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Known Dead by Daylight memory offset file '{fn}' found. " +
                                       "Offset files (dbd_offsets.json, dbd_addresses.txt, dbd_patterns.txt) " +
                                       "contain the memory addresses and pointer chains used by external and " +
                                       "DMA-based DBD cheats to locate game entities such as survivors, " +
                                       "killers, generators, hooks, and totems.",
                            Detail   = $"Full path: {file}"
                        });
                        continue;
                    }

                    // Content scan for DBD offset keywords in relevant file types
                    if (ext != ".json" && ext != ".hpp" && ext != ".h" &&
                        ext != ".cpp" && ext != ".txt" && ext != ".ini") continue;

                    bool nameRelevant = fn.Contains("dbd", StringComparison.OrdinalIgnoreCase) ||
                                        fn.Contains("deadbydaylight", StringComparison.OrdinalIgnoreCase) ||
                                        fn.Contains("daylight", StringComparison.OrdinalIgnoreCase) ||
                                        fn.Contains("bhvr", StringComparison.OrdinalIgnoreCase) ||
                                        fn.Contains("offset", StringComparison.OrdinalIgnoreCase) ||
                                        fn.Contains("sdk", StringComparison.OrdinalIgnoreCase) ||
                                        fn.Contains("dump", StringComparison.OrdinalIgnoreCase);

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

                    var hits = DbdOffsetKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count >= 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Dead by Daylight Memory Offset / SDK File: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"File '{fn}' contains {hits.Count} Dead by Daylight game memory offset " +
                                       "identifiers. These files are used by DMA-based and external DBD cheats " +
                                       "to locate survivors, killers, generators, hooks, and totems in game " +
                                       "memory without requiring code injection into the game process.",
                            Detail   = "Offsets found: " + string.Join(", ", hits.Take(8))
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 7: DBD external overlay and aura reading tools
    // -------------------------------------------------------------------------
    private Task CheckDbdOverlayFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var overlaySet = DbdOverlayFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

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
                    if (!overlaySet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Dead by Daylight External Overlay/Aura Tool: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Dead by Daylight external overlay or aura-reading tool '{fn}' found. " +
                                   "External overlay cheats for DBD render ESP data (survivor positions, " +
                                   "generator progress, hook states, totem locations) as a transparent " +
                                   "overlay on top of the game without injecting into the game process, " +
                                   "making them harder to detect by in-process anti-cheat systems.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 8: Epic Games Launcher / Behaviour bypass artifacts for DBD
    // -------------------------------------------------------------------------
    private Task CheckEpicBypassFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var epicSet = DbdEpicBypassFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EpicGamesLauncher"),
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

                    if (epicSet.Contains(fn))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Epic Games / BHVR Bypass Tool for DBD: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Known Epic Games Launcher or Behaviour Interactive bypass artifact '{fn}' " +
                                       "found for Dead by Daylight. These tools bypass platform-level protections " +
                                       "including EGS ownership verification, entitlement checks, and DRM to " +
                                       "enable unauthorized or modified DBD clients that can load cheat modules.",
                            Detail   = $"Full path: {file}"
                        });
                        continue;
                    }

                    // Fuzzy: epic/bhvr + bypass + dbd context in filenames
                    var fnLower = fn.ToLowerInvariant();
                    if ((fnLower.Contains("epic") || fnLower.Contains("bhvr") || fnLower.Contains("behaviour") ||
                         fnLower.Contains("egs")) &&
                        (fnLower.Contains("bypass") || fnLower.Contains("patch") ||
                         fnLower.Contains("disable") || fnLower.Contains("hook")) &&
                        (fnLower.Contains("dbd") || fnLower.Contains("deadbydaylight") || fnLower.Contains("daylight")) &&
                        (fn.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                         fn.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Suspicious Epic/BHVR Bypass File (DBD): {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"File '{fn}' combines Epic Games/BHVR-related and bypass-related " +
                                       "naming components in a Dead by Daylight context. This pattern is " +
                                       "characteristic of platform bypass tools for DBD.",
                            Detail   = $"Full path: {file}"
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 9: DBD log files for cheat activity patterns
    // -------------------------------------------------------------------------
    private Task CheckDbdLogFilesForCheatPatterns(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var logDirs = new[]
            {
                Path.Combine(localApp, "DeadByDaylight", "Saved", "Logs"),
                Path.Combine(localApp, "DeadByDaylight", "Saved"),
                Path.Combine(localApp, "DeadByDaylight"),
            };

            foreach (var logDir in logDirs)
            {
                if (!Directory.Exists(logDir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(logDir, "*.log", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);

                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hits = DbdLogCheatPatterns
                        .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"DBD Log File Contains Cheat Patterns: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Dead by Daylight log file '{fn}' in '%LOCALAPPDATA%\\DeadByDaylight\\Saved\\Logs\\' " +
                                       $"contains {hits.Count} cheat-indicative patterns. These log entries may " +
                                       "record detection events, error conditions triggered by memory manipulation, " +
                                       "or anomalous game state changes associated with active cheat software.",
                            Detail   = "Patterns: " + string.Join(", ", hits.Take(6))
                        });
                    }
                    else if (hits.Count == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"DBD Log File Contains Cheat Pattern: {fn}",
                            Risk     = RiskLevel.Medium,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Dead by Daylight log file '{fn}' contains the pattern '{hits[0]}' " +
                                       "associated with cheat tool activity or anomalous game behavior. " +
                                       "Single hits require corroboration from other findings.",
                            Detail   = "Pattern: " + hits[0]
                        });
                    }
                }

                // Also scan crash log and backup logs
                string[] txtFiles;
                try { txtFiles = Directory.GetFiles(logDir, "*.txt", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in txtFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);

                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hits = DbdLogCheatPatterns
                        .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"DBD Text Log Contains Cheat Patterns: {fn}",
                            Risk     = RiskLevel.Medium,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Dead by Daylight text file '{fn}' contains {hits.Count} cheat-related " +
                                       "patterns. May indicate cheat tool logs, crash dumps, or game error " +
                                       "records from previous cheat activity sessions.",
                            Detail   = "Patterns: " + string.Join(", ", hits.Take(6))
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 10: Registry Run keys for DBD cheat autostart
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

                        foreach (var keyword in DbdCheatRunKeywords)
                        {
                            if (valueName.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                                value.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"DBD Cheat Autostart Registry Entry: {valueName}",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKLM/HKCU\{keyPath}\{valueName}",
                                    Reason   = $"Registry Run key '{valueName}' references Dead by Daylight " +
                                               $"cheat-related keyword '{keyword}'. This indicates a DBD cheat " +
                                               "tool is configured to launch automatically with Windows, " +
                                               "a persistence technique used by advanced DBD cheat loaders " +
                                               "and injectors to ensure pre-launch setup before DBD starts.",
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
    // Check 11: UserAssist registry records for DBD cheat execution history
    // -------------------------------------------------------------------------
    private Task CheckUserAssistDbdCheats(ScanContext ctx, CancellationToken ct)
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

                            var hit = DbdCheatExecutionKeywords.FirstOrDefault(k =>
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
                                Title    = $"DBD Cheat Execution History (UserAssist): {Path.GetFileName(decoded)}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason   = $"UserAssist execution history contains a record for Dead by Daylight " +
                                           $"cheat-related executable matching keyword '{hit}'. " +
                                           "Windows UserAssist tracks executed programs, providing forensic " +
                                           "evidence this cheat tool was actively launched on this machine.",
                                Detail   = $"Decoded: {decoded} | Runs: {runCount} | " +
                                           $"Last: {lastRun?.ToString("u") ?? "unknown"}"
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
    // Check 12: MUICache registry for DBD cheat execution artifacts
    // -------------------------------------------------------------------------
    private Task CheckMuiCacheDbdCheats(ScanContext ctx, CancellationToken ct)
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
                    var valueNameLower = valueName.ToLowerInvariant();

                    var hit = DbdCheatExecutionKeywords.FirstOrDefault(k =>
                        valueNameLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hit is null) continue;

                    var displayName = key.GetValue(valueName)?.ToString() ?? string.Empty;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"DBD Cheat Execution Artifact (MUICache): {Path.GetFileName(valueName)}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKCU\{muiCacheKey}",
                        FileName = Path.GetFileName(valueName),
                        Reason   = $"MUICache contains an entry for a Dead by Daylight cheat-related " +
                                   $"executable matching keyword '{hit}'. The Windows MUICache records " +
                                   "friendly display names of executables that have been run, providing " +
                                   "forensic evidence of past DBD cheat tool execution even if the file " +
                                   "itself has been deleted.",
                        Detail   = $"Path: {valueName} | Display: {displayName}"
                    });
                }
            }
            catch { }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 13: Temp folder comprehensive scan for DBD cheat artifacts
    // -------------------------------------------------------------------------
    private Task CheckTempFolderDbdArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var tempDirs = new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            };

            var allDbdCheatFiles = DbdCheatExecutables
                .Concat(DbdCheatDlls)
                .Concat(DbdEacBypassFiles)
                .Concat(DbdSpeedHackFiles)
                .Concat(DbdTotemHexFiles)
                .Concat(DbdOverlayFiles)
                .Concat(DbdEpicBypassFiles)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var tempDir in tempDirs)
            {
                if (!Directory.Exists(tempDir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(tempDir, "*.*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);

                    if (allDbdCheatFiles.Contains(fn))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"DBD Cheat Artifact in Temp Folder: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Known Dead by Daylight cheat artifact '{fn}' found in the system Temp " +
                                       "folder. Cheat tools frequently extract, stage, or cache components in " +
                                       "Temp directories during loading, installation, or between game sessions " +
                                       "before being cleaned up by the cheat tool itself.",
                            Detail   = $"Temp directory: {tempDir} | Full path: {file}"
                        });
                        continue;
                    }

                    // Fuzzy scan for unlisted DBD cheat files in Temp
                    var fnLower = fn.ToLowerInvariant();
                    var ext = Path.GetExtension(fn).ToLowerInvariant();
                    if (ext != ".exe" && ext != ".dll" && ext != ".sys") continue;

                    bool isDbdRelated = fnLower.Contains("dbd") ||
                                        fnLower.Contains("deadbydaylight") ||
                                        fnLower.Contains("daylight") ||
                                        fnLower.Contains("bhvr");

                    bool isCheatRelated = fnLower.Contains("cheat") || fnLower.Contains("hack") ||
                                          fnLower.Contains("esp") || fnLower.Contains("aimbot") ||
                                          fnLower.Contains("bypass") || fnLower.Contains("inject") ||
                                          fnLower.Contains("trainer") || fnLower.Contains("noclip") ||
                                          fnLower.Contains("godmode") || fnLower.Contains("speed") ||
                                          fnLower.Contains("aura") || fnLower.Contains("totem") ||
                                          fnLower.Contains("reveal") || fnLower.Contains("overlay");

                    if (!isDbdRelated || !isCheatRelated) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Suspicious DBD-Related Temp File: {fn}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Executable/DLL '{fn}' found in Temp folder combines Dead by Daylight " +
                                   "and cheat-related naming patterns. Temp folder staging is a common " +
                                   "behavioral indicator of cheat loaders and injectors.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 14: Hosts file entries blocking DBD / EAC / Epic Games servers
    // -------------------------------------------------------------------------
    private Task CheckHostsFileDbdBlocking(ScanContext ctx, CancellationToken ct)
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
                ctx.IncrementFiles();
                using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }

            foreach (var pattern in DbdHostsBlockPatterns)
            {
                if (ct.IsCancellationRequested) return;
                if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                foreach (var line in content.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("#")) continue;
                    if (!trimmed.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    if (trimmed.StartsWith("0.0.0.0") || trimmed.StartsWith("127."))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Hosts File Blocking DBD/EAC/Epic Server: {pattern}",
                            Risk     = RiskLevel.High,
                            Location = hostsPath,
                            FileName = "hosts",
                            Reason   = $"The system hosts file contains an active redirect blocking '{pattern}'. " +
                                       "Blocking Dead by Daylight backend servers, EasyAntiCheat endpoints, " +
                                       "or Epic Games services is a known technique used alongside DBD cheat " +
                                       "tools to prevent ban enforcement, telemetry reporting, and cheat " +
                                       "signature updates from reaching the game client.",
                            Detail   = $"Blocking entry: {trimmed.Trim()}"
                        });
                        break;
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 15: EAC service and BHVR/Epic registry state for DBD
    // -------------------------------------------------------------------------
    private Task CheckDbdEacServiceRegistry(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var eacServiceKeys = new[]
            {
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat",
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS",
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_DBD",
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_DeadByDaylight",
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
                            Title    = $"EasyAntiCheat Service Disabled (DBD): {Path.GetFileName(svcKey)}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{svcKey}",
                            Reason   = $"EasyAntiCheat service '{Path.GetFileName(svcKey)}' is set to Start=4 " +
                                       "(disabled). Dead by Daylight requires EAC to be enabled and functional. " +
                                       "Disabling this service allows DBD cheat tools to operate without " +
                                       "triggering kernel-mode anti-cheat protection.",
                            Detail   = "Start=4 indicates SERVICE_DISABLED in Windows SCM"
                        });
                    }

                    var imagePath = key.GetValue("ImagePath") as string ?? string.Empty;
                    if (!string.IsNullOrEmpty(imagePath))
                    {
                        var fnLower = Path.GetFileName(imagePath).ToLowerInvariant();
                        if (fnLower.Contains("bypass") || fnLower.Contains("patch") ||
                            fnLower.Contains("hook") || fnLower.Contains("disable"))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"EAC Service ImagePath References Bypass Binary (DBD): {Path.GetFileName(imagePath)}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{svcKey}",
                                Reason   = $"EasyAntiCheat service ImagePath references a potentially modified " +
                                           $"binary '{Path.GetFileName(imagePath)}' in a Dead by Daylight context. " +
                                           "Replacing the EAC service binary with a bypass shim prevents the " +
                                           "anti-cheat kernel module from loading, allowing unrestricted cheat use.",
                                Detail   = $"ImagePath: {imagePath}"
                            });
                        }
                    }
                }
                catch { }
            }

            // Check BHVR / Epic Games / Dead by Daylight registry paths
            var gameKeys = new[]
            {
                @"SOFTWARE\Behaviour Interactive\Dead By Daylight",
                @"SOFTWARE\BHVR\Dead By Daylight",
                @"SOFTWARE\DeadByDaylight",
                @"SOFTWARE\EpicGames\Unreal Engine\DeadByDaylight",
                @"SOFTWARE\WOW6432Node\EpicGames\Unreal Engine\DeadByDaylight",
                @"SOFTWARE\WOW6432Node\Behaviour Interactive\Dead By Daylight",
            };

            foreach (var gameKey in gameKeys)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var k = Registry.CurrentUser.OpenSubKey(gameKey, writable: false)
                               ?? Registry.LocalMachine.OpenSubKey(gameKey, writable: false);
                    if (k is null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valName in k.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        var valNameLower = valName.ToLowerInvariant();

                        bool isSuspicious = DbdRegistrySuspiciousKeywords.Any(kw =>
                            valNameLower.Contains(kw, StringComparison.OrdinalIgnoreCase));

                        if (!isSuspicious) continue;

                        var val = k.GetValue(valName)?.ToString() ?? string.Empty;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Suspicious DBD/BHVR Registry Value: {valName}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU/HKLM\{gameKey}",
                            Reason   = $"Dead by Daylight/BHVR registry key '{gameKey}' contains suspicious " +
                                       $"value name '{valName}' matching cheat-related keywords. Cheat tools " +
                                       "sometimes write configuration or bypass state into legitimate game " +
                                       "registry paths to blend with normal installation data.",
                            Detail   = $"Value name: {valName} | Data: {val} | Key: {gameKey}"
                        });
                    }
                }
                catch { }
            }

            // Check for Epic Online Services registry bypass indicators
            var eosKey = @"SOFTWARE\Epic Games\EOS";
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(eosKey, writable: false)
                           ?? Registry.CurrentUser.OpenSubKey(eosKey, writable: false);
                if (k is not null)
                {
                    ctx.IncrementRegistryKeys();
                    foreach (var valName in k.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        if (valName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("disable", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("hook", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Suspicious Epic Online Services Registry Value: {valName}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM/HKCU\{eosKey}",
                                Reason   = $"Epic Online Services registry key contains suspicious value '{valName}'. " +
                                           "EOS handles anti-cheat coordination for Dead by Daylight; " +
                                           "suspicious EOS registry values may indicate bypass configuration.",
                                Detail   = $"Key: {eosKey} | Value: {valName}"
                            });
                        }
                    }
                }
            }
            catch { }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 16: Running processes matching known DBD cheat tool names
    // -------------------------------------------------------------------------
    private Task CheckDbdProcesses(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var allCheatProcNames = DbdCheatExecutables
                .Concat(DbdOverlayFiles.Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)))
                .Concat(DbdTotemHexFiles.Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)))
                .Select(f => Path.GetFileNameWithoutExtension(f))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var proc in ctx.GetProcessSnapshot())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementProcesses();
                try
                {
                    var pname = proc.ProcessName;
                    if (!allCheatProcNames.Contains(pname)) continue;

                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"DBD Cheat Process Currently Running: {pname}",
                        Risk     = RiskLevel.Critical,
                        Location = string.IsNullOrEmpty(procPath) ? $"PID {proc.Id}" : procPath,
                        FileName = pname + ".exe",
                        Reason   = $"Known Dead by Daylight cheat process '{pname}' is currently active. " +
                                   "An actively running DBD cheat tool confirms that cheat software is " +
                                   "operational on this machine and may currently be targeting a DBD session.",
                        Detail   = $"PID: {proc.Id} | Path: {procPath}"
                    });
                }
                catch { }
            }
        }, ct);
    }
}
