using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class WarzoneCODCheatScanModule : IScanModule
{
    public string Name => "Warzone / COD Cheat Deep Scan";
    public double Weight => 3.8;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    // -------------------------------------------------------------------------
    // RICOCHET anti-cheat bypass tool filenames
    // -------------------------------------------------------------------------
    private static readonly string[] RicochetBypassFiles =
    {
        "ricochet_bypass.exe", "rico_bypass.dll", "coda_bypass.dll",
        "ricochet_bypass.dll", "rico_bypass.exe", "coda_bypass.exe",
        "ricochet_killer.exe", "ricochet_killer.dll", "ricochet_patch.exe",
        "ricochet_disable.dll", "ricochet_hook.dll", "ricochet_hook.exe",
        "ricochet_inject.dll", "ricochet_inject.exe",
        "ricochet_spoof.dll", "ricochet_spoof.exe",
        "bypass_ricochet.exe", "bypass_ricochet.dll",
        "cod_anticheat_bypass.exe", "cod_anticheat_bypass.dll",
        "wz_anticheat_bypass.exe", "wz_bypass.exe", "wz_bypass.dll",
        "call_of_duty_bypass.exe", "activision_bypass.exe",
        "mw2_bypass.exe", "mw3_bypass.exe", "mw_bypass.exe",
        "warzone_bypass.exe", "warzone_bypass.dll",
        "wz2_bypass.exe", "wz2_bypass.dll",
        // Kernel-mode bypass artifacts
        "ntkrnl_patch.exe", "ntkrnl_bypass.exe", "ntkrnl_hook.dll",
        "vmusbmouse_bypass.exe", "km_bypass.sys", "km_bypass.exe",
        "km_bypass.dll", "vmusbmouse.sys.bak", "ntkrnl_replacement.exe",
        "ntoskrnl_spoof.exe", "kernel_bypass_ricochet.exe",
        "ricochet_kernel_bypass.exe", "driver_bypass_rico.sys",
        "cod_kernel_patch.exe",
    };

    // -------------------------------------------------------------------------
    // Aimbot filenames for Warzone / COD
    // -------------------------------------------------------------------------
    private static readonly string[] AimbotFiles =
    {
        "warzone_aim.exe", "cod_aimbot.dll", "wz_aimbot.exe",
        "wz_aimbot.dll", "warzone_aimbot.exe", "warzone_aimbot.dll",
        "cod_aim.exe", "cod_aim.dll", "mw_aimbot.exe", "mw_aimbot.dll",
        "mw2_aimbot.exe", "mw2_aimbot.dll", "mw3_aimbot.exe",
        "silent_aim_wz.exe", "silent_aim_wz.dll", "silent_aim_cod.dll",
        "wz_silent_aim.exe", "cod_silent_aim.dll",
        "wz_aim.exe", "wz_aim.dll", "wz_aimassist.exe", "wz_aimassist.dll",
        "aimbot_warzone.exe", "aimbot_warzone.dll",
        "triggerbot_cod.dll", "wz_trigger.exe", "cod_trigger.dll",
        "wz_triggerbot.exe", "wz_triggerbot.dll", "cod_triggerbot.exe",
        "bone_aimbot_wz.dll", "head_aim_wz.dll",
        "fov_aimbot_wz.dll", "smooth_aimbot_wz.dll",
        "prediction_wz.dll", "aim_prediction_cod.dll",
        "auto_aim_wz.exe", "auto_aim_wz.dll",
    };

    // -------------------------------------------------------------------------
    // Wallhack / ESP filenames for Warzone / COD
    // -------------------------------------------------------------------------
    private static readonly string[] WallhackEspFiles =
    {
        "warzone_esp.dll", "wz_wh.exe", "cod_esp.dll",
        "wz_esp.exe", "wz_esp.dll", "warzone_wallhack.exe",
        "warzone_wallhack.dll", "cod_wallhack.exe", "cod_wallhack.dll",
        "wz_wallhack.exe", "wz_wallhack.dll",
        "mw_esp.dll", "mw2_esp.dll", "mw3_esp.dll",
        "mw_wh.exe", "mw_wallhack.dll", "cod_wh.exe", "cod_wh.dll",
        "wz_player_esp.dll", "wz_loot_esp.dll", "wz_item_esp.dll",
        "wz_skeleton_esp.dll", "wz_health_esp.dll", "wz_armor_esp.dll",
        "wz_distance_esp.dll", "wz_box_esp.dll",
        "wz_glow.dll", "wz_chams.dll", "wz_glow.exe",
        "wz_external_esp.dll", "wz_external_esp.exe",
        "cod_external_esp.dll", "warzone_external.exe",
        "cod_visible_check.dll", "wz_vis_check.dll",
    };

    // -------------------------------------------------------------------------
    // No-recoil filenames
    // -------------------------------------------------------------------------
    private static readonly string[] NoRecoilFiles =
    {
        "wz_recoil.exe", "no_recoil_wz.dll", "wz_no_recoil.exe",
        "wz_no_recoil.dll", "cod_no_recoil.exe", "cod_no_recoil.dll",
        "warzone_recoil.exe", "warzone_no_recoil.dll",
        "mw_no_recoil.dll", "mw2_no_recoil.dll",
        "no_recoil_cod.exe", "no_recoil_cod.dll",
        "recoil_control_wz.dll", "recoil_script_wz.exe",
        "wz_norecoil.exe", "wz_norecoil.dll",
        "anti_recoil_cod.dll", "spray_control_wz.dll",
        "cod_recoil_reducer.dll",
    };

    // -------------------------------------------------------------------------
    // Radar hack filenames
    // -------------------------------------------------------------------------
    private static readonly string[] RadarHackFiles =
    {
        "wz_radar.exe", "cod_radar.dll", "wz_radar.dll",
        "warzone_radar.exe", "warzone_radar.dll",
        "cod_radar.exe", "mw_radar.exe", "mw_radar.dll",
        "mw2_radar.exe", "wz_map_hack.exe", "wz_minimap.dll",
        "warzone_radar_server.exe", "wz_radar_hack.exe",
        "cod_minimap_hack.dll", "wz_enemy_radar.dll",
        "cod_map_reveal.dll", "wz_radar_esp.dll",
    };

    // -------------------------------------------------------------------------
    // Unlock-all / stat editor filenames
    // -------------------------------------------------------------------------
    private static readonly string[] UnlockAllFiles =
    {
        "unlock_all_cod.exe", "wz_unlocker.dll", "unlock_all_wz.exe",
        "cod_unlocker.exe", "cod_unlocker.dll", "wz_unlock.exe",
        "wz_unlock.dll", "cod_unlock_all.exe", "cod_stat_editor.exe",
        "warzone_unlocker.exe", "mw_unlocker.exe", "mw2_unlocker.exe",
        "cod_skin_unlocker.exe", "wz_operator_unlock.exe",
        "cod_camo_unlocker.exe", "cod_blueprint_unlock.dll",
        "unlock_all_mw2.exe", "unlock_all_mw3.exe",
        "wz_rank_hack.exe", "cod_rank_editor.exe",
        "wz_xp_hack.exe", "cod_xp_editor.exe",
        "cod_prestige_hack.exe", "wz_money_hack.exe",
    };

    // -------------------------------------------------------------------------
    // Known COD / Warzone cheat loaders and hack EXEs
    // -------------------------------------------------------------------------
    private static readonly string[] CheatLoaderFiles =
    {
        "warzoneHack.exe", "CODhack.exe", "wzcheat.exe", "mw_cheater.exe",
        "warzonecheats.exe", "wz_cheat.exe", "cod_cheat.exe",
        "warzone_hack.exe", "cod_hack.exe", "wz_loader.exe",
        "cod_loader.exe", "wz_cheat_loader.exe", "cod_cheat_loader.exe",
        "warzone_loader.exe", "wz_injector.exe", "cod_injector.exe",
        "warzone_injector.exe", "mw_loader.exe", "mw2_loader.exe",
        "mw3_loader.exe", "wz2_loader.exe", "wz2_cheat.exe",
        "warzone2_hack.exe", "warzone2_cheat.exe",
        "warzone2_loader.exe", "wz_mod.exe", "wz_mod_menu.exe",
        "cod_mod_menu.exe", "warzone_mod.exe",
        "wz_premium_cheat.exe", "wz_private_cheat.exe",
        "wz_free_cheat.exe", "wz_undetected.exe",
        "engineowning_wz.exe", "skycheats_wz.exe",
        "ringone_wz.exe", "blackcell_wz.exe",
        "cod_paid_cheat.exe", "activision_cheat.exe",
        "battlenet_bypass.exe", "battlenet_hack.exe",
        "bnet_bypass.exe", "bnet_cheat.exe",
    };

    // -------------------------------------------------------------------------
    // Known cheat DLL names (injectable)
    // -------------------------------------------------------------------------
    private static readonly string[] CheatDllNames =
    {
        "wz_cheat.dll", "cod_cheat.dll", "warzone_hack.dll",
        "wz_internal.dll", "cod_internal.dll", "warzone_internal.dll",
        "wz_hook.dll", "cod_hook.dll", "warzone_memory.dll",
        "wz_memory.dll", "cod_memory.dll", "wz_offsets.dll",
        "cod_offsets.dll", "wz_core.dll", "cod_core.dll",
        "wz_base.dll", "cod_base.dll", "wz_sdk.dll",
        "cod_sdk.dll", "wz_features.dll", "cod_features.dll",
        "wz_render.dll", "cod_render.dll", "wz_draw.dll",
        "wz_input.dll", "cod_input.dll", "wz_patch.dll",
        "battlenet_bypass.dll", "bnet_bypass.dll",
        "activision_bypass.dll",
    };

    // -------------------------------------------------------------------------
    // Hardware spoofer filenames specific to RICOCHET hardware bans
    // -------------------------------------------------------------------------
    private static readonly string[] HwidSpooferCodFiles =
    {
        "cod_spoofer.exe", "wz_spoofer.exe", "ricochet_spoofer.exe",
        "cod_hwid_spoofer.exe", "wz_hwid_spoofer.exe",
        "activision_spoofer.exe", "battlenet_spoofer.exe",
        "cod_serial_changer.exe", "wz_serial_spoofer.exe",
        "ricochet_hwid_bypass.exe", "cod_ban_bypass.exe",
        "wz_ban_bypass.exe", "cod_unban.exe", "wz_unban.exe",
        "activision_ban_bypass.exe", "cod_account_bypass.exe",
        "wz_account_spoofer.exe", "cod_mac_spoofer.exe",
        "wz_disk_spoofer.exe", "cod_gpu_spoofer.exe",
        "wz_cpu_spoofer.exe", "ricochet_bypass_hwid.exe",
    };

    // -------------------------------------------------------------------------
    // Activision account bypass / ban evasion tools
    // -------------------------------------------------------------------------
    private static readonly string[] AccountBypassFiles =
    {
        "activision_account_bypass.exe", "activision_ban_evade.exe",
        "cod_account_creator.exe", "wz_account_gen.exe",
        "battlenet_account_bypass.exe", "cod_new_account.exe",
        "wz_account_reset.exe", "activision_unban.exe",
        "ricochet_account_bypass.exe", "shadowban_bypass_cod.exe",
        "wz_shadowban_evade.exe", "cod_phone_spoof.exe",
        "activision_phone_bypass.exe", "cod_phone_number_bypass.exe",
    };

    // -------------------------------------------------------------------------
    // Battle.net launcher bypass/modification files
    // -------------------------------------------------------------------------
    private static readonly string[] BattleNetBypassFiles =
    {
        "battlenet_bypass.exe", "battlenet_bypass.dll",
        "battlenet_crack.exe", "battlenet_patch.exe",
        "bnet_bypass.exe", "bnet_bypass.dll",
        "bnet_crack.exe", "bnet_patch.exe",
        "agent_bypass.exe", "agent_patch.exe",
        "battlenet_offline.exe", "bnet_offline.dll",
        "blizzard_bypass.exe", "blizzard_patch.exe",
    };

    // -------------------------------------------------------------------------
    // Suspicious COD/Warzone config keywords in config.cfg or autoexec
    // -------------------------------------------------------------------------
    private static readonly string[] CheatConfigKeywords =
    {
        "aimbot_smoothing_wz", "aimbot_fov_wz", "aimbot_bone_wz",
        "esp_boxes_wz", "esp_health_wz", "esp_armor_wz",
        "esp_ammo_wz", "esp_distance_wz", "no_recoil_wz",
        "silent_aim_wz", "triggerbot_wz", "loot_esp_wz",
        "speedhack_wz", "bhop_wz", "spinbot_wz", "wallhack_wz",
        "wz_aimbot", "wz_esp", "wz_wallhack", "cod_aimbot",
        "cod_esp", "wz_triggerbot", "cod_triggerbot",
        "wz_aim_key", "wz_esp_key", "wz_triggerbot_key",
        "aimbot_enabled_wz", "esp_enabled_wz", "wallhack_enabled_wz",
        "no_recoil_enabled", "silent_aim_enabled",
        "aim_at_head_wz", "aim_at_body_wz",
        "aimbot_prediction_wz", "movement_prediction_wz",
        "wz_player_list", "wz_bone_list", "wz_hitbox",
        "wz_team_filter", "wz_visibility_check",
        "wz_smooth_factor", "draw_fov_circle_wz",
        "esp_skeleton_wz", "esp_snapline_wz",
        "wz_no_spread", "wz_rapid_fire", "wz_fast_loot",
        "triggerbot_enabled", "triggerbot_delay_wz",
        "ricochet_bypass_cfg", "wz_unlock_all",
        "esp_distance_wz", "esp_name_wz", "esp_weapon_wz",
        "cod_cheat_settings", "warzone_cheat_cfg",
    };

    // -------------------------------------------------------------------------
    // COD memory offset identifiers for DMA / external cheats
    // -------------------------------------------------------------------------
    private static readonly string[] OffsetKeywords =
    {
        "LocalPlayer", "EntityList", "ViewMatrix", "Health", "Armor",
        "TeamNum", "WorldToScreen", "m_iHealth", "m_iArmor",
        "m_iTeamNum", "m_vecOrigin", "m_vecVelocity", "m_bAlive",
        "m_nModelIndex", "ModernWarfare", "Warzone",
        "PlayerArray", "GameContext", "CGameMode",
        "RelativeLocation", "AbsoluteLocation", "BoneMatrix",
        "LocalPlayerPtr", "CameraManager", "VisibilityBone",
        "CursorHint", "weapon_def", "vehicle_ptr",
        "cod_offsets", "mw_offsets", "wz_offsets",
        "soldier_ptr", "player_health", "player_position",
        "squad_id", "loadout_ptr", "parachute_state",
    };

    // -------------------------------------------------------------------------
    // Suspicious kernel artifacts related to RICOCHET bypass
    // -------------------------------------------------------------------------
    private static readonly string[] RicochetKernelArtifacts =
    {
        "ntkrnl_replacement", "ntkrnl_bypass", "ntkrnl_patch",
        "vmusbmouse.sys", "km_bypass.sys", "km_bypass",
        "ricochet_driver", "ricochet_kernel", "cod_kernel_bypass",
        "ricochet_bypass_driver", "anti_ricochet.sys",
        "driver_bypass_wz.sys", "cod_drv_bypass.sys",
        "shadowless.sys", "umbrabypass.sys",
    };

    // -------------------------------------------------------------------------
    // Hosts file entries blocking Activision / Battle.net servers
    // -------------------------------------------------------------------------
    private static readonly string[] ActivisionHostsBlockPatterns =
    {
        "activision.com", "callofduty.com", "battlenet.com",
        "battle.net", "blizzard.com", "blizzard.net",
        "api.activision.com", "login.activision.com",
        "telemetry.activision.com", "ricochet.activision.com",
        "anticheat.activision.com", "cod.tracker.gg",
        "us.battle.net", "eu.battle.net", "kr.battle.net",
        "cdn.blizzard.com", "agent.battle.net",
    };

    // -------------------------------------------------------------------------
    // Registry keys for Warzone cheat loaders / run entries
    // -------------------------------------------------------------------------
    private static readonly string[] WzCheatRunKeywords =
    {
        "warzoneHack", "wzcheat", "wz_cheat", "cod_cheat",
        "warzone_hack", "cod_hack", "wz_loader", "cod_loader",
        "warzone_loader", "wz_injector", "cod_injector",
        "ricochet_bypass", "battlenet_bypass", "bnet_bypass",
        "wz_aimbot", "cod_aimbot", "wz_esp", "cod_esp",
        "wz_unlocker", "cod_unlocker", "wz_spoofer", "cod_spoofer",
        "activision_bypass", "wz_radar", "cod_radar",
        "wz_bypass", "warzonecheats", "wz_mod",
    };

    // -------------------------------------------------------------------------
    // UserAssist / MUICache keywords for Warzone / COD cheats
    // -------------------------------------------------------------------------
    private static readonly string[] WzCheatExecutionKeywords =
    {
        "warzoneHack", "CODhack", "wzcheat", "mw_cheater",
        "warzonecheats", "wz_cheat", "cod_cheat", "warzone_hack",
        "cod_hack", "wz_loader", "cod_loader", "warzone_loader",
        "wz_injector", "cod_injector", "ricochet_bypass", "bnet_bypass",
        "wz_aimbot", "cod_aimbot", "wz_esp", "cod_esp",
        "wz_unlocker", "cod_unlocker", "wz_spoofer", "cod_spoofer",
        "activision_bypass", "wz_radar", "cod_radar",
        "wz_bypass", "warzone_bypass", "unlock_all_cod",
        "wz_wallhack", "wz_triggerbot", "cod_triggerbot",
        "wz_no_recoil", "cod_no_recoil", "wz_silent_aim",
        "engineowning", "skycheats", "ringone_cod", "blackcell_wz",
    };

    // -------------------------------------------------------------------------
    // RTSS / overlay profile keywords for COD cheats
    // -------------------------------------------------------------------------
    private static readonly string[] SuspiciousRtssProfileKeywords =
    {
        "wz_esp_overlay", "wz_aim_overlay", "wz_cheat_overlay",
        "cod_cheat_overlay", "warzonehack", "wz_external_esp",
        "cod overlay cheat", "warzone overlay", "ricochet overlay bypass",
    };

    // -------------------------------------------------------------------------
    // Temp folder artifact patterns
    // -------------------------------------------------------------------------
    private static readonly string[] TempArtifactKeywords =
    {
        "wz_", "warzone_", "ricochet_", "cod_cheat", "mw_hack",
        "wz_cheat", "cod_hack", "bnet_bypass", "activision_bypass",
        "wz_bypass", "cod_bypass", "wz_inject", "cod_inject",
    };

    // -------------------------------------------------------------------------
    // Scan path builder
    // -------------------------------------------------------------------------
    private static string[] GetWzScanPaths()
    {
        var localApp     = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var temp         = Path.GetTempPath();
        var programX86   = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

        return new[]
        {
            Path.Combine(localApp, "Activision"),
            Path.Combine(programX86, "Battle.net"),
            Path.Combine(programFiles, "Battle.net"),
            Path.Combine(localApp, "Battle.net"),
            Path.Combine(programFiles, "Call of Duty"),
            Path.Combine(programFiles, "Call of Duty HQ"),
            Path.Combine(programX86, "Call of Duty"),
            @"C:\Program Files (x86)\Battle.net",
            @"C:\Program Files\Call of Duty",
            @"C:\Program Files\Call of Duty HQ",
            Path.Combine(userProfile, "Downloads"),
            temp,
            Path.Combine(localApp, "Temp"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
        };
    }

    private static IEnumerable<string> GetCodGameDirs()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programX86   = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var candidates = new List<string>
        {
            Path.Combine(programFiles, "Call of Duty"),
            Path.Combine(programFiles, "Call of Duty HQ"),
            Path.Combine(programFiles, "Modern Warfare II"),
            Path.Combine(programFiles, "Modern Warfare III"),
            Path.Combine(programX86, "Call of Duty"),
            @"C:\Program Files\Call of Duty",
            @"C:\Program Files\Call of Duty HQ",
            @"D:\Call of Duty",
            @"D:\Games\Call of Duty",
            @"E:\Games\Call of Duty",
        };

        // Battle.net install path from registry
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Blizzard Entertainment\Battle.net\Capabilities", writable: false);
            var installPath = key?.GetValue("ApplicationName") as string;
            if (!string.IsNullOrEmpty(installPath))
                candidates.Add(Path.GetDirectoryName(installPath) ?? string.Empty);
        }
        catch { }

        return candidates.Where(d => !string.IsNullOrEmpty(d));
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
        ctx.Report(0.0, Name, "Starting Warzone / COD cheat deep scan...");

        await Task.WhenAll(
            CheckWarzoneGameDirectoryFiles(ctx, ct),
            CheckCheatLoaderFiles(ctx, ct),
            CheckAimbotAndEspFiles(ctx, ct),
            CheckNoRecoilFiles(ctx, ct),
            CheckRadarHackFiles(ctx, ct),
            CheckUnlockAllTools(ctx, ct),
            CheckRicochetBypassFiles(ctx, ct),
            CheckKernelBypassArtifacts(ctx, ct),
            CheckHwidSpooferFiles(ctx, ct),
            CheckAccountBypassTools(ctx, ct),
            CheckBattleNetBypassFiles(ctx, ct),
            CheckWarzoneProcesses(ctx, ct),
            CheckCodConfigFiles(ctx, ct),
            CheckCodOffsetFiles(ctx, ct),
            CheckRegistryRunKeys(ctx, ct),
            CheckRicochetServiceRegistry(ctx, ct),
            CheckUserAssistWzCheats(ctx, ct),
            CheckMuiCacheWzCheats(ctx, ct),
            CheckHostsFileActivisionBlocking(ctx, ct),
            CheckRtssOverlayProfiles(ctx, ct),
            CheckTempFolderArtifacts(ctx, ct),
            CheckActivisionAppData(ctx, ct),
            CheckDownloadsFolderWarzone(ctx, ct),
            CheckSuspiciousGameDirDlls(ctx, ct)
        );

        ctx.Report(1.0, Name, "Warzone / COD cheat deep scan complete.");
    }

    // -------------------------------------------------------------------------
    // Check 1: COD game directories for cheat EXEs and DLLs
    // -------------------------------------------------------------------------
    private Task CheckWarzoneGameDirectoryFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var allPaths = GetWzScanPaths().Concat(GetCodGameDirs()).ToArray();

            var allCheatFiles = CheatLoaderFiles
                .Concat(CheatDllNames)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

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

                    if (!allCheatFiles.Contains(fn)) continue;

                    bool isDll = fn.EndsWith(".dll", StringComparison.OrdinalIgnoreCase);
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = isDll
                            ? $"Warzone/COD Cheat DLL Found: {fn}"
                            : $"Warzone/COD Cheat Executable Found: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = isDll
                            ? $"Known Warzone/COD cheat DLL '{fn}' found in scan path. These DLLs are injected into " +
                              "the game process or used by DMA hardware cheats to provide aimbot, ESP, and memory " +
                              "reading capabilities while bypassing RICOCHET anti-cheat."
                            : $"Known Warzone/COD cheat executable '{fn}' found. This binary is a cheat loader, " +
                              "injector, or hack tool targeting Call of Duty: Warzone and its anti-cheat system.",
                        Detail   = $"Path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 2: Standalone cheat loaders in user-accessible paths
    // -------------------------------------------------------------------------
    private Task CheckCheatLoaderFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var loaderSet = CheatLoaderFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);
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
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!loaderSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Warzone Cheat Loader in User Directory: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Warzone/COD cheat loader '{fn}' found in user-accessible directory '{dir}'. " +
                                   "Cheat tools targeting Warzone are commonly stored in these directories and " +
                                   "executed before or during gameplay to inject cheats past RICOCHET.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 3: Aimbot and ESP specific files
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
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Activision"),
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
                    if (!allAimbotEsp.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    bool isAimbot = AimbotFiles.Any(a => a.Equals(fn, StringComparison.OrdinalIgnoreCase));
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = isAimbot
                            ? $"Warzone/COD Aimbot File: {fn}"
                            : $"Warzone/COD ESP/Wallhack File: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = isAimbot
                            ? $"Known Warzone aimbot file '{fn}' detected. Warzone aimbot tools automatically track " +
                              "and snap to enemy targets, providing unfair accuracy advantages that cannot be " +
                              "replicated through legitimate skill."
                            : $"Known Warzone ESP/wallhack file '{fn}' detected. These tools render enemy positions, " +
                              "health bars, loot, and other game-state information through solid surfaces, " +
                              "providing complete battlefield awareness.",
                        Detail   = $"Path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 4: No-recoil hack files
    // -------------------------------------------------------------------------
    private Task CheckNoRecoilFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var recoilSet = NoRecoilFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);
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
                    if (!recoilSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Warzone/COD No-Recoil Hack: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Warzone/COD no-recoil hack '{fn}' found. No-recoil tools eliminate " +
                                   "weapon recoil patterns via scripted mouse movements or memory patching, " +
                                   "providing significantly improved automatic weapon accuracy.",
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
                        Title    = $"Warzone/COD Radar Hack: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Warzone/COD radar hack '{fn}' detected. Radar hacks reveal all player " +
                                   "positions, vehicle locations, and loot on an external display map, eliminating " +
                                   "the information asymmetry that is core to battle royale competition.",
                        Detail   = $"Path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 6: Unlock-all and stat editor tools
    // -------------------------------------------------------------------------
    private Task CheckUnlockAllTools(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var unlockSet = UnlockAllFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Activision"),
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
                    if (!unlockSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"COD Unlock-All / Stat Editor Tool: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known COD/Warzone unlock-all or stat editor tool '{fn}' found. These tools " +
                                   "modify account statistics, unlock all operators/weapons/camos, or manipulate " +
                                   "player progression through unauthorized server-side or client-side modifications.",
                        Detail   = $"Path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 7: RICOCHET bypass specific files
    // -------------------------------------------------------------------------
    private Task CheckRicochetBypassFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var ricochetSet = RicochetBypassFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers"),
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

                    if (ricochetSet.Contains(fn))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"RICOCHET Anti-Cheat Bypass Tool: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Known RICOCHET anti-cheat bypass tool '{fn}' found. RICOCHET is Activision's " +
                                       "kernel-level anti-cheat for Call of Duty: Warzone. Bypass tools disable or " +
                                       "circumvent this protection to allow cheat injection without ban detection.",
                            Detail   = $"Path: {file}"
                        });
                        continue;
                    }

                    // Fuzzy: ricochet + bypass in filename
                    var fnLower = fn.ToLowerInvariant();
                    if (fnLower.Contains("ricochet") &&
                        (fnLower.Contains("bypass") || fnLower.Contains("patch") ||
                         fnLower.Contains("disable") || fnLower.Contains("hook") ||
                         fnLower.Contains("kill") || fnLower.Contains("spoof")))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Suspicious RICOCHET Bypass File: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"File '{fn}' combines RICOCHET-related and bypass-related name components. " +
                                       "This naming pattern is strongly indicative of anti-cheat evasion tooling " +
                                       "targeting Call of Duty: Warzone.",
                            Detail   = $"Path: {file}"
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 8: Kernel-level RICOCHET bypass artifacts (ntkrnl, vmusbmouse, km_bypass)
    // -------------------------------------------------------------------------
    private Task CheckKernelBypassArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var driversDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");

            var systemDir = Environment.GetFolderPath(Environment.SpecialFolder.System);

            var kernelSearchDirs = new[] { driversDir, systemDir };

            foreach (var dir in kernelSearchDirs)
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
                    ctx.IncrementFiles();

                    foreach (var artifact in RicochetKernelArtifacts)
                    {
                        if (fn.Contains(artifact, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"RICOCHET Kernel Bypass Artifact: {fn}",
                                Risk     = RiskLevel.Critical,
                                Location = file,
                                FileName = fn,
                                Reason   = $"Kernel artifact '{fn}' matching RICOCHET bypass pattern '{artifact}' found " +
                                           $"in system directory '{dir}'. RICOCHET bypass techniques include replacing " +
                                           "ntoskrnl components, planting fake HID drivers (vmusbmouse.sys), and " +
                                           "deploying kernel-mode bypass drivers to disable RICOCHET protection.",
                                Detail   = $"Artifact pattern: {artifact} | System dir: {dir}"
                            });
                            break;
                        }
                    }
                }
            }

            // Check registry for suspicious kernel driver services
            try
            {
                using var services = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services", writable: false);
                if (services is null) return;

                foreach (var svcName in services.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var svc = services.OpenSubKey(svcName, writable: false);
                        if (svc is null) continue;
                        ctx.IncrementRegistryKeys();

                        var type = svc.GetValue("Type") as int? ?? 0;
                        if (type != 1) continue; // kernel drivers only

                        var imagePath = (svc.GetValue("ImagePath") as string ?? "").ToLowerInvariant();
                        foreach (var artifact in RicochetKernelArtifacts)
                        {
                            if (svcName.Contains(artifact, StringComparison.OrdinalIgnoreCase) ||
                                imagePath.Contains(artifact, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"RICOCHET Kernel Bypass Driver Service: {svcName}",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                    FileName = Path.GetFileName(imagePath),
                                    Reason   = $"Kernel driver service '{svcName}' matches RICOCHET bypass pattern '{artifact}'. " +
                                               "RICOCHET bypass drivers operate at kernel level to intercept anti-cheat " +
                                               "queries and return spoofed results, masking active cheats.",
                                    Detail   = $"ImagePath: {imagePath} | Type: {type}"
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
    // Check 9: HWID spoofer files specific to COD/Warzone RICOCHET hardware bans
    // -------------------------------------------------------------------------
    private Task CheckHwidSpooferFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var spooferSet = HwidSpooferCodFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);
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
                    if (!spooferSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"COD/Warzone HWID Spoofer: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known COD/Warzone hardware ID spoofer '{fn}' found. RICOCHET enforces hardware " +
                                   "bans that persist across new accounts and IP addresses. HWID spoofers manipulate " +
                                   "disk serials, MAC addresses, GPU IDs, and CPU IDs to evade these hardware bans " +
                                   "and continue cheating after account bans.",
                        Detail   = $"Path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 10: Activision account bypass / ban evasion tools
    // -------------------------------------------------------------------------
    private Task CheckAccountBypassTools(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var bypassSet = AccountBypassFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
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
                    if (!bypassSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Activision Account Bypass / Ban Evasion Tool: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Activision account bypass or ban evasion tool '{fn}' found. These tools " +
                                   "generate fake phone numbers for Activision account creation (bypassing phone " +
                                   "verification required after bans), create anonymous accounts, or reset " +
                                   "shadowban status — all used to continue cheating after detection.",
                        Detail   = $"Path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 11: Battle.net launcher bypass / modification files
    // -------------------------------------------------------------------------
    private Task CheckBattleNetBypassFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var bnetSet = BattleNetBypassFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var bnetDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Battle.net"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Battle.net"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Battle.net"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Battle.net"),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            };

            foreach (var dir in bnetDirs)
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

                    if (bnetSet.Contains(fn))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Battle.net Launcher Bypass Tool: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Known Battle.net launcher bypass file '{fn}' found. Battle.net bypass tools " +
                                       "intercept the launcher's authentication and patch-verification process, " +
                                       "enabling modified game clients or bypassing RICOCHET initialization " +
                                       "that occurs through the Battle.net launcher.",
                            Detail   = $"Path: {file}"
                        });
                        continue;
                    }

                    // Scan config files in Battle.net dirs for bypass content
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if ((ext == ".cfg" || ext == ".json" || ext == ".ini" || ext == ".xml") &&
                        dir.Contains("Battle.net", StringComparison.OrdinalIgnoreCase))
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

                        if (content.Contains("bypass", StringComparison.OrdinalIgnoreCase) &&
                            (content.Contains("ricochet", StringComparison.OrdinalIgnoreCase) ||
                             content.Contains("anticheat", StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Battle.net Config with Anti-Cheat Bypass Reference: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"Battle.net configuration file '{fn}' references both 'bypass' and " +
                                           "anti-cheat terms (ricochet/anticheat). This may indicate modified " +
                                           "launcher configuration designed to disable or circumvent RICOCHET.",
                                Detail   = $"Path: {file}"
                            });
                        }
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 12: Running processes matching Warzone cheat tools
    // -------------------------------------------------------------------------
    private Task CheckWarzoneProcesses(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var allCheatNames = CheatLoaderFiles
                .Concat(AimbotFiles)
                .Concat(WallhackEspFiles)
                .Concat(NoRecoilFiles)
                .Concat(RadarHackFiles)
                .Concat(UnlockAllFiles)
                .Concat(RicochetBypassFiles)
                .Concat(HwidSpooferCodFiles)
                .Concat(AccountBypassFiles)
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
                        Title    = $"Warzone/COD Cheat Process Active: {pname}",
                        Risk     = RiskLevel.Critical,
                        Location = string.IsNullOrEmpty(procPath) ? $"PID {proc.Id}" : procPath,
                        FileName = pname + ".exe",
                        Reason   = $"Known Warzone/COD cheat process '{pname}' is currently running. " +
                                   "An actively running cheat or bypass tool represents an immediate, ongoing " +
                                   "violation of Call of Duty fair play policies.",
                        Detail   = $"PID: {proc.Id} | Path: {procPath}"
                    });
                }
                catch { }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 13: COD config files (config.cfg and autoexec) for cheat keywords
    // -------------------------------------------------------------------------
    private Task CheckCodConfigFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var codConfigDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Activision"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Battle.net"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "Call of Duty"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "Call of Duty Modern Warfare"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "Call of Duty Modern Warfare II"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "Call of Duty Modern Warfare III"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "AppData", "Local", "Activision", "warzone"),
            };

            foreach (var dir in codConfigDirs)
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
                            Title    = $"Warzone Cheat Config File: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"COD/Warzone config file '{Path.GetFileName(file)}' contains {hits.Count} " +
                                       "cheat-related configuration keywords. This is highly indicative of a " +
                                       "Warzone cheat tool configuration file with multiple active features.",
                            Detail   = "Keywords: " + string.Join(", ", hits.Take(8))
                        });
                    }
                    else if (hits.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Warzone Config Cheat Keyword: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"COD/Warzone config file '{Path.GetFileName(file)}' contains the " +
                                       $"cheat-related keyword '{hits[0]}'. Warzone cheat tools store settings " +
                                       "in config files to persist between game sessions.",
                            Detail   = "Matched: " + string.Join(", ", hits)
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 14: COD memory offset / DMA cheat artifact files
    // -------------------------------------------------------------------------
    private Task CheckCodOffsetFiles(ScanContext ctx, CancellationToken ct)
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
                        || fn.Contains("warzone", StringComparison.OrdinalIgnoreCase)
                        || fn.Contains("cod", StringComparison.OrdinalIgnoreCase)
                        || fn.Contains("mw2", StringComparison.OrdinalIgnoreCase)
                        || fn.Contains("mw3", StringComparison.OrdinalIgnoreCase)
                        || fn.Contains("dump", StringComparison.OrdinalIgnoreCase)
                        || fn.Contains("sdk", StringComparison.OrdinalIgnoreCase)
                        || fn.Contains("dma", StringComparison.OrdinalIgnoreCase);

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
                            Title    = $"Warzone/COD Memory Offset File: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"File '{fn}' contains {hits.Count} Warzone/COD memory offset identifiers. " +
                                       "These files are used by DMA hardware cheats and external hacks to locate " +
                                       "player entities, health, and positions in COD memory without code injection.",
                            Detail   = "Offsets: " + string.Join(", ", hits.Take(8))
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 15: Registry Run keys for Warzone cheat autostart
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

                        foreach (var keyword in WzCheatRunKeywords)
                        {
                            if (valueName.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                                value.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"Warzone Cheat Autostart in Registry: {valueName}",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKLM/HKCU\{keyPath}\{valueName}",
                                    Reason   = $"Registry Run key '{valueName}' references Warzone/COD cheat keyword '{keyword}'. " +
                                               "This indicates a Warzone cheat tool or RICOCHET bypass is configured for " +
                                               "automatic startup with Windows, a persistence mechanism used by persistent cheaters.",
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
    // Check 16: RICOCHET service and Activision registry bypass indicators
    // -------------------------------------------------------------------------
    private Task CheckRicochetServiceRegistry(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            // RICOCHET kernel driver service
            var ricochetServiceKeys = new[]
            {
                @"SYSTEM\CurrentControlSet\Services\ricochet",
                @"SYSTEM\CurrentControlSet\Services\RicochetAC",
                @"SYSTEM\CurrentControlSet\Services\COD_AntiCheat",
                @"SYSTEM\CurrentControlSet\Services\RICOCHET",
            };

            foreach (var svcKey in ricochetServiceKeys)
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
                            Title    = $"RICOCHET Anti-Cheat Service Disabled: {Path.GetFileName(svcKey)}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{svcKey}",
                            Reason   = $"RICOCHET anti-cheat service '{Path.GetFileName(svcKey)}' has Start=4 (disabled). " +
                                       "Disabling the RICOCHET kernel driver allows Warzone cheat injection " +
                                       "without triggering kernel-level integrity monitoring.",
                            Detail   = "Start=4 indicates SERVICE_DISABLED"
                        });
                    }
                }
                catch { }
            }

            // Also scan all kernel services for RICOCHET bypass driver patterns
            try
            {
                using var allServices = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services", writable: false);
                if (allServices is null) return;

                foreach (var svcName in allServices.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var svc = allServices.OpenSubKey(svcName, writable: false);
                        if (svc is null) continue;
                        ctx.IncrementRegistryKeys();

                        var type = svc.GetValue("Type") as int? ?? 0;
                        if (type != 1) continue;

                        var imagePath = (svc.GetValue("ImagePath") as string ?? "").ToLowerInvariant();
                        if ((imagePath.Contains("rico") || imagePath.Contains("warzone") || imagePath.Contains("cod_")) &&
                            (imagePath.Contains("bypass") || imagePath.Contains("patch") || imagePath.Contains("kill")))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Suspicious COD/RICOCHET Kernel Driver: {svcName}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = Path.GetFileName(imagePath),
                                Reason   = $"Kernel driver service '{svcName}' with ImagePath '{imagePath}' combines " +
                                           "COD/RICOCHET-related and bypass-related terms. This pattern is characteristic " +
                                           "of a RICOCHET kernel bypass driver installed to evade COD anti-cheat.",
                                Detail   = $"ImagePath: {imagePath}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }

            // Activision/Battle.net registry for suspicious values
            var activisionKeys = new[]
            {
                @"SOFTWARE\Activision",
                @"SOFTWARE\WOW6432Node\Activision",
                @"SOFTWARE\Blizzard Entertainment\Battle.net",
                @"SOFTWARE\WOW6432Node\Blizzard Entertainment\Battle.net",
            };

            foreach (var regKey in activisionKeys)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey(regKey, writable: false)
                               ?? Registry.CurrentUser.OpenSubKey(regKey, writable: false);
                    if (k is null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valName in k.GetValueNames())
                    {
                        if (valName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("crack", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("ricochet_off", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Suspicious Activision/Battle.net Registry Value: {valName}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM/HKCU\{regKey}",
                                Reason   = $"Activision/Battle.net registry key '{regKey}' contains suspicious value '{valName}'. " +
                                           "Cheat tools may write configuration into official Activision registry paths " +
                                           "to blend in with legitimate COD/Battle.net installation data.",
                                Detail   = $"Value: {valName} | Key: {regKey}"
                            });
                        }
                    }
                }
                catch { }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 17: UserAssist records for Warzone cheat execution history
    // -------------------------------------------------------------------------
    private Task CheckUserAssistWzCheats(ScanContext ctx, CancellationToken ct)
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

                            var hit = WzCheatExecutionKeywords.FirstOrDefault(k =>
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
                                Title    = $"UserAssist: Warzone/COD Cheat Executed — {hit}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason   = $"UserAssist forensic record (ROT13 decoded: '{Path.GetFileName(decoded)}') " +
                                           $"confirms a Warzone/COD cheat tool was executed on this machine " +
                                           $"({runCount} time(s)" +
                                           (lastRun.HasValue ? $", last seen {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                           $"). Matched keyword: '{hit}'. This record persists after file deletion.",
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
    // Check 18: MUICache for Warzone cheat execution records
    // -------------------------------------------------------------------------
    private Task CheckMuiCacheWzCheats(ScanContext ctx, CancellationToken ct)
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

                    var hit = WzCheatExecutionKeywords.FirstOrDefault(k =>
                        combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hit is null) continue;

                    var pathPart = valueName.Contains('.') ? valueName[..valueName.LastIndexOf('.')] : valueName;
                    var fn = Path.GetFileName(pathPart);
                    bool fileExists = File.Exists(pathPart);

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"MUICache: Warzone/COD Cheat Executed — {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKCU\{muiCacheKey}",
                        FileName = fn,
                        Reason   = $"MUICache record '{valueName}' matches Warzone/COD cheat keyword '{hit}'. " +
                                   "Windows MUICache caches display names of launched executables. " +
                                   $"This record confirms this cheat tool ran on this system. " +
                                   (fileExists ? "File still present." : "File deleted, but execution record remains."),
                        Detail   = $"Registry value: {valueName} | Description: {friendlyName} | Keyword: {hit}"
                    });
                }
            }
            catch { }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 19: Hosts file blocking Activision / Battle.net servers
    // -------------------------------------------------------------------------
    private Task CheckHostsFileActivisionBlocking(ScanContext ctx, CancellationToken ct)
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
            foreach (var pattern in ActivisionHostsBlockPatterns)
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

            bool blocksRicochet = blockedDomains.Any(d =>
                d.Contains("ricochet", StringComparison.OrdinalIgnoreCase) ||
                d.Contains("anticheat.activision", StringComparison.OrdinalIgnoreCase));
            bool blocksActivision = blockedDomains.Any(d =>
                d.Contains("activision", StringComparison.OrdinalIgnoreCase) ||
                d.Contains("callofduty", StringComparison.OrdinalIgnoreCase));

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = blocksRicochet
                    ? "Hosts File Blocks RICOCHET/Activision Anti-Cheat Servers"
                    : "Hosts File Blocks Activision/Battle.net Servers",
                Risk     = blocksRicochet ? RiskLevel.Critical : RiskLevel.High,
                Location = hostsPath,
                FileName = "hosts",
                Reason   = $"Windows hosts file redirects or blocks {blockedDomains.Count} Activision/COD server domain(s). " +
                           (blocksRicochet ? "Blocking RICOCHET telemetry and anti-cheat validation servers prevents " +
                                             "the system from receiving updated cheat signatures and integrity checks, " +
                                             "disabling cloud-based COD anti-cheat functions. "
                                           : "") +
                           "Hosts file manipulation is a known cheat infrastructure technique.",
                Detail   = "Blocked: " + string.Join(", ", blockedDomains)
            });
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 20: RTSS / MSI Afterburner overlay profiles for COD cheating
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

                    // Check filename for cheat keywords
                    foreach (var kw in SuspiciousRtssProfileKeywords)
                    {
                        if (fn.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Suspicious RTSS/Afterburner COD Profile: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"RTSS/MSI Afterburner config '{fn}' contains Warzone/COD cheat keyword '{kw}'. " +
                                           "GPU overlay tools are sometimes modified to render Warzone ESP and aimbot " +
                                           "information as a hardware overlay without game process injection.",
                                Detail   = $"Keyword: {kw} | Directory: {dir}"
                            });
                            break;
                        }
                    }

                    // Scan content
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
                                Title    = $"RTSS Profile Content References COD Cheat: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"RTSS/Afterburner profile '{fn}' content contains Warzone cheat keyword '{kw}'. " +
                                           "This indicates the overlay was configured to display cheat-related information " +
                                           "during Warzone gameplay via GPU-level overlay rendering.",
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
    // Check 21: Temp folder artifacts for Warzone cheat remnants
    // -------------------------------------------------------------------------
    private Task CheckTempFolderArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var tempDirs = new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            };

            foreach (var dir in tempDirs)
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
                    var fn = Path.GetFileName(file).ToLowerInvariant();
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    if (ext != ".exe" && ext != ".dll" && ext != ".sys" &&
                        ext != ".bin" && ext != ".dat") continue;

                    foreach (var kw in TempArtifactKeywords)
                    {
                        if (fn.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Warzone Cheat Artifact in Temp: {Path.GetFileName(file)}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason   = $"Executable/binary '{Path.GetFileName(file)}' in temp directory matches " +
                                           $"Warzone cheat artifact keyword '{kw}'. Temp folders are commonly used " +
                                           "as staging areas for Warzone cheats and RICOCHET bypass tools " +
                                           "to minimize a permanent disk footprint.",
                                Detail   = $"Keyword: {kw} | Temp dir: {dir}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 22: Activision app data folder for unexpected executables
    // -------------------------------------------------------------------------
    private Task CheckActivisionAppData(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var activisionDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Activision"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Activision"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Battle.net"),
            };

            foreach (var dir in activisionDirs)
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
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    // Unexpected executables in Activision app data
                    if (ext == ".exe" || ext == ".sys")
                    {
                        bool isKnownLegit = fn.StartsWith("Activision", StringComparison.OrdinalIgnoreCase) ||
                                            fn.StartsWith("Battle.net", StringComparison.OrdinalIgnoreCase) ||
                                            fn.StartsWith("Agent", StringComparison.OrdinalIgnoreCase) ||
                                            fn.StartsWith("BlizzardError", StringComparison.OrdinalIgnoreCase);
                        if (!isKnownLegit)
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Unexpected Executable in Activision App Data: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"Unexpected executable '{fn}' found in Activision application data directory. " +
                                           "Legitimate Activision/Battle.net data does not include arbitrary executables. " +
                                           "This is consistent with cheat tools hiding in official game data paths.",
                                Detail   = $"Path: {file}"
                            });
                        }
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
                                Title    = $"Cheat Keywords in Activision App Data: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"Activision app data file '{fn}' contains {hits.Count} Warzone cheat keyword(s). " +
                                           "Warzone cheat tools sometimes store configuration in Activision directories " +
                                           "to appear as legitimate game data and evade basic detection.",
                                Detail   = "Keywords: " + string.Join(", ", hits.Take(5))
                            });
                        }
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 23: Downloads folder for Warzone cheat files
    // -------------------------------------------------------------------------
    private Task CheckDownloadsFolderWarzone(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var downloads = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

            if (!Directory.Exists(downloads)) return;

            var allCheatKeywords = WzCheatExecutionKeywords
                .Concat(new[] { "wz_cheat", "cod_cheat", "ricochet_bypass", "warzone_hack",
                                 "cod_hack", "wz_aimbot", "cod_aimbot", "wz_esp", "cod_esp",
                                 "wz_wallhack", "wz_bypass", "wz_loader", "unlock_all_cod",
                                 "wz_spoofer", "cod_spoofer", "wz_radar", "wz_unlocker" })
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            string[] files;
            try { files = Directory.GetFiles(downloads, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                var fn = Path.GetFileName(file);
                var fnLower = fn.ToLowerInvariant();
                var ext = Path.GetExtension(file).ToLowerInvariant();

                foreach (var kw in allCheatKeywords)
                {
                    if (fnLower.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        bool isExec = ext == ".exe" || ext == ".dll" || ext == ".sys";
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Warzone/COD Cheat Download: {fn}",
                            Risk     = isExec ? RiskLevel.Critical : RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"File '{fn}' in Downloads folder contains Warzone/COD cheat keyword '{kw}'. " +
                                       "Warzone cheat tools and RICOCHET bypass utilities are commonly downloaded " +
                                       "to the user's Downloads folder before execution.",
                            Detail   = $"Keyword: {kw} | Extension: {ext}"
                        });
                        break;
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 24: Suspicious DLL names in COD game directories
    // -------------------------------------------------------------------------
    private Task CheckSuspiciousGameDirDlls(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var suspiciousFragments = new[]
            {
                "bypass", "inject", "hook", "cheat", "hack", "aim", "esp",
                "wallhack", "recoil", "radar", "spoof", "loader", "patch",
                "internal", "external", "memory", "offset", "trainer",
                "triggerbot", "aimassist", "modmenu", "ricochet_off",
                "cod_bypass", "wz_bypass", "bnet_bypass",
            };

            foreach (var gameDir in GetCodGameDirs())
            {
                if (!Directory.Exists(gameDir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] dlls;
                try { dlls = Directory.GetFiles(gameDir, "*.dll", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var dll in dlls)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(dll).ToLowerInvariant();
                    ctx.IncrementFiles();

                    foreach (var fragment in suspiciousFragments)
                    {
                        if (fn.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Suspicious DLL in COD Game Directory: {Path.GetFileName(dll)}",
                                Risk     = RiskLevel.High,
                                Location = dll,
                                FileName = Path.GetFileName(dll),
                                Reason   = $"DLL '{Path.GetFileName(dll)}' in the Call of Duty game directory contains " +
                                           $"suspicious fragment '{fragment}'. Legitimate COD game DLLs do not carry " +
                                           "cheat-related terms. This may indicate a DLL injection staging file, " +
                                           "a RICOCHET bypass shim, or a cheat payload placed in the game folder.",
                                Detail   = $"Fragment: {fragment} | Game dir: {gameDir}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);
    }
}
