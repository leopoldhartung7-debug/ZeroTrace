using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class PUBG2CheatDeepScanModule : IScanModule
{
    public string Name => "PUBG Cheat Deep Forensic Scan";
    public double Weight => 3.6;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    // -------------------------------------------------------------------------
    // Known PUBG cheat executable and DLL artifact names
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> KnownCheatExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        "pubg_aimbot.exe",
        "pubg_esp.dll",
        "pubg_wh.exe",
        "pubg_cheat.exe",
        "bpubg.exe",
        "pubghack.exe",
        "pubg_trigger.exe",
        "pubg_no_recoil.exe",
        "pubg_radar.exe",
        "pubgm_cheat.exe",
        "pubg_speed.exe",
        "pubg_loot_esp.exe",
        "pubg_player_esp.exe",
        "pubg_vehicle_esp.dll",
        "pubg_aimbot.dll",
        "pubg_esp.exe",
        "pubg_hack.exe",
        "pubg_hack.dll",
        "pubg_wallhack.exe",
        "pubg_wallhack.dll",
        "pubg_loader.exe",
        "pubg_loader.dll",
        "pubg_injector.exe",
        "pubg_injector.dll",
        "pubg_bypass.exe",
        "pubg_bypass.dll",
        "pubg_external.exe",
        "pubg_external.dll",
        "pubg_internal.exe",
        "pubg_internal.dll",
        "pubg_menu.exe",
        "pubg_spinbot.exe",
        "pubg_silentaim.exe",
        "pubg_silentaim.dll",
        "pubg_triggerbot.exe",
        "pubg_triggerbot.dll",
        "pubg_bhop.exe",
        "pubg_flyhack.exe",
        "pubg_teleport.exe",
        "pubg_godmode.exe",
        "pubg_auto_heal.exe",
        "pubg_auto_loot.exe",
        "pubg_loot_filter.exe",
        "pubg_zone_esp.exe",
        "pubg_vehicle.exe",
        "pubg_crate_esp.exe",
        "pubg_parachute.exe",
        "pubg_bomb_esp.exe",
        "pubg_radar_server.exe",
        "pubgradar.exe",
        "pubg_dma.exe",
        "pubg_dma.dll",
        "dma_pubg.exe",
        "pubg_memory.exe",
        "pubg_memory.dll",
        "pubg_hvh.exe",
        "pubg_ragebot.exe",
        "pubg_legitbot.exe",
        "pubg_aimassist.exe",
        "pubg_unlocker.exe",
        "pubg_spoofer.exe",
        "tslgame_cheat.exe",
        "tslgame_hack.exe",
        "tslgame_external.exe",
        "tslgame_memory.exe",
        "tsl_cheat.exe",
        "tsl_hack.exe",
        "tsl_loader.exe",
        "tslloader.exe",
        "pubglite_hack.exe",
        "pubg_mobile_hack.exe",
        "pubgmobile_hack.exe",
        "bgmi_hack.exe",
        "bgmicheat.exe",
        "pubg_kill_all.exe",
        "pubg_esp_boxes.exe",
        "pubg_skeleton_esp.exe",
        "pubg_name_esp.exe",
        "pubg_distance_esp.exe",
        "pubg_weapon_esp.exe",
        "pubg_drop_esp.exe",
        "pubg_airdrop_esp.exe",
        "pubg_iteminfo.exe",
        "pubg_minimap.exe",
        "pubg_3d_radar.exe",
        "pubg_2d_radar.exe",
        "pubg_fakeping.exe",
        "pubg_lagswitch.exe",
        "pubg_norecoil.exe",
        "pubg_nospread.exe",
        "pubg_instantkill.exe",
        "pubg_bullet_drop_off.exe",
        "pubg_leadshots.exe",
        "pubg_anti_report.exe",
        "pubg_smart_bullet.exe",
        "pubg_streamer_mode.exe",
        "pubg_obs_bypass.exe",
    };

    // -------------------------------------------------------------------------
    // BattlEye bypass artifact names for PUBG
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> BattleEyeBypassArtifacts = new(StringComparer.OrdinalIgnoreCase)
    {
        "pubg_be_bypass.dll",
        "battleye_bypass_pubg.exe",
        "be_bypass_pubg.dll",
        "be_bypass_pubg.exe",
        "be_bypass.dll",
        "be_bypass.exe",
        "battleye_bypass.dll",
        "battleye_bypass.exe",
        "be_hook.dll",
        "be_hook.exe",
        "be_spoofer.dll",
        "be_disable_pubg.exe",
        "be_patch_pubg.dll",
        "be_inject_pubg.dll",
        "be_loader_pubg.exe",
        "beservice_bypass.dll",
        "beclient_bypass.dll",
        "battleeye_bypass.dll",
        "battle_eye_bypass.dll",
        "be_kill_pubg.exe",
        "be_unload_pubg.exe",
        "pubg_be_hook.dll",
        "pubg_be_patch.dll",
        "pubg_be_disable.exe",
        "pubg_battleye.exe",
        "pubgbebypass.exe",
        "pubgbebypass.dll",
        "be_client_bypass.dll",
        "beservice_pubg_bypass.dll",
        "betesimulator.dll",
        "be_emulator.dll",
        "be_emulator_pubg.dll",
        "battleye_emulator.dll",
        "battleye_emulator.exe",
        "be_emu.dll",
        "be_emu.exe",
        "pubg_be_emu.dll",
    };

    // -------------------------------------------------------------------------
    // PUBG emulator (GameLoop/TxGameAssistant) cheat tool artifacts
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> EmulatorCheatArtifacts = new(StringComparer.OrdinalIgnoreCase)
    {
        "gameloop_cheat.exe",
        "gameloop_esp.exe",
        "gameloop_aimbot.exe",
        "gameloop_hack.exe",
        "gameloop_bypass.exe",
        "txgame_cheat.exe",
        "txgameassistant_bypass.exe",
        "tencent_gaming_bypass.exe",
        "tgp_cheat.exe",
        "tgp_hack.exe",
        "tgp_esp.exe",
        "tgp_aimbot.exe",
        "gamebuddy_cheat.exe",
        "pubg_emulator_hack.exe",
        "pubg_gameloop_hack.exe",
        "pubg_mobile_emulator_hack.exe",
        "pubgm_emulator_cheat.exe",
        "pubgm_gameloop_esp.exe",
        "pubgm_tencent_bypass.exe",
        "gameassistant_bypass.exe",
        "txgame_bypass.dll",
        "gameloop_bypass.dll",
        "txgame_hook.dll",
        "gameloop_hook.dll",
        "txgp_bypass.dll",
        "tenprotect_bypass.dll",
        "tprt_bypass.dll",
        "transporthub_bypass.dll",
    };

    // -------------------------------------------------------------------------
    // PUBG radar hack relay script names and patterns
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> RadarHackArtifacts = new(StringComparer.OrdinalIgnoreCase)
    {
        "websocket_relay_pubg.py",
        "radar_pubg.html",
        "radar_pubg.js",
        "pubg_radar.html",
        "pubg_radar.js",
        "pubg_radar.py",
        "pubg_radar_server.py",
        "pubg_map_relay.py",
        "pubg_ws_relay.py",
        "pubg_websocket.py",
        "pubg_radar_client.html",
        "pubg_radar_client.js",
        "pubg_2dradar.html",
        "pubg_3dradar.html",
        "pubg_minimap_relay.py",
        "pubg_minimap_relay.js",
        "pubg_radar_setup.bat",
        "pubg_radar_install.bat",
        "pubg_radar_run.bat",
        "radar_server_pubg.py",
        "radar_client_pubg.html",
        "map_pubg_radar.html",
        "pubg_esp_web.html",
        "pubg_esp_web.js",
        "pubg_dma_radar.py",
        "pubg_dma_radar.html",
        "dma_radar_pubg.py",
        "fpga_radar_pubg.py",
        "pcileech_pubg.py",
        "pubg_pcileech.py",
    };

    // -------------------------------------------------------------------------
    // PUBG offset and memory pattern file names
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> OffsetAndPatternFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "pubg_offsets.json",
        "pubg_addresses.txt",
        "pubg_patterns.txt",
        "pubg_offsets.txt",
        "pubg_offsets.cfg",
        "pubg_offsets.ini",
        "pubg_offsets.yaml",
        "pubg_netvars.json",
        "pubg_netvars.txt",
        "pubg_dump.txt",
        "pubg_dump.json",
        "pubg_signatures.txt",
        "pubg_patterns.json",
        "pubg_addresses.json",
        "offsets_pubg.json",
        "offsets_pubg.txt",
        "tslgame_offsets.json",
        "tslgame_offsets.txt",
        "tslgame_dump.txt",
        "tslgame_patterns.txt",
        "tslgame_addresses.txt",
        "pubg_config.json",
        "pubg_config.ini",
        "pubg_config.txt",
        "pubg_config.yaml",
        "pubg_settings.json",
        "pubg_settings.ini",
        "pubg_settings.txt",
        "pubg_cheat_config.json",
        "pubg_cheat_config.ini",
        "pubg_cheat_settings.json",
        "pubg_aimbot_config.json",
        "pubg_esp_config.json",
        "pubg_trigger_config.json",
        "pubg_recoil_config.json",
        "pubg_radar_config.json",
        "pubg_loot_config.json",
        "pubg_filter_config.json",
    };

    // -------------------------------------------------------------------------
    // PUBG config.ini cheat keywords (in-game config modifications)
    // -------------------------------------------------------------------------

    private static readonly string[] ConfigCheatKeywords =
    {
        "aimbot_smooth_pubg", "aimbot_fov_pubg", "esp_boxes_pubg",
        "esp_health_pubg", "esp_loot_pubg", "loot_filter_pubg",
        "vehicle_esp", "bomb_esp", "zone_esp", "parachute_hack",
        "no_recoil_pubg", "no_spread_pubg", "silent_aim_pubg",
        "triggerbot_pubg", "bhop_pubg", "speedhack_pubg",
        "instant_kill", "auto_heal", "auto_loot", "loot_esp_pubg",
        "crate_esp", "player_esp_pubg", "radar_pubg", "map_hack_pubg",
        "pubg_aimbot", "pubg_esp", "pubg_wallhack", "pubg_aim",
        "tslgame_aim", "tslgame_esp", "aim_at_head_pubg",
        "aim_at_body_pubg", "aim_prediction_pubg", "aim_bone_pubg",
        "draw_fov_pubg", "draw_esp_pubg", "draw_loot_pubg",
        "filter_ammo", "filter_armor", "filter_helmet", "filter_meds",
        "filter_weapons", "loot_priority", "auto_pickup",
        "recoil_control", "spread_control", "bullet_drop_pubg",
        "lead_target_pubg", "bullet_velocity_pubg",
        "aimbot_enabled", "esp_enabled", "wallhack_enabled",
        "norecoil_enabled", "radar_enabled", "trigger_enabled",
        "bhop_enabled", "speedhack_enabled", "godmode_enabled",
        "flyhack_enabled", "teleport_enabled", "killall_enabled",
        "aimbot_key", "esp_key", "wallhack_key", "trigger_key",
        "aimbot_smooth", "aimbot_fov", "aimbot_bone",
        "esp_distance", "esp_box", "esp_skeleton", "esp_healthbar",
        "esp_name", "esp_weapon", "esp_vehicle",
        "loot_esp_distance", "loot_filter_enabled",
        "radar_port", "radar_host", "websocket_port",
        "be_bypass_enabled", "battleye_bypass",
        "be_disable", "be_hook_enabled",
    };

    // -------------------------------------------------------------------------
    // PUBG in-game Unreal Engine offset keywords (validates offset files)
    // -------------------------------------------------------------------------

    private static readonly string[] Tf2OffsetKeywords =
    {
        "TslGame-Win64-Shipping", "GWorld", "GNames", "ULevel",
        "APlayerController", "ACharacter", "USkeletalMeshComponent",
        "BoneArray", "m_team", "PlayerArray", "ActorArray", "ItemTable",
        "UGameInstance", "UWorld", "PersistentLevel",
        "TslPlayerController", "TslCharacter", "TslInventory",
        "TslLootDropContainer", "TslVehicle", "TslAirDrop",
        "TslProjectile", "BluezoneRadius", "PlayZone",
        "ActorList", "EntityArray", "WorldToScreen",
        "ViewMatrix", "LocalPlayer", "CameraManager",
        "FNamePool", "TUObjectArray", "GUObjectArray",
        "APlayerState", "ATslPlayerState", "GetBoneMatrix",
        "ComponentToWorld", "RootComponent", "AActor",
        "GetPlayerViewPoint", "GetLocalPlayer",
    };

    // -------------------------------------------------------------------------
    // Registry Run key keywords for PUBG cheat persistence
    // -------------------------------------------------------------------------

    private static readonly string[] RegistryRunKeywords =
    {
        "pubg_aimbot", "pubg_esp", "pubg_hack", "pubg_cheat",
        "pubg_loader", "pubg_bypass", "pubg_injector",
        "pubg_be_bypass", "battleye_bypass_pubg", "be_bypass_pubg",
        "pubghack", "pubgcheat", "pubgloader", "pubgbypass",
        "bpubg", "tslgame_cheat", "tslgame_hack", "tslgame_loader",
        "pubg_radar", "pubg_radar_server", "pubgradar",
        "pubg_dma", "pubg_memory", "pubg_silentaim",
        "pubg_triggerbot", "pubg_no_recoil", "pubg_norecoil",
        "pubg_wallhack", "pubg_wh", "pubg_spoofer",
        "pubg_unlocker", "gameloop_cheat", "txgame_cheat",
        "pubgm_cheat", "pubglite_hack", "bgmi_hack",
    };

    // -------------------------------------------------------------------------
    // MUICache keywords for PUBG cheats
    // -------------------------------------------------------------------------

    private static readonly string[] MuiCacheKeywords =
    {
        "pubg_aimbot", "pubg_esp", "pubg_hack", "pubg_cheat",
        "pubg_loader", "pubg_bypass", "pubg_injector",
        "pubg_be_bypass", "battleye_bypass_pubg", "be_bypass_pubg",
        "pubghack", "pubgcheat", "pubgloader", "pubgbypass",
        "bpubg", "tslgame_cheat", "tslgame_hack", "tslgame_loader",
        "pubg_radar", "pubg_radar_server", "pubgradar",
        "pubg_dma", "pubg_memory", "pubg_silentaim",
        "pubg_triggerbot", "pubg_no_recoil", "pubg_norecoil",
        "pubg_wallhack", "pubg_wh", "pubg_spoofer", "pubg_unlocker",
        "gameloop_cheat", "txgame_cheat", "pubgm_cheat",
        "pubg_vehicle_esp", "pubg_loot_esp", "pubg_player_esp",
    };

    // -------------------------------------------------------------------------
    // Temp folder PUBG cheat artifact file names
    // -------------------------------------------------------------------------

    private static readonly string[] TempCheatArtifactNames =
    {
        "pubg_cheat.log", "pubg_hack.log", "pubg_aimbot.log",
        "pubg_esp.log", "pubg_bypass.log", "pubg_loader.log",
        "pubg_radar.log", "pubg_dma.log", "pubg_memory.log",
        "pubg_cheat_dump.txt", "pubg_cheat_log.txt",
        "pubg_offsets_dump.txt", "pubg_crash.log",
        "be_bypass.log", "battleye_bypass.log",
        "pubg_be_bypass.log", "be_bypass_pubg.log",
        "tslgame_cheat.log", "tslgame_hack.log",
        "pubg_radar_server.log", "pubgradar.log",
        "gameloop_cheat.log", "txgame_cheat.log",
        "pubgm_cheat.log", "bgmi_hack.log",
        "pubg_settings_backup.json", "pubg_config_backup.json",
        "pubg_cheat_config.json", "pubg_aimbot_config.json",
        "pubg_esp_config.json", "pubg_trigger_config.json",
        "pubg_recoil_config.json", "pubg_radar_config.json",
        "pubg_loot_config.json", "pubg_filter_config.json",
        "pubg_cheat_settings.json",
    };

    // -------------------------------------------------------------------------
    // Known BattlEye log tampering indicators
    // -------------------------------------------------------------------------

    private static readonly string[] BattleEyeLogTamperKeywords =
    {
        "bypass", "patch", "hook", "disabled", "spoofed",
        "injected", "modified", "tampered", "cleaned",
        "cleared", "deleted", "removed", "fake",
        "be_bypass", "battleye_bypass", "anti_detect",
        "evasion", "cheat_loader", "memory_patch",
    };

    // -------------------------------------------------------------------------
    // Steam path helpers
    // -------------------------------------------------------------------------

    private static string? GetSteamInstallPath()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam")
                         ?? Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Valve\Steam");
            return key?.GetValue("InstallPath") as string;
        }
        catch { return null; }
    }

    private static IEnumerable<string> GetPubgInstallPaths()
    {
        var paths = new List<string>
        {
            @"C:\Program Files (x86)\Steam\steamapps\common\PUBG",
            @"C:\Program Files\Steam\steamapps\common\PUBG",
            @"D:\Steam\steamapps\common\PUBG",
            @"D:\SteamLibrary\steamapps\common\PUBG",
            @"E:\Steam\steamapps\common\PUBG",
            @"E:\SteamLibrary\steamapps\common\PUBG",
            @"F:\SteamLibrary\steamapps\common\PUBG",
            @"G:\SteamLibrary\steamapps\common\PUBG",
        };
        var steamPath = GetSteamInstallPath();
        if (!string.IsNullOrEmpty(steamPath))
            paths.Add(Path.Combine(steamPath, "steamapps", "common", "PUBG"));
        return paths.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    // -------------------------------------------------------------------------
    // IScanModule.RunAsync
    // -------------------------------------------------------------------------

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting PUBG cheat deep forensic scan");

        await Task.WhenAll(
            CheckKnownCheatExecutables(ctx, ct),
            CheckBattleEyeBypassArtifacts(ctx, ct),
            CheckEmulatorCheatArtifacts(ctx, ct),
            CheckRadarHackArtifacts(ctx, ct),
            CheckOffsetAndPatternFiles(ctx, ct),
            CheckPubgConfigFiles(ctx, ct),
            CheckBattleEyeLogTampering(ctx, ct),
            CheckTempFolderArtifacts(ctx, ct),
            CheckRegistryRunKeys(ctx, ct),
            CheckUserAssistArtifacts(ctx, ct),
            CheckMuiCacheArtifacts(ctx, ct),
            CheckDownloadsFolderArtifacts(ctx, ct),
            CheckPubgAppDataArtifacts(ctx, ct),
            CheckTxGameAssistantArtifacts(ctx, ct),
            CheckPubgGameDirectoryArtifacts(ctx, ct)
        );

        ctx.Report(1.0, Name, "PUBG cheat deep forensic scan complete");
    }

    // -------------------------------------------------------------------------
    // Check 1: Known PUBG cheat executables and DLLs
    // -------------------------------------------------------------------------

    private Task CheckKnownCheatExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.02, Name, "Scanning for known PUBG cheat executables");

            var searchBases = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PUBG"),
            };

            foreach (var pubgPath in GetPubgInstallPaths())
                searchBases.Add(pubgPath);

            foreach (var baseDir in searchBases)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(baseDir)) continue;

                string[] files;
                try { files = Directory.GetFiles(baseDir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (!KnownCheatExecutables.Contains(fn)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG Cheat Executable Found: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"The file '{fn}' is a known PlayerUnknown's Battlegrounds cheat executable " +
                                 "or DLL artifact. This binary is associated with aimbot, ESP, wallhack, " +
                                 "radar, or no-recoil functionality for PUBG. Its presence on disk is a " +
                                 "direct forensic artifact of cheat tool acquisition or usage.",
                        Detail = $"Path: {file}"
                    });
                }
            }

            // Recursive scan in PUBG install paths
            foreach (var pubgRoot in GetPubgInstallPaths())
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(pubgRoot)) continue;

                IEnumerable<string> allFiles;
                try { allFiles = Directory.EnumerateFiles(pubgRoot, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in allFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (!KnownCheatExecutables.Contains(fn)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG Cheat Binary in Game Directory: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known PUBG cheat binary '{fn}' was found inside the PUBG game directory. " +
                                 "Cheats placed within the game installation tree are either loaded at " +
                                 "runtime via DLL hijacking or injected via a separate loader process. " +
                                 "This is a high-confidence forensic indicator of active cheat tool deployment.",
                        Detail = $"PUBG install: {pubgRoot} | File: {file}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 2: BattlEye bypass artifacts for PUBG
    // -------------------------------------------------------------------------

    private Task CheckBattleEyeBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.07, Name, "Scanning for BattlEye bypass artifacts");

            var searchBases = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow"),
            };

            foreach (var pubgPath in GetPubgInstallPaths())
                searchBases.Add(pubgPath);

            foreach (var baseDir in searchBases)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(baseDir)) continue;

                string[] files;
                try { files = Directory.GetFiles(baseDir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (!BattleEyeBypassArtifacts.Contains(fn)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG BattlEye Bypass Artifact Found: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"The file '{fn}' is a known BattlEye bypass artifact for PUBG. " +
                                 "BattlEye bypass tools neutralize PUBG's anti-cheat service to prevent " +
                                 "it from detecting injected cheat DLLs, memory manipulation, or process " +
                                 "hooking. The presence of BattlEye bypass tools is a critical forensic " +
                                 "indicator of deliberate anti-cheat evasion.",
                        Detail = $"Path: {file}"
                    });
                }
            }

            // Specifically check the PUBG BattlEye directory for unauthorized files
            foreach (var pubgRoot in GetPubgInstallPaths())
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(pubgRoot)) continue;

                var beDir = Path.Combine(pubgRoot, "TslGame", "Binaries", "Win64", "BattlEye");
                if (!Directory.Exists(beDir)) continue;

                string[] beFiles;
                try { beFiles = Directory.GetFiles(beDir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in beFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (BattleEyeBypassArtifacts.Contains(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"BattlEye Bypass DLL in PUBG BattlEye Directory: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"A known BattlEye bypass DLL '{fn}' was found inside the PUBG BattlEye " +
                                     "directory. Placing bypass DLLs in the BattlEye folder is a technique " +
                                     "for neutralizing the anti-cheat before it initializes, as BattlEye " +
                                     "loads these files early in the game launch sequence.",
                            Detail = $"BattlEye dir: {beDir} | File: {file}"
                        });
                    }
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 3: PUBG emulator (GameLoop/TxGameAssistant) cheat artifacts
    // -------------------------------------------------------------------------

    private Task CheckEmulatorCheatArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.12, Name, "Scanning for GameLoop/TxGameAssistant cheat artifacts");

            var txGamePaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TxGameAssistant"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GameLoop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Tencent", "GameLoop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "TxGameAssistant"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "GameLoop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "TxGameAssistant"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "GameLoop"),
                @"C:\Program Files (x86)\TxGameAssistant",
                @"C:\Program Files (x86)\GameLoop",
                @"C:\TxGameAssistant",
                @"C:\GameLoop",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            };

            foreach (var baseDir in txGamePaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(baseDir)) continue;

                string[] files;
                try { files = Directory.GetFiles(baseDir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (!EmulatorCheatArtifacts.Contains(fn)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG Mobile Emulator Cheat Artifact: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"The file '{fn}' is a known cheat tool artifact for PUBG Mobile running " +
                                 "on the GameLoop/TxGameAssistant Android emulator. These cheats bypass " +
                                 "the emulator's anti-cheat detection and provide aimbot, ESP, and " +
                                 "Tencent security bypass functionality for PUBG Mobile.",
                        Detail = $"Path: {file}"
                    });
                }
            }

            // Also scan Downloads and Desktop for emulator cheat files
            foreach (var dir in new[] {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop) })
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (!EmulatorCheatArtifacts.Contains(fn)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG Emulator Cheat Tool in User Folder: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"A PUBG Mobile emulator cheat tool '{fn}' was found in the user's " +
                                 "Downloads or Desktop directory. This indicates the cheat was recently " +
                                 "downloaded or is staged for use against PUBG Mobile on the emulator.",
                        Detail = $"Directory: {dir} | File: {file}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 4: PUBG radar hack relay scripts
    // -------------------------------------------------------------------------

    private Task CheckRadarHackArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.18, Name, "Scanning for PUBG radar hack relay scripts");

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Scripts"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "radar"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "pubg_radar"),
                Path.GetTempPath(),
            };

            foreach (var baseDir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(baseDir)) continue;

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(baseDir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    // Check for known radar file names
                    if (RadarHackArtifacts.Contains(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"PUBG Radar Hack Script Found: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"The file '{fn}' is a known PUBG radar hack relay script. " +
                                     "PUBG radar hacks work by reading game memory to extract player " +
                                     "positions, then relaying the data via WebSocket to a browser-based " +
                                     "radar displayed on a second screen or phone. This gives the cheater " +
                                     "a real-time map of all player positions without in-game ESP that " +
                                     "could be detected by screen captures.",
                            Detail = $"File: {file}"
                        });
                        continue;
                    }

                    // Check Python and HTML files for PUBG radar content
                    var ext = Path.GetExtension(fn).ToLowerInvariant();
                    if (ext is not (".py" or ".html" or ".js" or ".htm")) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    var radarKeywords = new[]
                    {
                        "pubg", "tslgame", "battlegrounds",
                        "websocket", "WebSocket", "ws.send",
                        "radar", "minimap", "playerpos",
                        "player_position", "entity_list", "actor_list",
                        "GWorld", "GNames", "ULevel",
                        "TslCharacter", "TslPlayerController",
                        "ReadProcessMemory", "OpenProcess",
                        "memory_read", "mem.read",
                    };

                    // Require at least 2 different radar keywords to reduce false positives
                    int matchCount = 0;
                    var matchedKws = new List<string>();
                    foreach (var kw in radarKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            matchCount++;
                            matchedKws.Add(kw);
                            if (matchCount >= 2) break;
                        }
                    }

                    if (matchCount < 2) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG Radar Hack Script (Content Match): {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"The script '{fn}' contains multiple keywords associated with a PUBG radar " +
                                 "hack relay implementation. It references PUBG-specific memory structures " +
                                 "and WebSocket/radar communication patterns used by external radar tools " +
                                 "that relay player positions to a second-screen display.",
                        Detail = $"Matched keywords: {string.Join(", ", matchedKws)} | File: {file}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 5: PUBG offset and memory pattern files
    // -------------------------------------------------------------------------

    private Task CheckOffsetAndPatternFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.24, Name, "Scanning for PUBG offset/address/pattern files");

            var searchDirs = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.GetTempPath(),
            };

            foreach (var pubgPath in GetPubgInstallPaths())
                searchDirs.Add(pubgPath);

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (!OffsetAndPatternFiles.Contains(fn)) continue;

                    // Read the file to confirm it contains PUBG Unreal Engine structure references
                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    bool hasPubgContent = Tf2OffsetKeywords.Any(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG External Cheat Offset File: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"The file '{fn}' appears to be a PUBG cheat offset, address, or pattern file. " +
                                 "External PUBG cheats read these files to locate memory offsets for game " +
                                 "objects including player positions, health values, weapon data, and bone " +
                                 "matrices. Offset files are updated with each PUBG game update and are a " +
                                 "key component of external aimbot and ESP implementations." +
                                 (hasPubgContent ? " File content contains PUBG Unreal Engine structure references." : ""),
                        Detail = $"File: {file}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 6: PUBG config.ini and settings files for cheat keywords
    // -------------------------------------------------------------------------

    private Task CheckPubgConfigFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.30, Name, "Scanning PUBG config files for cheat settings");

            // PUBG stores user config in %LOCALAPPDATA%\TslGame\Saved\Config\WindowsNoEditor\
            var pubgConfigDirs = new List<string>
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "TslGame", "Saved", "Config", "WindowsNoEditor"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "TslGame", "Saved", "Config"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PUBG"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PUBG"),
            };

            foreach (var pubgRoot in GetPubgInstallPaths())
            {
                pubgConfigDirs.Add(Path.Combine(pubgRoot, "TslGame", "Saved", "Config"));
                pubgConfigDirs.Add(Path.Combine(pubgRoot, "config"));
            }

            var configFileExtensions = new[] { ".ini", ".cfg", ".json", ".txt", ".yaml", ".xml" };

            foreach (var configDir in pubgConfigDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(configDir)) continue;

                string[] configFiles;
                try { configFiles = Directory.GetFiles(configDir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in configFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    if (!configFileExtensions.Contains(ext)) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    var foundKeywords = new List<string>();
                    foreach (var kw in ConfigCheatKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            foundKeywords.Add(kw);
                    }

                    if (foundKeywords.Count == 0) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG Config File Contains Cheat Settings: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"The PUBG configuration file '{Path.GetFileName(file)}' contains settings " +
                                 "associated with cheat functionality. Cheat tools modify or create PUBG " +
                                 "config files to store their settings including aimbot parameters, ESP " +
                                 "configuration, recoil control profiles, BattlEye bypass options, and " +
                                 "radar relay server addresses.",
                        Detail = $"Matched keywords: {string.Join(", ", foundKeywords)} | File: {file}"
                    });
                }
            }

            // Also check the cheat-specific config files by name in common locations
            var generalSearchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
            };

            foreach (var dir in generalSearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] dirFiles;
                try { dirFiles = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in dirFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (!OffsetAndPatternFiles.Contains(fn)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG Cheat Config File Found: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"A known PUBG cheat configuration file '{fn}' was found. Cheat tools use " +
                                 "these files to persist settings across sessions including aimbot smoothing, " +
                                 "ESP toggle keys, recoil profiles, and BattlEye bypass parameters.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 7: BattlEye log tampering in PUBG installation
    // -------------------------------------------------------------------------

    private Task CheckBattleEyeLogTampering(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.36, Name, "Checking BattlEye log integrity in PUBG installation");

            foreach (var pubgRoot in GetPubgInstallPaths())
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(pubgRoot)) continue;

                // Known BattlEye log directory locations in PUBG
                var beDirs = new[]
                {
                    Path.Combine(pubgRoot, "TslGame", "Binaries", "Win64", "BattlEye"),
                    Path.Combine(pubgRoot, "TslGame", "Saved", "BattlEye"),
                    Path.Combine(pubgRoot, "BattlEye"),
                };

                foreach (var beDir in beDirs)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(beDir)) continue;

                    string[] beFiles;
                    try { beFiles = Directory.GetFiles(beDir, "*", SearchOption.TopDirectoryOnly); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    bool hasBeLauncherExe = false;
                    bool hasBeClientDll = false;
                    bool hasBeServiceExe = false;
                    bool hasUnexpectedFiles = false;
                    var unexpectedFiles = new List<string>();

                    foreach (var file in beFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file).ToLowerInvariant();

                        // Track expected BattlEye files
                        if (fn.Equals("belauncher.exe", StringComparison.OrdinalIgnoreCase)) hasBeLauncherExe = true;
                        else if (fn.Equals("beclient.dll", StringComparison.OrdinalIgnoreCase)) hasBeClientDll = true;
                        else if (fn.Equals("beservice.exe", StringComparison.OrdinalIgnoreCase)
                              || fn.Equals("beservice_x64.exe", StringComparison.OrdinalIgnoreCase)) hasBeServiceExe = true;
                        else if (fn.Equals("beclient_x64.dll", StringComparison.OrdinalIgnoreCase)) hasBeClientDll = true;
                        else
                        {
                            // Non-standard files in BattlEye directory are suspicious
                            var ext = Path.GetExtension(fn).ToLowerInvariant();
                            if (ext is ".dll" or ".exe" or ".sys")
                            {
                                hasUnexpectedFiles = true;
                                unexpectedFiles.Add(Path.GetFileName(file));
                            }
                        }

                        // Scan .txt and .log files in BattlEye directory for tamper indicators
                        if (fn.EndsWith(".log", StringComparison.OrdinalIgnoreCase)
                         || fn.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                        {
                            string logContent;
                            try
                            {
                                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                logContent = await sr.ReadToEndAsync(ct);
                            }
                            catch (IOException) { continue; }
                            catch (UnauthorizedAccessException) { continue; }

                            foreach (var kw in BattleEyeLogTamperKeywords)
                            {
                                if (!logContent.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Suspicious Content in BattlEye Log: {Path.GetFileName(file)}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"The BattlEye log/text file '{Path.GetFileName(file)}' contains " +
                                             $"the keyword '{kw}', which is associated with BattlEye bypass " +
                                             "or tampering activity. Cheat tools may write bypass status, " +
                                             "patch confirmation, or hook installation notes to log files " +
                                             "in the BattlEye directory.",
                                    Detail = $"Keyword: {kw} | BattlEye dir: {beDir} | File: {file}"
                                });
                                break;
                            }
                        }
                    }

                    if (hasUnexpectedFiles)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Unexpected Executables in PUBG BattlEye Directory",
                            Risk = RiskLevel.High,
                            Location = beDir,
                            Reason = "The PUBG BattlEye directory contains executable files that are not " +
                                     "part of the standard BattlEye installation. Unknown DLLs or EXEs " +
                                     "in the BattlEye directory may be bypass tools, hooks, or emulator " +
                                     "DLLs placed there to intercept or neutralize anti-cheat operations.",
                            Detail = $"Unexpected files: {string.Join(", ", unexpectedFiles)} | Directory: {beDir}"
                        });
                    }

                    // A PUBG BattlEye directory that's missing its core files is also suspicious
                    if (!hasBeLauncherExe || !hasBeClientDll)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "PUBG BattlEye Core Files Missing",
                            Risk = RiskLevel.Medium,
                            Location = beDir,
                            Reason = "The PUBG BattlEye directory is missing one or more core BattlEye files " +
                                     "(BELauncher.exe, BEClient.dll). Missing BattlEye components may indicate " +
                                     "they were deleted by a bypass tool to prevent the anti-cheat from loading, " +
                                     "or replaced with non-functional stub versions.",
                            Detail = $"BELauncher.exe present: {hasBeLauncherExe} | " +
                                     $"BEClient.dll present: {hasBeClientDll} | " +
                                     $"BEService.exe present: {hasBeServiceExe} | " +
                                     $"Directory: {beDir}"
                        });
                    }
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 8: Temp folder PUBG cheat artifacts
    // -------------------------------------------------------------------------

    private Task CheckTempFolderArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.43, Name, "Scanning temp folders for PUBG cheat logs and configs");

            var tempDirs = new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            };

            foreach (var tempDir in tempDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tempDir)) continue;

                string[] files;
                try { files = Directory.GetFiles(tempDir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    bool isCheatArtifact = TempCheatArtifactNames.Any(a =>
                        fn.Equals(a, StringComparison.OrdinalIgnoreCase));

                    if (!isCheatArtifact) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG Cheat Artifact in Temp Directory: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"A PUBG cheat-associated file '{fn}' was found in the system temp directory. " +
                                 "Cheat tools write log files, crash dumps, configuration caches, offset dumps, " +
                                 "and BattlEye bypass status files to temp directories. These artifacts persist " +
                                 "after the cheat executables have been removed.",
                        Detail = $"Temp dir: {tempDir} | File: {file}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 9: Registry Run keys for PUBG cheat persistence
    // -------------------------------------------------------------------------

    private Task CheckRegistryRunKeys(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.49, Name, "Scanning registry Run keys for PUBG cheat loaders");

            var runKeyPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            };

            foreach (var keyPath in runKeyPaths)
            {
                if (ct.IsCancellationRequested) return;

                // HKCU
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(keyPath, writable: false);
                    if (key != null)
                    {
                        ctx.IncrementRegistryKeys();
                        ScanRunKeyForPubgCheats(ctx, key, $@"HKCU\{keyPath}");
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }

                if (ct.IsCancellationRequested) return;

                // HKLM
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                    if (key != null)
                    {
                        ctx.IncrementRegistryKeys();
                        ScanRunKeyForPubgCheats(ctx, key, $@"HKLM\{keyPath}");
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    private void ScanRunKeyForPubgCheats(ScanContext ctx, RegistryKey key, string displayPath)
    {
        string[] valueNames;
        try { valueNames = key.GetValueNames(); }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }

        foreach (var valueName in valueNames)
        {
            ctx.IncrementRegistryKeys();

            string? valueData;
            try { valueData = key.GetValue(valueName) as string; }
            catch (IOException) { continue; }
            if (string.IsNullOrWhiteSpace(valueData)) continue;

            var searchText = $"{valueName} {valueData}";

            foreach (var kw in RegistryRunKeywords)
            {
                if (!searchText.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"PUBG Cheat Loader in Registry Run Key: {valueName}",
                    Risk = RiskLevel.Critical,
                    Location = displayPath,
                    FileName = Path.GetFileName(valueData.Trim('"')),
                    Reason = $"A registry Run key entry '{valueName}' with value '{valueData}' contains " +
                             $"the PUBG cheat-related keyword '{kw}'. Run keys cause programs to execute " +
                             "automatically at Windows startup. PUBG cheat loaders use this to ensure " +
                             "the cheat is injected into PUBG every time the game launches.",
                    Detail = $"Key: {displayPath} | Value name: {valueName} | Data: {valueData} | Keyword: {kw}"
                });
                break;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Check 10: UserAssist registry for PUBG cheat EXE execution history
    // -------------------------------------------------------------------------

    private Task CheckUserAssistArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.55, Name, "Scanning UserAssist registry for PUBG cheat execution history");

            const string userAssistRoot =
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

            try
            {
                using var uaRoot = Registry.CurrentUser.OpenSubKey(userAssistRoot, writable: false);
                if (uaRoot is null) return;

                ctx.IncrementRegistryKeys();

                string[] guidNames;
                try { guidNames = uaRoot.GetSubKeyNames(); }
                catch (IOException) { return; }
                catch (UnauthorizedAccessException) { return; }

                foreach (var guidName in guidNames)
                {
                    if (ct.IsCancellationRequested) return;

                    try
                    {
                        using var guidKey = uaRoot.OpenSubKey(guidName, writable: false);
                        if (guidKey is null) continue;

                        using var countKey = guidKey.OpenSubKey("Count", writable: false);
                        if (countKey is null) continue;

                        ctx.IncrementRegistryKeys();

                        string[] valueNames;
                        try { valueNames = countKey.GetValueNames(); }
                        catch (IOException) { continue; }
                        catch (UnauthorizedAccessException) { continue; }

                        foreach (var encodedName in valueNames)
                        {
                            if (string.IsNullOrWhiteSpace(encodedName)) continue;
                            ctx.IncrementRegistryKeys();

                            var decoded = Rot13Decode(encodedName);
                            if (string.IsNullOrWhiteSpace(decoded)) continue;

                            bool isCheat = RegistryRunKeywords.Any(kw =>
                                decoded.Contains(kw, StringComparison.OrdinalIgnoreCase));
                            if (!isCheat) continue;

                            string matchedKw = RegistryRunKeywords.First(kw =>
                                decoded.Contains(kw, StringComparison.OrdinalIgnoreCase));

                            string runCountNote = string.Empty;
                            try
                            {
                                byte[]? valData = countKey.GetValue(
                                    encodedName, null,
                                    RegistryValueOptions.DoNotExpandEnvironmentNames) as byte[];
                                if (valData != null && valData.Length >= 8)
                                {
                                    int runCount = BitConverter.ToInt32(valData, 4);
                                    runCountNote = $" | Run count: {runCount}";
                                    if (valData.Length >= 16)
                                    {
                                        try
                                        {
                                            long fileTime = BitConverter.ToInt64(valData, 8);
                                            if (fileTime > 0)
                                            {
                                                var lastRun = DateTime.FromFileTimeUtc(fileTime);
                                                runCountNote += $" | Last run: {lastRun:yyyy-MM-dd HH:mm:ss} UTC";
                                            }
                                        }
                                        catch { }
                                    }
                                }
                            }
                            catch (IOException) { }

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"UserAssist: PUBG Cheat Program Executed — {Path.GetFileName(decoded)}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{userAssistRoot}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"Windows UserAssist records that '{decoded}' was launched via the GUI. " +
                                         $"The decoded path matches the PUBG cheat keyword '{matchedKw}'. " +
                                         "UserAssist entries include a run counter and last-run timestamp, " +
                                         "and persist in the registry after the cheat executable is deleted.",
                                Detail = $"ROT13: {encodedName} | Decoded: {decoded}{runCountNote}"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 11: MUICache registry for PUBG cheat program execution history
    // -------------------------------------------------------------------------

    private Task CheckMuiCacheArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.60, Name, "Scanning MUICache registry for PUBG cheat program history");

            const string muiCacheKey =
                @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
            const string muiCacheKeyAlt =
                @"SOFTWARE\Microsoft\Windows\ShellNoRoam\MUICache";

            var keys = new[] { muiCacheKey, muiCacheKeyAlt };

            foreach (var keyPath in keys)
            {
                if (ct.IsCancellationRequested) return;

                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    ctx.IncrementRegistryKeys();

                    string[] valueNames;
                    try { valueNames = key.GetValueNames(); }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var valueName in valueNames)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        if (string.IsNullOrWhiteSpace(valueName)) continue;

                        var exePath = valueName;
                        if (exePath.EndsWith(".FriendlyAppName", StringComparison.OrdinalIgnoreCase))
                            exePath = exePath[..^".FriendlyAppName".Length];

                        bool isCheat = MuiCacheKeywords.Any(kw =>
                            exePath.Contains(kw, StringComparison.OrdinalIgnoreCase));
                        if (!isCheat) continue;

                        string matchedKw = MuiCacheKeywords.First(kw =>
                            exePath.Contains(kw, StringComparison.OrdinalIgnoreCase));

                        string? friendlyName;
                        try { friendlyName = key.GetValue(valueName) as string; }
                        catch (IOException) { friendlyName = null; }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"MUICache: PUBG Cheat Program Previously Run — {Path.GetFileName(exePath)}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{keyPath}",
                            FileName = Path.GetFileName(exePath),
                            Reason = $"The Windows MUICache registry contains an entry for '{exePath}', " +
                                     $"which matches the PUBG cheat keyword '{matchedKw}'. MUICache is " +
                                     "populated the first time any GUI application runs and persists after " +
                                     "the program is deleted. It is a reliable forensic artifact of cheat " +
                                     "execution history.",
                            Detail = $"Key: {keyPath} | Entry: {valueName} | Friendly name: {friendlyName ?? "(none)"} | Keyword: {matchedKw}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 12: Downloads folder for PUBG cheat artifacts
    // -------------------------------------------------------------------------

    private Task CheckDownloadsFolderArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.65, Name, "Scanning Downloads folder for PUBG cheat artifacts");

            var downloadsDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            if (!Directory.Exists(downloadsDir)) return;

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(downloadsDir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);
                var fnLower = fn.ToLowerInvariant();

                if (KnownCheatExecutables.Contains(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG Cheat Executable in Downloads: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"The known PUBG cheat binary '{fn}' was found in the Downloads folder. " +
                                 "Downloaded PUBG cheat tools indicate active acquisition of cheating " +
                                 "software for PlayerUnknown's Battlegrounds.",
                        Detail = $"Downloads: {downloadsDir} | File: {file}"
                    });
                    continue;
                }

                if (BattleEyeBypassArtifacts.Contains(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG BattlEye Bypass Tool in Downloads: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"A known BattlEye bypass tool '{fn}' for PUBG was found in the Downloads " +
                                 "folder. This tool is designed to circumvent PUBG's BattlEye anti-cheat service.",
                        Detail = $"Downloads: {downloadsDir} | File: {file}"
                    });
                    continue;
                }

                if (RadarHackArtifacts.Contains(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG Radar Hack Script in Downloads: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"A known PUBG radar hack relay script '{fn}' was found in the Downloads " +
                                 "folder. This script implements or supports a real-time radar that displays " +
                                 "all player positions on a map without in-game overlays.",
                        Detail = $"Downloads: {downloadsDir} | File: {file}"
                    });
                    continue;
                }

                // Flag archives with PUBG cheat names
                var ext = Path.GetExtension(fnLower);
                if (ext is ".zip" or ".rar" or ".7z" or ".tar" or ".gz")
                {
                    bool archiveNameIsCheat = RegistryRunKeywords.Any(kw =>
                        fnLower.Contains(kw, StringComparison.OrdinalIgnoreCase));
                    if (archiveNameIsCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"PUBG Cheat Archive in Downloads: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"A downloaded archive '{fn}' with a PUBG cheat-related name was found " +
                                     "in the Downloads folder. PUBG cheat tools are commonly distributed as " +
                                     "compressed archives containing the loader, DLL, and configuration files.",
                            Detail = $"Downloads: {downloadsDir} | File: {file}"
                        });
                    }
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 13: AppData for PUBG cheat configuration persistence
    // -------------------------------------------------------------------------

    private Task CheckPubgAppDataArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.71, Name, "Scanning AppData for PUBG cheat configuration artifacts");

            var appDataDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PUBG"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PUBG"),
            };

            // Known PUBG cheat AppData subdirectory names
            var cheatSubFolders = new[]
            {
                "pubg_aimbot", "pubg_esp", "pubg_hack", "pubg_cheat",
                "pubg_loader", "pubg_bypass", "pubg_radar",
                "pubg_be_bypass", "be_bypass_pubg", "battleye_bypass_pubg",
                "pubghack", "pubgcheat", "pubgradar",
                "bpubg", "tslgame_cheat", "pubg_dma",
                "pubg_memory", "pubg_silentaim", "pubg_triggerbot",
                "pubg_norecoil", "pubg_wallhack", "pubg_spoofer",
                "pubg_loot_esp", "pubg_player_esp", "pubg_vehicle_esp",
                "pubg_mobile_hack", "pubgm_cheat", "pubglite_hack",
                "gameloop_cheat", "txgame_cheat", "bgmi_hack",
            };

            foreach (var appDataDir in appDataDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(appDataDir)) continue;

                foreach (var subFolder in cheatSubFolders)
                {
                    if (ct.IsCancellationRequested) return;
                    var cheatDir = Path.Combine(appDataDir, subFolder);
                    if (!Directory.Exists(cheatDir)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PUBG Cheat Tool AppData Directory Found: {subFolder}",
                        Risk = RiskLevel.High,
                        Location = cheatDir,
                        FileName = subFolder,
                        Reason = $"A directory named '{subFolder}' associated with a PUBG cheat tool was " +
                                 "found in AppData. PUBG cheat tools create these directories to store " +
                                 "persistent configuration, license keys, session logs, BattlEye bypass " +
                                 "status, and offset caches. The directory's presence persists after the " +
                                 "main cheat executable has been deleted.",
                        Detail = $"Cheat AppData directory: {cheatDir}"
                    });

                    // Enumerate files inside the cheat's AppData folder
                    string[] cheatFiles;
                    try { cheatFiles = Directory.GetFiles(cheatDir, "*", SearchOption.AllDirectories); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in cheatFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        var ext = Path.GetExtension(fn).ToLowerInvariant();

                        if (ext is ".log" or ".cfg" or ".json" or ".txt" or ".ini" or ".xml" or ".yaml")
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"PUBG Cheat Configuration/Log File: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"A configuration or log file '{fn}' was found inside the PUBG cheat " +
                                         $"tool directory '{subFolder}'. This is a forensic artifact of the " +
                                         "cheat having been configured and run on this system.",
                                Detail = $"Cheat folder: {cheatDir} | File: {file}"
                            });
                        }
                    }
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 14: TxGameAssistant / GameLoop emulator directory artifacts
    // -------------------------------------------------------------------------

    private Task CheckTxGameAssistantArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.77, Name, "Scanning TxGameAssistant/GameLoop directories for cheat artifacts");

            var txGameRoots = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TxGameAssistant"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GameLoop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Tencent", "GameLoop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "TxGameAssistant"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "GameLoop"),
                @"C:\Program Files (x86)\TxGameAssistant",
                @"C:\Program Files (x86)\GameLoop",
                @"C:\TxGameAssistant",
                @"C:\GameLoop",
            };

            // Cheat-indicative keywords for files found inside the emulator directories
            var emulatorCheatFileKeywords = new[]
            {
                "aimbot", "esp", "wallhack", "cheat", "hack", "bypass",
                "be_bypass", "battleye", "txprotect_bypass", "tprt_bypass",
                "radar", "norecoil", "silentaim", "triggerbot",
                "speedhack", "bhop", "godmode", "teleport",
                "nospread", "norecoil", "autoheal", "autoloot",
                "spoofer", "hwid", "ban_bypass",
            };

            foreach (var txRoot in txGameRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(txRoot)) continue;

                IEnumerable<string> txFiles;
                try { txFiles = Directory.EnumerateFiles(txRoot, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in txFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var fnLower = fn.ToLowerInvariant();

                    // Check for known emulator cheat executables
                    if (EmulatorCheatArtifacts.Contains(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"PUBG Emulator Cheat in GameLoop Directory: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"A known PUBG Mobile emulator cheat tool '{fn}' was found inside the " +
                                     "TxGameAssistant/GameLoop emulator directory. This indicates the cheat " +
                                     "was actively deployed against PUBG Mobile running on the emulator.",
                            Detail = $"Emulator dir: {txRoot} | File: {file}"
                        });
                        continue;
                    }

                    // Check filenames with cheat keywords
                    bool nameHit = emulatorCheatFileKeywords.Any(kw =>
                        fnLower.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    var ext = Path.GetExtension(fnLower);
                    if (!nameHit || ext is not (".exe" or ".dll" or ".py" or ".json" or ".cfg" or ".txt"))
                        continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious Cheat-Named File in GameLoop Directory: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"A file named '{fn}' with a cheat-related keyword was found inside the " +
                                 "TxGameAssistant/GameLoop emulator directory. Files with aimbot, ESP, " +
                                 "bypass, or hack keywords placed inside the emulator directory may be " +
                                 "cheat components configured to run within the emulator environment.",
                        Detail = $"Emulator dir: {txRoot} | File: {file}"
                    });
                }
            }

            // Registry check for TxGameAssistant bypass tools
            try
            {
                using var txKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\WOW6432Node\Tencent\TxGameAssistant", writable: false);
                if (txKey != null)
                {
                    ctx.IncrementRegistryKeys();
                    var installPath = txKey.GetValue("InstallPath") as string;
                    if (!string.IsNullOrEmpty(installPath))
                    {
                        // TxGameAssistant is installed — check its protection status values
                        var protectionValue = txKey.GetValue("ProtectionEnabled") as string
                                           ?? txKey.GetValue("AntiCheatEnabled") as string;
                        if (protectionValue != null &&
                            (protectionValue.Equals("0", StringComparison.Ordinal)
                          || protectionValue.Equals("false", StringComparison.OrdinalIgnoreCase)
                          || protectionValue.Equals("disabled", StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "TxGameAssistant Anti-Cheat Protection Disabled in Registry",
                                Risk = RiskLevel.High,
                                Location = @"HKLM\SOFTWARE\WOW6432Node\Tencent\TxGameAssistant",
                                Reason = "The TxGameAssistant (GameLoop) emulator registry indicates that " +
                                         "anti-cheat or protection features are disabled. Disabling the " +
                                         "emulator's protection layer is a prerequisite for running " +
                                         "PUBG Mobile cheat tools without detection.",
                                Detail = $"InstallPath: {installPath} | Protection value: {protectionValue}"
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 15: PUBG game directory for anomalous files
    // -------------------------------------------------------------------------

    private Task CheckPubgGameDirectoryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.84, Name, "Scanning PUBG game directory for anomalous cheat artifacts");

            // UE4 DLLs that cheats commonly proxy in the PUBG game directory
            var suspiciousProxyDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "d3d11.dll", "d3d12.dll", "dxgi.dll", "d3d9.dll",
                "opengl32.dll", "xinput1_3.dll", "xinput1_4.dll",
                "xinput9_1_0.dll", "dinput8.dll", "dinput.dll",
                "version.dll", "winmm.dll", "dbghelp.dll",
                "steam_api64.dll", "steam_api.dll",
                "steamclient.dll", "steamclient64.dll",
                "tier0.dll", "vstdlib.dll",
            };

            // Files that should NOT normally appear in PUBG game directories
            var forbiddenFileKeywords = new[]
            {
                "aimbot", "esp", "wallhack", "cheat", "hack", "bypass",
                "be_bypass", "battleye_bypass", "radar", "norecoil",
                "silentaim", "triggerbot", "speedhack", "godmode",
                "pubg_cheat", "pubg_hack", "pubg_loader",
            };

            foreach (var pubgRoot in GetPubgInstallPaths())
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(pubgRoot)) continue;

                // Check the game's main executable directory for proxy DLLs
                var win64Dir = Path.Combine(pubgRoot, "TslGame", "Binaries", "Win64");
                if (Directory.Exists(win64Dir))
                {
                    string[] win64Files;
                    try { win64Files = Directory.GetFiles(win64Dir, "*.dll", SearchOption.TopDirectoryOnly); }
                    catch (UnauthorizedAccessException) { win64Files = Array.Empty<string>(); }
                    catch (IOException) { win64Files = Array.Empty<string>(); }

                    foreach (var file in win64Files)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);

                        if (!suspiciousProxyDlls.Contains(fn)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious Proxy DLL in PUBG Win64 Directory: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"The DLL '{fn}' is present in the PUBG Win64 binary directory. " +
                                     "Cheat tools commonly place proxy DLLs (d3d11.dll, dxgi.dll, " +
                                     "steam_api64.dll, version.dll, etc.) in the game's executable " +
                                     "directory to hook DirectX, Steam API, or system calls for ESP " +
                                     "rendering, aimbot, or BattlEye bypass purposes via DLL hijacking.",
                            Detail = $"Win64 dir: {win64Dir} | Proxy DLL: {file}"
                        });
                    }
                }

                // Scan the entire PUBG directory for files with cheat-related names
                IEnumerable<string> pubgAllFiles;
                try { pubgAllFiles = Directory.EnumerateFiles(pubgRoot, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in pubgAllFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file).ToLowerInvariant();
                    var ext = Path.GetExtension(fn);

                    if (ext is not (".exe" or ".dll" or ".sys" or ".log" or ".json" or ".cfg" or ".txt"))
                        continue;

                    bool nameHit = forbiddenFileKeywords.Any(kw =>
                        fn.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (!nameHit) continue;

                    // Skip if already reported as a known cheat executable
                    if (KnownCheatExecutables.Contains(Path.GetFileName(file))
                     || BattleEyeBypassArtifacts.Contains(Path.GetFileName(file)))
                        continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat-Named File in PUBG Installation: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"A file with a cheat-related name '{Path.GetFileName(file)}' was found " +
                                 "inside the PUBG game installation directory. Files with aimbot, ESP, " +
                                 "hack, bypass, or cheat keywords placed inside the game directory are " +
                                 "strong indicators of cheat tool deployment.",
                        Detail = $"PUBG install: {pubgRoot} | File: {file}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // ROT13 helper for UserAssist decoding
    // -------------------------------------------------------------------------

    private static string Rot13Decode(string s)
    {
        var chars = s.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (c >= 'A' && c <= 'Z') chars[i] = (char)('A' + (c - 'A' + 13) % 26);
            else if (c >= 'a' && c <= 'z') chars[i] = (char)('a' + (c - 'a' + 13) % 26);
        }
        return new string(chars);
    }
}
