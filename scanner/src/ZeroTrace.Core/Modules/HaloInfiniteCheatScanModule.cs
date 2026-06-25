using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

public sealed class HaloInfiniteCheatScanModule : IScanModule
{
    public string Name => "Halo Infinite Cheat Forensic Scan";
    public double Weight => 3.3;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] CheatExecutableNames =
    {
        "halo_cheat.exe",
        "halo_infinite_cheat.exe",
        "halo_aimbot.exe",
        "halo_esp.dll",
        "halo_wh.exe",
        "halocheat.exe",
        "halo_trigger.exe",
        "halo_speed.exe",
        "halo_fly.exe",
        "halo_radar.exe",
        "halo_nofall.exe",
        "halo_wallhack.dll",
        "halo_infinite_hack.exe",
        "halo_infinite_aimbot.exe",
        "halo_infinite_esp.dll",
        "halo_infinite_wh.exe",
        "halo_loader.exe",
        "halo_injector.exe",
        "halo_driver.sys",
        "halo_kmode.sys",
        "halo_bypass.exe",
        "halo_spoofer.exe",
        "halo_unlocker.exe",
        "halo_softaim.exe",
        "halo_silent.exe",
        "halo_legit.exe",
        "halo_rcs.exe",
        "halo_bhop.exe",
        "halo_fov.exe",
        "halo_distance.exe",
        "halo_loot.exe",
        "halo_no_recoil.exe",
        "halo_no_spread.exe",
        "halo_unlock_all.exe",
        "halo_unlock.exe",
        "halo_armor.exe",
        "halo_weapon.exe",
        "halo_super.exe",
        "halo_god.exe",
        "halo_inf_ammo.exe",
        "halo_ammo.exe",
        "halo_menu.exe",
        "halo_gui.exe",
        "halo_internal.dll",
        "halo_external.exe",
        "halo_d3d.dll",
        "halo_dx11.dll",
        "halo_dx12.dll",
        "halo_render.dll",
        "halo_hook.dll",
        "halo_patch.exe",
        "halo_crack.exe",
        "halo_keygen.exe",
        "halotrainer.exe",
        "haloinfinitecheat.exe",
        "haloinfinitehack.exe",
        "haloinfiniteaimbot.exe",
        "haloinfiniteesp.exe",
        "halo_infinite_trainer.exe",
        "halo_infinite_loader.exe",
        "halo_infinite_injector.exe",
        "haloinfinitebypass.exe",
        "halo_rank_hack.exe",
        "halo_csr_hack.exe",
        "halo_xp_hack.exe",
        "halo_challenge_bypass.exe",
        "halo_cosmetic_unlock.exe",
        "halo_battle_pass_hack.exe",
        "halo_infinite_godmode.exe",
        "hi_cheat.exe",
        "hi_aimbot.exe",
        "hi_esp.dll",
        "hi_hack.exe",
        "hi_loader.exe",
    };

    private static readonly string[] EacBypassArtifacts =
    {
        "halo_eac_bypass.dll",
        "eac_halo.exe",
        "easyanticheat_bypass_halo.dll",
        "eac_bypass_halo.exe",
        "halo_eac_loader.exe",
        "halo_anticheat_bypass.dll",
        "easyanticheat_halo.dll",
        "eac_halo_patcher.exe",
        "halo_eac_patcher.exe",
        "halo_eac_hook.dll",
        "eac_hook_halo.dll",
        "halo_eac_spoof.exe",
        "eac_spoof_halo.dll",
        "halo_eac_disable.exe",
        "halo_eac_kill.exe",
        "halo_eac_patch.dat",
        "eac_bypass_loader_halo.exe",
        "halo_cheat_driver.sys",
        "halo_km_bypass.sys",
        "halo_kmode_bypass.sys",
        "halo_infinite_eac_bypass.dll",
        "eac_bypass_halo_infinite.exe",
        "easyanticheat_bypass_haloinfinite.dll",
        "halo_infinite_eac_hook.dll",
        "halo_infinite_anticheat_bypass.dll",
    };

    private static readonly string[] XboxGamePassBypassArtifacts =
    {
        "xbox_gamepass_bypass.exe",
        "gamepass_bypass.dll",
        "xbox_bypass.exe",
        "gamepass_crack.exe",
        "xbox_live_bypass.dll",
        "xbl_bypass.exe",
        "xbox_token_stealer.exe",
        "ms_store_bypass.exe",
        "microsoft_store_bypass.exe",
        "uwp_bypass_halo.exe",
        "appx_bypass_halo.exe",
        "halo_gamepass_bypass.exe",
        "halo_xbox_bypass.exe",
        "halo_ms_bypass.exe",
        "halo_uwp_bypass.dll",
        "halo_infinite_gamepass_bypass.exe",
        "halo_infinite_xbox_bypass.dll",
        "xgp_bypass_halo.exe",
        "xbox_drm_bypass.exe",
        "xbox_drm_bypass_halo.dll",
        "halo_xbox_crack.exe",
        "halo_gamepass_crack.exe",
        "halo_infinite_crack.exe",
        "xbox_offline_bypass.exe",
        "halo_offline_bypass.exe",
        "xbox_auth_bypass.dll",
        "halo_xbox_auth_bypass.dll",
        "gaming_services_bypass.exe",
        "gamingservices_bypass.dll",
        "halo_gaming_services_bypass.exe",
    };

    private static readonly string[] CheatConfigFileNames =
    {
        "halo_cheat_config.json",
        "halo_config.cfg",
        "halo_infinite_config.json",
        "halo_settings.json",
        "halo_aimbot.cfg",
        "halo_esp.cfg",
        "halo_wallhack.cfg",
        "halo_triggerbot.cfg",
        "halo_recoil.cfg",
        "halo_menu.json",
        "halo_cheat.ini",
        "halo_hack.ini",
        "halo_options.json",
        "halo_profile.json",
        "halo_keys.json",
        "halo_hotkeys.cfg",
        "halo_armor.json",
        "halo_weapon.json",
        "halo_colors.json",
        "halo_esp_colors.json",
        "halo_bones.json",
        "cheat_config_halo.json",
        "hack_config_halo.json",
        "halo_internal_config.json",
        "halo_external_config.json",
        "hi_cheat.cfg",
        "hi_aimbot.cfg",
        "haloinfinite_cheat.cfg",
        "halo_infinite_cheat.ini",
        "halo_rank_hack.cfg",
        "halo_challenge_hack.cfg",
    };

    private static readonly string[] OffsetFileNames =
    {
        "halo_offsets.json",
        "halo_addresses.txt",
        "halo_patterns.txt",
        "halo_signatures.json",
        "halo_ptrs.json",
        "halo_netvar.json",
        "halo_sdk.hpp",
        "halo_sdk.h",
        "halo_sdk.cpp",
        "halo_offsets.h",
        "halo_offsets.hpp",
        "halo_offsets.txt",
        "halo_dump.json",
        "halo_dump.txt",
        "halo_structs.json",
        "halo_structs.h",
        "halo_classes.hpp",
        "halo_mem.json",
        "halo_memory.json",
        "halo_base.txt",
        "halo_gamebase.txt",
        "halo_entitylist.txt",
        "halo_localplayer.txt",
        "halo_viewmatrix.txt",
        "halo_viewangles.txt",
        "halo_bones.txt",
        "halo_weapon_offset.txt",
        "halo_ammo_offset.txt",
        "halo_vehicle_offsets.json",
        "halo_render_offset.txt",
        "halo_infinite_offsets.json",
        "halo_infinite_addresses.txt",
        "halo_infinite_patterns.txt",
        "halo_infinite_dump.json",
        "haloinfinite_offsets.json",
        "hi_offsets.json",
        "hi_addresses.txt",
        "hi_patterns.txt",
    };

    private static readonly string[] CheatKeywordsInConfigs =
    {
        "aimbot", "triggerbot", "wallhack", "wallhacks", "esp", "norecoil", "no_recoil",
        "nospread", "no_spread", "nofall", "no_fall", "bhop", "bunny_hop", "speedhack",
        "god_mode", "godmode", "infinite_ammo", "inf_ammo", "unlock_all", "armor_hack",
        "silent_aim", "silentaim", "fov_aimbot", "bone_aimbot", "head_aimbot",
        "smoothness", "aim_smooth", "aim_fov", "aim_bone", "aim_key", "aimkey",
        "draw_esp", "draw_box", "draw_skeleton", "draw_health", "draw_distance",
        "vehicle_esp", "vehicle_hack", "radar_hack", "radar_overlay", "cheat_enabled",
        "bypass_enabled", "eac_bypass", "anticheat_bypass", "rank_hack", "xp_hack",
        "challenge_bypass", "cosmetic_unlock", "battle_pass_hack",
    };

    private static readonly string[] UserAssistCheatNames =
    {
        "halo_cheat",
        "halo_infinite_cheat",
        "halo_aimbot",
        "halo_hack",
        "halo_esp",
        "halo_wh",
        "halo_trigger",
        "halo_recoil",
        "halo_speed",
        "halo_radar",
        "halo_nofall",
        "halo_fly",
        "halo_loader",
        "halo_injector",
        "halo_bypass",
        "halo_spoofer",
        "halo_unlock",
        "halo_infinite_hack",
        "halo_infinite_loader",
        "halo_eac_bypass",
        "eac_halo",
        "halotrainer",
        "halocheat",
        "haloinfinitecheat",
        "haloinfinitehack",
        "hi_cheat",
        "hi_hack",
        "hi_aimbot",
    };

    private static readonly string[] RunKeyCheatPatterns =
    {
        "halo_cheat",
        "halo_aimbot",
        "halo_hack",
        "halo_loader",
        "halo_injector",
        "halo_bypass",
        "halo_spoofer",
        "halo_driver",
        "halo_kmode",
        "halo_eac",
        "halo_infinite_cheat",
        "halo_infinite_hack",
        "halo_infinite_loader",
        "halocheat",
        "haloinfinitecheat",
        "halotrainer",
        "hi_cheat",
        "hi_loader",
    };

    private static readonly string[] TempCheatFilePatterns =
    {
        "halo_cheat",
        "halo_aimbot",
        "halo_hack",
        "halo_esp",
        "halo_loader",
        "halo_injector",
        "halo_bypass",
        "halo_spoofer",
        "halo_radar",
        "halo_offsets",
        "halo_dump",
        "halo_sdk",
        "halo_update",
        "halo_patch",
        "halo_crack",
        "halo_keygen",
        "halo_unpack",
        "halo_extract",
        "halo_install",
        "halo_setup",
        "halo_payload",
        "halo_kernel",
        "halo_km_",
        "halo_infinite_cheat",
        "halo_infinite_hack",
        "halo_infinite_loader",
        "haloinfinitecheat",
        "haloinfinitehack",
        "halocheat",
        "halohack",
        "haloaimbot",
        "hi_cheat",
        "hi_hack",
        "hi_loader",
    };

    private static readonly string[] HaloLogCheatPatterns =
    {
        "cheat", "aimbot", "wallhack", "triggerbot", "esp", "norecoil",
        "no_recoil", "bypass", "injector", "loader", "exploit", "hack",
        "speedhack", "nofall", "godmode", "god_mode", "unlock_all",
        "silent_aim", "silentaim", "radar_hack", "bhop", "bunny_hop",
        "armor_hack", "vehicle_hack", "eac_bypass", "anticheat_bypass",
        "offset_dump", "memory_read", "process_inject", "dll_inject",
        "kernel_driver", "km_cheat", "dma_cheat", "rank_hack", "xp_hack",
        "challenge_bypass", "cosmetic_unlock", "xbox_bypass", "gamepass_bypass",
    };

    private static readonly string[] KnownCheatFolderNames =
    {
        "halo_cheat",
        "halo_aimbot",
        "halo_hack",
        "halo_esp",
        "halo_loader",
        "halo_injector",
        "halocheat",
        "halohack",
        "haloaimbot",
        "haloesp",
        "halo_infinite_cheat",
        "halo_infinite_hack",
        "halo_infinite_loader",
        "haloinfinitecheat",
        "haloinfinitehack",
        "halotools",
        "halo_bypass",
        "halo_spoofer",
        "hi_cheat",
        "hi_hack",
    };

    private static readonly string[] XboxOverlayAbuseArtifacts =
    {
        "xbox_overlay_inject.dll",
        "xgameruntime_hook.dll",
        "gamebar_bypass.dll",
        "gamebar_inject.dll",
        "xbox_game_bar_hook.dll",
        "halo_gamebar_inject.dll",
        "halo_xbox_overlay_hook.dll",
        "halo_gamebar_bypass.dll",
        "xbox_dvr_hook.dll",
        "halo_xbox_dvr_bypass.dll",
        "gameoverlay_bypass_halo.dll",
        "halo_gameoverlay_hook.dll",
        "xbox_overlay_cheat.dll",
        "halo_overlay_cheat.exe",
        "gamingservices_hook.dll",
        "halo_gamingservices_bypass.dll",
        "playfab_bypass_halo.dll",
        "halo_playfab_bypass.exe",
        "halo_xbox_auth_hook.dll",
        "xbox_identity_bypass_halo.dll",
    };

    private static readonly string[] MuiCacheCheatPatterns =
    {
        "halo_cheat",
        "halo_infinite_cheat",
        "halo_aimbot",
        "halo_hack",
        "halo_esp",
        "halo_wh",
        "halo_trigger",
        "halo_recoil",
        "halo_speed",
        "halo_radar",
        "halo_nofall",
        "halo_fly",
        "halo_loader",
        "halo_injector",
        "halo_bypass",
        "halo_spoofer",
        "halo_unlock",
        "halo_infinite_hack",
        "halo_infinite_loader",
        "halo_eac_bypass",
        "eac_halo",
        "halotrainer",
        "halocheat",
        "haloinfinitecheat",
        "haloinfinitehack",
        "hi_cheat",
        "hi_hack",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.WhenAll(
            CheckCheatExecutables(ctx, ct),
            CheckEacBypassArtifacts(ctx, ct),
            CheckXboxGamePassBypassArtifacts(ctx, ct),
            CheckXboxOverlayAbuseArtifacts(ctx, ct),
            CheckCheatConfigFiles(ctx, ct),
            CheckOffsetFiles(ctx, ct),
            CheckUserAssistRegistry(ctx, ct),
            CheckMuiCacheRegistry(ctx, ct),
            CheckRunKeyRegistry(ctx, ct),
            CheckUwpPackageDataArtifacts(ctx, ct),
            CheckTempFolderArtifacts(ctx, ct),
            CheckHaloLogFiles(ctx, ct),
            CheckKnownCheatFolders(ctx, ct),
            CheckInstalledSoftwareRegistry(ctx, ct),
            CheckScheduledTaskArtifacts(ctx, ct),
            CheckDownloadsFolderArtifacts(ctx, ct)
        );
    }

    private Task CheckCheatExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.02, "Halo Infinite Cheat EXEs", "Scanning for Halo Infinite cheat executables...");

            var searchRoots = new List<string>
            {
                KnownPaths.UserProfile,
                KnownPaths.Downloads,
                KnownPaths.LocalAppData,
                KnownPaths.RoamingAppData,
                KnownPaths.Temp,
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
                Path.Combine(KnownPaths.LocalAppData, "Temp"),
                @"C:\HaloInfinite",
                @"C:\halo_cheat",
                @"C:\halo",
                @"C:\cheats",
                @"C:\hacks",
                @"C:\tools",
            };

            var steamDir = KnownPaths.FindSteamDirectory();
            if (steamDir is not null)
            {
                searchRoots.Add(steamDir);
                searchRoots.Add(Path.Combine(steamDir, "steamapps", "common", "Halo Infinite"));
            }

            var cheatNamesLower = new HashSet<string>(
                CheatExecutableNames.Select(n => n.ToLowerInvariant()),
                StringComparer.OrdinalIgnoreCase);

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                string[] files;
                try { files = Directory.GetFiles(root, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);
                    if (!cheatNamesLower.Contains(fileName.ToLowerInvariant())) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Halo Infinite Cheat Executable Found: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' at '{file}' matches a known Halo Infinite cheat executable name. " +
                                 "This artifact indicates the presence of cheat software targeting Halo Infinite. " +
                                 "Known cheat tools with this exact filename have been observed in cheat distribution channels.",
                        Detail = $"Artifact type: Halo Infinite cheat executable · Path: {file}"
                    });
                }

                string[] subDirs;
                try { subDirs = Directory.GetDirectories(root); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var sub in subDirs)
                {
                    if (ct.IsCancellationRequested) return;

                    string[] subFiles;
                    try { subFiles = Directory.GetFiles(sub, "*", SearchOption.TopDirectoryOnly); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in subFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var fileName = Path.GetFileName(file);
                        if (!cheatNamesLower.Contains(fileName.ToLowerInvariant())) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Halo Infinite Cheat Executable Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"The file '{fileName}' at '{file}' matches a known Halo Infinite cheat executable name. " +
                                     "This artifact indicates the presence of cheat software targeting Halo Infinite.",
                            Detail = $"Artifact type: Halo Infinite cheat executable · Path: {file}"
                        });
                    }
                }
            }

            ctx.Report(0.08, "Halo Infinite Cheat EXEs", "Halo Infinite cheat executable scan complete");
        }, ct);

    private Task CheckEacBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.10, "Halo EAC Bypass", "Scanning for Halo Infinite EasyAntiCheat bypass artifacts...");

            var bypassNamesLower = new HashSet<string>(
                EacBypassArtifacts.Select(n => n.ToLowerInvariant()),
                StringComparer.OrdinalIgnoreCase);

            var searchRoots = new List<string>
            {
                KnownPaths.UserProfile,
                KnownPaths.Downloads,
                KnownPaths.LocalAppData,
                KnownPaths.RoamingAppData,
                KnownPaths.Temp,
                Path.Combine(KnownPaths.LocalAppData, "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)),
                @"C:\Windows\System32",
                @"C:\Windows\SysWOW64",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            };

            var eacInstallDirs = new[]
            {
                @"C:\Program Files (x86)\EasyAntiCheat",
                @"C:\Program Files\EasyAntiCheat",
                Path.Combine(KnownPaths.LocalAppData, "EasyAntiCheat"),
            };
            searchRoots.AddRange(eacInstallDirs);

            var steamDir = KnownPaths.FindSteamDirectory();
            if (steamDir is not null)
            {
                searchRoots.Add(steamDir);
                var eacSteam = Path.Combine(steamDir, "steamapps", "common", "Halo Infinite", "EasyAntiCheat");
                if (Directory.Exists(eacSteam)) searchRoots.Add(eacSteam);
            }

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                string[] files;
                try { files = Directory.GetFiles(root, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);
                    if (!bypassNamesLower.Contains(fileName.ToLowerInvariant())) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Halo Infinite EAC Bypass Artifact: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' is a known EasyAntiCheat bypass artifact targeting Halo Infinite. " +
                                 "EAC bypass tools are used to disable or circumvent the anti-cheat system, " +
                                 "allowing cheats to operate undetected. This artifact strongly indicates cheat usage.",
                        Detail = $"Artifact type: EAC bypass · Path: {file}"
                    });
                }
            }

            ctx.Report(0.16, "Halo EAC Bypass", "Halo Infinite EAC bypass scan complete");
        }, ct);

    private Task CheckXboxGamePassBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.18, "Halo Xbox/GamePass Bypass", "Scanning for Xbox Game Pass / Microsoft Store bypass artifacts...");

            var bypassNamesLower = new HashSet<string>(
                XboxGamePassBypassArtifacts.Select(n => n.ToLowerInvariant()),
                StringComparer.OrdinalIgnoreCase);

            var searchRoots = new List<string>
            {
                KnownPaths.UserProfile,
                KnownPaths.Downloads,
                KnownPaths.LocalAppData,
                KnownPaths.RoamingAppData,
                KnownPaths.Temp,
                Path.Combine(KnownPaths.LocalAppData, "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
                Path.Combine(KnownPaths.LocalAppData, "Packages"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Microsoft", "Windows"),
                @"C:\Program Files\WindowsApps",
                @"C:\Windows\System32",
                @"C:\Windows\SysWOW64",
            };

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                string[] files;
                try { files = Directory.GetFiles(root, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);
                    if (!bypassNamesLower.Contains(fileName.ToLowerInvariant())) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Halo Infinite Xbox/GamePass Bypass: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' is a known Xbox Game Pass or Microsoft Store bypass artifact. " +
                                 "Halo Infinite is distributed via Xbox Game Pass and Microsoft Store (as a UWP application), " +
                                 "and bypass tools targeting these platforms can circumvent authentication, entitlement checks, " +
                                 "and Xbox Live services that protect competitive integrity.",
                        Detail = $"Artifact type: Xbox/GamePass bypass · Path: {file}"
                    });
                }
            }

            ctx.Report(0.23, "Halo Xbox/GamePass Bypass", "Halo Infinite Xbox/GamePass bypass scan complete");
        }, ct);

    private Task CheckXboxOverlayAbuseArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.25, "Halo Xbox Overlay Abuse", "Scanning for Halo Infinite Xbox overlay abuse artifacts...");

            var artifactNamesLower = new HashSet<string>(
                XboxOverlayAbuseArtifacts.Select(n => n.ToLowerInvariant()),
                StringComparer.OrdinalIgnoreCase);

            var searchRoots = new List<string>
            {
                KnownPaths.UserProfile,
                KnownPaths.Downloads,
                KnownPaths.LocalAppData,
                KnownPaths.RoamingAppData,
                KnownPaths.Temp,
                Path.Combine(KnownPaths.LocalAppData, "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
                Path.Combine(KnownPaths.LocalAppData, "Packages"),
                @"C:\Windows\System32",
                @"C:\Windows\SysWOW64",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Microsoft", "Xbox"),
            };

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                string[] files;
                try { files = Directory.GetFiles(root, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);
                    if (!artifactNamesLower.Contains(fileName.ToLowerInvariant())) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Halo Infinite Xbox Overlay Abuse Artifact: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' is a known artifact of Xbox Game Bar overlay injection or hooking targeting Halo Infinite. " +
                                 "Cheats abusing the Xbox Game Bar overlay can inject code into the Halo Infinite process through the overlay's " +
                                 "rendering or audio pipeline, potentially bypassing injection-focused anti-cheat detection. " +
                                 "Xbox DVR and Gaming Services hooks allow cheats to obtain process handles with broad permissions.",
                        Detail = $"Artifact type: Halo Xbox overlay abuse · Path: {file}"
                    });
                }
            }

            ctx.Report(0.30, "Halo Xbox Overlay Abuse", "Halo Infinite Xbox overlay abuse scan complete");
        }, ct);

    private Task CheckCheatConfigFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.32, "Halo Cheat Configs", "Scanning for Halo Infinite cheat configuration files...");

            var configNamesLower = new HashSet<string>(
                CheatConfigFileNames.Select(n => n.ToLowerInvariant()),
                StringComparer.OrdinalIgnoreCase);

            var searchRoots = new List<string>
            {
                KnownPaths.UserProfile,
                KnownPaths.Downloads,
                KnownPaths.LocalAppData,
                KnownPaths.RoamingAppData,
                KnownPaths.Temp,
                Path.Combine(KnownPaths.LocalAppData, "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
                Path.Combine(KnownPaths.LocalAppData, "Halo Infinite"),
                Path.Combine(KnownPaths.RoamingAppData, "Halo Infinite"),
                Path.Combine(KnownPaths.LocalAppData, "HaloInfinite"),
                Path.Combine(KnownPaths.RoamingAppData, "HaloInfinite"),
                Path.Combine(KnownPaths.LocalAppData, "Halo"),
                Path.Combine(KnownPaths.RoamingAppData, "Halo"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Saved Games", "Halo Infinite"),
            };

            var steamDir = KnownPaths.FindSteamDirectory();
            if (steamDir is not null)
            {
                searchRoots.Add(Path.Combine(steamDir, "steamapps", "common", "Halo Infinite"));
                searchRoots.Add(Path.Combine(steamDir, "steamapps", "common"));
            }

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                string[] files;
                try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);

                    if (configNamesLower.Contains(fileName.ToLowerInvariant()))
                    {
                        string content = string.Empty;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { }

                        bool hasCheatKeyword = CheatKeywordsInConfigs.Any(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Halo Infinite Cheat Config File: {fileName}",
                            Risk = hasCheatKeyword ? RiskLevel.Critical : RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"The file '{fileName}' matches a known Halo Infinite cheat configuration filename. " +
                                     (hasCheatKeyword
                                         ? "The file content also contains known cheat configuration keywords, confirming its nature as a cheat config file. "
                                         : "The filename itself strongly indicates a cheat configuration artifact. ") +
                                     "Cheat config files store aimbot settings, ESP colors, keybinds, and bypass options.",
                            Detail = $"Artifact type: Halo Infinite cheat config · Keywords found: {hasCheatKeyword} · Path: {file}"
                        });
                        continue;
                    }

                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext is not (".cfg" or ".ini" or ".json")) continue;

                    if (!fileName.StartsWith("halo", StringComparison.OrdinalIgnoreCase) &&
                        !fileName.StartsWith("hi_", StringComparison.OrdinalIgnoreCase) &&
                        !fileName.StartsWith("haloinfinite", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string fileContent = string.Empty;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        fileContent = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var matchedKeyword = CheatKeywordsInConfigs.FirstOrDefault(k =>
                        fileContent.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (matchedKeyword is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Halo Infinite Config File with Cheat Keywords: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The config file '{fileName}' contains the cheat-related keyword '{matchedKeyword}'. " +
                                 "Config files with Halo Infinite-related names that contain cheat keywords are artifacts " +
                                 "of cheat tools that store their settings alongside or near game configuration.",
                        Detail = $"Keyword found: '{matchedKeyword}' · Path: {file}"
                    });
                }
            }

            ctx.Report(0.38, "Halo Cheat Configs", "Halo Infinite cheat config scan complete");
        }, ct);

    private Task CheckOffsetFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.40, "Halo Offset Files", "Scanning for Halo Infinite memory offset/address files...");

            var offsetNamesLower = new HashSet<string>(
                OffsetFileNames.Select(n => n.ToLowerInvariant()),
                StringComparer.OrdinalIgnoreCase);

            var searchRoots = new List<string>
            {
                KnownPaths.UserProfile,
                KnownPaths.Downloads,
                KnownPaths.LocalAppData,
                KnownPaths.RoamingAppData,
                KnownPaths.Temp,
                Path.Combine(KnownPaths.LocalAppData, "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            };

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                string[] files;
                try { files = Directory.GetFiles(root, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);
                    if (!offsetNamesLower.Contains(fileName.ToLowerInvariant())) continue;

                    string snippet = string.Empty;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        snippet = await sr.ReadToEndAsync(ct);
                        if (snippet.Length > 500) snippet = snippet[..500];
                    }
                    catch (IOException) { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Halo Infinite Offset/Address File: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' matches a known Halo Infinite memory offset or address dump file. " +
                                 "Offset files contain game memory layout information (entity list offsets, bone matrix addresses, " +
                                 "view matrix, local player, weapon data, armor and vehicle data) required to build or run cheat software. " +
                                 "These files are exclusively created by cheat developers and users performing game memory analysis.",
                        Detail = $"Artifact type: Halo Infinite offset/address dump · Path: {file}"
                    });
                }
            }

            ctx.Report(0.45, "Halo Offset Files", "Halo Infinite offset file scan complete");
        }, ct);

    private Task CheckUserAssistRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.47, "Halo UserAssist", "Scanning UserAssist registry for Halo Infinite cheat execution history...");

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

                        var decodedLower = decoded.ToLowerInvariant();
                        var matched = UserAssistCheatNames.FirstOrDefault(n =>
                            decodedLower.Contains(n.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));

                        if (matched is null) continue;

                        DateTime? lastRun = null;
                        try
                        {
                            if (count.GetValue(valueName) is byte[] b && b.Length >= 72)
                                lastRun = DateTime.FromFileTime(BitConverter.ToInt64(b, 60));
                        }
                        catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Halo Infinite Cheat Executed (UserAssist): {Path.GetFileName(decoded)}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason = $"UserAssist registry records the execution of '{decoded}', which matches the known Halo Infinite cheat name pattern '{matched}'. " +
                                     "UserAssist logs GUI application launches; this entry proves the cheat executable was run on this system, " +
                                     "even if the file has since been deleted.",
                            Detail = $"Decoded name: {decoded} · Last run: {(lastRun.HasValue ? lastRun.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm") : "unknown")} · ROT13 source: {valueName}"
                        });
                    }
                }
            }
            catch { }

            ctx.Report(0.52, "Halo UserAssist", "Halo Infinite UserAssist scan complete");
        }, ct);

    private Task CheckMuiCacheRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.53, "Halo MUICache", "Scanning MUICache registry for Halo Infinite cheat artifacts...");

            var muiCachePaths = new[]
            {
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                @"Software\Microsoft\Windows\ShellNoRoam\MUICache"
            };

            foreach (var regPath in muiCachePaths)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var k = Registry.CurrentUser.OpenSubKey(regPath);
                    if (k is null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var val in k.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        if (!val.Contains('\\') && !val.Contains('/')) continue;

                        var valLower = val.ToLowerInvariant();
                        var matched = MuiCacheCheatPatterns.FirstOrDefault(p =>
                            valLower.Contains(p.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));

                        if (matched is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Halo Infinite Cheat in MUICache: {Path.GetFileName(val)}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\{regPath}",
                            FileName = Path.GetFileName(val),
                            Reason = $"MUICache contains a reference to '{val}', which matches the Halo Infinite cheat pattern '{matched}'. " +
                                     "MUICache records the display names of executables that were launched in the Windows shell. " +
                                     "This proves the cheat executable was run on this system.",
                            Detail = $"Registry path: HKCU\\{regPath} · Value: {val} · Matched pattern: {matched}"
                        });
                    }
                }
                catch { }
            }

            ctx.Report(0.57, "Halo MUICache", "Halo Infinite MUICache scan complete");
        }, ct);

    private Task CheckRunKeyRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.58, "Halo Run Keys", "Scanning registry Run keys for Halo Infinite cheat persistence...");

            var runKeyPaths = new[]
            {
                @"Software\Microsoft\Windows\CurrentVersion\Run",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                @"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
                @"Software\Microsoft\Windows\CurrentVersion\RunServices",
                @"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            };

            var hives = new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine };

            foreach (var hive in hives)
            {
                foreach (var runPath in runKeyPaths)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                        using var k = baseKey.OpenSubKey(runPath);
                        if (k is null) continue;
                        ctx.IncrementRegistryKeys();

                        foreach (var valName in k.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            var valData = k.GetValue(valName)?.ToString() ?? string.Empty;
                            var combined = (valName + " " + valData).ToLowerInvariant();

                            var matched = RunKeyCheatPatterns.FirstOrDefault(p =>
                                combined.Contains(p.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));

                            if (matched is null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Halo Infinite Cheat Autostart (Run Key): {valName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"{(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM")}\{runPath}",
                                FileName = valName,
                                Reason = $"Registry Run key '{valName}' = '{valData}' matches Halo Infinite cheat pattern '{matched}'. " +
                                         "A Run key entry causes the referenced program to execute at user login. " +
                                         "Halo Infinite cheat loaders and kernel drivers use Run keys to ensure they start automatically " +
                                         "before Halo Infinite launches, preloading memory patches or bypasses.",
                                Detail = $"Hive: {(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM")} · Key: {runPath} · Value: {valName} = {valData}"
                            });
                        }
                    }
                    catch { }
                }
            }

            ctx.Report(0.62, "Halo Run Keys", "Halo Infinite Run key scan complete");
        }, ct);

    private Task CheckUwpPackageDataArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.63, "Halo UWP Package Data", "Scanning UWP package data for Halo Infinite cheat modifications...");

            var packagesRoot = Path.Combine(KnownPaths.LocalAppData, "Packages");
            if (!Directory.Exists(packagesRoot)) return;

            string[] packageDirs;
            try { packageDirs = Directory.GetDirectories(packagesRoot); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            var haloPackagePrefixes = new[]
            {
                "Microsoft.254428597",
                "Microsoft.HaloInfinite",
                "HaloInfinite",
                "MicrosoftCorporationII.HaloInfinite",
                "343Industries.HaloInfinite",
            };

            foreach (var packageDir in packageDirs)
            {
                if (ct.IsCancellationRequested) return;
                var packageName = Path.GetFileName(packageDir);

                bool isHaloPackage = haloPackagePrefixes.Any(prefix =>
                    packageName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

                if (!isHaloPackage) continue;

                var subDirsToScan = new[]
                {
                    Path.Combine(packageDir, "LocalState"),
                    Path.Combine(packageDir, "RoamingState"),
                    Path.Combine(packageDir, "TempState"),
                    Path.Combine(packageDir, "LocalCache"),
                    Path.Combine(packageDir, "Settings"),
                    Path.Combine(packageDir, "AC"),
                };

                foreach (var subDir in subDirsToScan)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(subDir)) continue;

                    string[] files;
                    try { files = Directory.GetFiles(subDir, "*", SearchOption.AllDirectories); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in files)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var fileName = Path.GetFileName(file).ToLowerInvariant();
                        var ext = Path.GetExtension(file).ToLowerInvariant();

                        var matchedCheatName = CheatExecutableNames
                            .Concat(EacBypassArtifacts)
                            .Concat(CheatConfigFileNames)
                            .Concat(OffsetFileNames)
                            .FirstOrDefault(n => fileName.Equals(n.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));

                        if (matchedCheatName is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Halo Infinite UWP Package Cheat Artifact: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"A known Halo Infinite cheat artifact '{matchedCheatName}' was found inside the " +
                                         $"UWP package data directory '{packageName}'. " +
                                         "Finding cheat files within the UWP package storage area is highly suspicious, as only " +
                                         "the game itself and authorized tools should write to this location.",
                                Detail = $"Package: {packageName} · Matched: {matchedCheatName} · Path: {file}"
                            });
                            continue;
                        }

                        if (ext is not (".cfg" or ".ini" or ".json" or ".log" or ".txt")) continue;

                        var matchedPattern = TempCheatFilePatterns.FirstOrDefault(p =>
                            fileName.Contains(p.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));
                        if (matchedPattern is null) continue;

                        string content = string.Empty;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }

                        bool hasCheatKeyword = CheatKeywordsInConfigs.Any(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (!hasCheatKeyword) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Halo Infinite UWP Package Modified Config: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"A config/log file in the Halo Infinite UWP package data directory '{packageName}' " +
                                     $"has a cheat-related name pattern ('{matchedPattern}') and contains cheat keywords. " +
                                     "Unusual files in the UWP package data area may indicate attempts to modify game settings " +
                                     "or persist cheat configuration through the UWP storage APIs.",
                            Detail = $"Package: {packageName} · Matched pattern: {matchedPattern} · Path: {file}"
                        });
                    }
                }
            }

            ctx.Report(0.67, "Halo UWP Package Data", "Halo Infinite UWP package data scan complete");
        }, ct);

    private Task CheckTempFolderArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.68, "Halo Temp Artifacts", "Scanning temp folders for Halo Infinite cheat artifacts...");

            var tempRoots = new[]
            {
                KnownPaths.Temp,
                Path.Combine(KnownPaths.LocalAppData, "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            };

            foreach (var tempRoot in tempRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tempRoot)) continue;

                string[] files;
                try { files = Directory.GetFiles(tempRoot, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file).ToLowerInvariant();
                    var matched = TempCheatFilePatterns.FirstOrDefault(p =>
                        fileName.Contains(p.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));
                    if (matched is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Halo Infinite Cheat Artifact in Temp: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"A file matching the Halo Infinite cheat pattern '{matched}' was found in a temporary folder at '{file}'. " +
                                 "Cheat loaders and installers commonly drop payloads into temp directories before injection or installation. " +
                                 "Temp-resident cheat artifacts may indicate an in-progress or recently completed cheat deployment.",
                        Detail = $"Artifact type: Halo Infinite temp cheat file · Matched pattern: {matched} · Path: {file}"
                    });
                }

                string[] subDirs;
                try { subDirs = Directory.GetDirectories(tempRoot); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var sub in subDirs)
                {
                    if (ct.IsCancellationRequested) return;
                    var subName = Path.GetFileName(sub).ToLowerInvariant();
                    var dirMatched = TempCheatFilePatterns.FirstOrDefault(p =>
                        subName.Contains(p.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));
                    if (dirMatched is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Halo Infinite Cheat Folder in Temp: {Path.GetFileName(sub)}",
                            Risk = RiskLevel.High,
                            Location = sub,
                            FileName = Path.GetFileName(sub),
                            Reason = $"A directory matching Halo Infinite cheat pattern '{dirMatched}' was found in a temporary folder. " +
                                     "Cheat software frequently creates subdirectories in temp for storing unpacked components, " +
                                     "driver files, or configuration data during or after installation.",
                            Detail = $"Artifact type: Halo Infinite temp cheat folder · Matched: {dirMatched} · Path: {sub}"
                        });
                        continue;
                    }

                    string[] subFiles;
                    try { subFiles = Directory.GetFiles(sub, "*", SearchOption.TopDirectoryOnly); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in subFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var fileName = Path.GetFileName(file).ToLowerInvariant();
                        var fileMatched = TempCheatFilePatterns.FirstOrDefault(p =>
                            fileName.Contains(p.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));
                        if (fileMatched is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Halo Infinite Cheat File in Temp Subfolder: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"A file matching Halo Infinite cheat pattern '{fileMatched}' was found in a temp subdirectory. " +
                                     "This is consistent with cheat installer or loader activity.",
                            Detail = $"Matched pattern: {fileMatched} · Path: {file}"
                        });
                    }
                }
            }

            ctx.Report(0.73, "Halo Temp Artifacts", "Halo Infinite temp folder scan complete");
        }, ct);

    private Task CheckHaloLogFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.74, "Halo Log Files", "Scanning Halo Infinite log files for cheat-related patterns...");

            var haloLogDirs = new List<string>
            {
                Path.Combine(KnownPaths.LocalAppData, "Halo Infinite"),
                Path.Combine(KnownPaths.RoamingAppData, "Halo Infinite"),
                Path.Combine(KnownPaths.LocalAppData, "HaloInfinite"),
                Path.Combine(KnownPaths.RoamingAppData, "HaloInfinite"),
                Path.Combine(KnownPaths.LocalAppData, "Halo"),
                Path.Combine(KnownPaths.RoamingAppData, "Halo"),
                Path.Combine(KnownPaths.LocalAppData, "Packages"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Saved Games", "Halo Infinite"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Documents", "Halo Infinite"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Documents", "My Games", "Halo Infinite"),
            };

            var steamDir = KnownPaths.FindSteamDirectory();
            if (steamDir is not null)
            {
                haloLogDirs.Add(Path.Combine(steamDir, "steamapps", "common", "Halo Infinite"));
                haloLogDirs.Add(Path.Combine(steamDir, "logs"));
            }

            foreach (var logDir in haloLogDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(logDir)) continue;

                string[] logFiles;
                try { logFiles = Directory.GetFiles(logDir, "*.log", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

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

                    if (string.IsNullOrWhiteSpace(content)) continue;

                    var matchedPatterns = HaloLogCheatPatterns
                        .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchedPatterns.Count == 0) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Halo Infinite Log Contains Cheat Patterns: {Path.GetFileName(logFile)}",
                        Risk = RiskLevel.High,
                        Location = logFile,
                        FileName = Path.GetFileName(logFile),
                        Reason = $"The Halo Infinite log file '{logFile}' contains cheat-related keywords: " +
                                 $"{string.Join(", ", matchedPatterns.Take(5).Select(p => $"'{p}'"))}. " +
                                 "Cheat tools may log their own activity, or trigger error/exception entries in game logs " +
                                 "when intercepting game functions. These patterns in official game logs are forensic evidence " +
                                 "of cheat tool interaction with the game process.",
                        Detail = $"Matched patterns: {string.Join(", ", matchedPatterns.Take(10))} · Log: {logFile}"
                    });
                }

                string[] txtFiles;
                try { txtFiles = Directory.GetFiles(logDir, "*.txt", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var txtFile in txtFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(txtFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    if (string.IsNullOrWhiteSpace(content)) continue;

                    var matchedPatterns = HaloLogCheatPatterns
                        .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchedPatterns.Count < 2) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Halo Infinite Text File with Cheat Keywords: {Path.GetFileName(txtFile)}",
                        Risk = RiskLevel.Medium,
                        Location = txtFile,
                        FileName = Path.GetFileName(txtFile),
                        Reason = $"A text file in the Halo Infinite data directory contains multiple cheat-related keywords: " +
                                 $"{string.Join(", ", matchedPatterns.Take(5).Select(p => $"'{p}'"))}. " +
                                 "This may indicate a cheat's own log file or output file left in the Halo Infinite data directory.",
                        Detail = $"Matched patterns: {string.Join(", ", matchedPatterns.Take(10))} · File: {txtFile}"
                    });
                }
            }

            ctx.Report(0.79, "Halo Log Files", "Halo Infinite log file scan complete");
        }, ct);

    private Task CheckKnownCheatFolders(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.80, "Halo Cheat Folders", "Scanning for known Halo Infinite cheat installation directories...");

            var searchRoots = new List<string>
            {
                KnownPaths.UserProfile,
                KnownPaths.Downloads,
                KnownPaths.LocalAppData,
                KnownPaths.RoamingAppData,
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
                @"C:\",
                @"C:\Users\Public",
                @"C:\ProgramData",
                @"C:\Program Files",
                @"C:\Program Files (x86)",
            };

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                string[] dirs;
                try { dirs = Directory.GetDirectories(root); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var dir in dirs)
                {
                    if (ct.IsCancellationRequested) return;
                    var dirName = Path.GetFileName(dir);
                    var matched = KnownCheatFolderNames.FirstOrDefault(n =>
                        dirName.Equals(n, StringComparison.OrdinalIgnoreCase) ||
                        dirName.Contains(n, StringComparison.OrdinalIgnoreCase));
                    if (matched is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known Halo Infinite Cheat Directory: {dirName}",
                        Risk = RiskLevel.Critical,
                        Location = dir,
                        FileName = dirName,
                        Reason = $"The directory '{dirName}' at '{dir}' matches a known Halo Infinite cheat installation folder name. " +
                                 "Cheat software typically creates named directories for storing executables, configs, and DLLs. " +
                                 "This directory name is associated with known Halo Infinite cheat packages.",
                        Detail = $"Matched folder pattern: {matched} · Full path: {dir}"
                    });
                }
            }

            ctx.Report(0.84, "Halo Cheat Folders", "Halo Infinite cheat folder scan complete");
        }, ct);

    private Task CheckInstalledSoftwareRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.85, "Halo Installed Software", "Scanning installed software registry for Halo Infinite cheat entries...");

            var uninstallPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };

            var cheatNameFragments = new[]
            {
                "halo_cheat", "halo_hack", "halo_aimbot", "halo_esp",
                "halo_loader", "halo_injector", "halo_bypass", "halo_spoofer",
                "halo_trainer", "halo_infinite_cheat", "halo cheat", "halo hack",
                "halo aimbot", "halo trainer", "halo infinite cheat",
                "halocheat", "halohack", "halo_eac_bypass", "halo infinite hack",
                "halo infinite trainer", "hi_cheat", "hi_hack",
            };

            var hives = new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine };

            foreach (var hive in hives)
            {
                foreach (var uninstallPath in uninstallPaths)
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                        using var uninstall = baseKey.OpenSubKey(uninstallPath);
                        if (uninstall is null) continue;

                        foreach (var subName in uninstall.GetSubKeyNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            try
                            {
                                using var sub = uninstall.OpenSubKey(subName);
                                if (sub is null) continue;
                                ctx.IncrementRegistryKeys();

                                var displayName = sub.GetValue("DisplayName")?.ToString() ?? string.Empty;
                                var displayLocation = sub.GetValue("InstallLocation")?.ToString() ?? string.Empty;
                                var combined = (displayName + " " + subName + " " + displayLocation).ToLowerInvariant();

                                var matched = cheatNameFragments.FirstOrDefault(f =>
                                    combined.Contains(f.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));
                                if (matched is null) continue;

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Halo Infinite Cheat in Installed Programs: {displayName}",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"{(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM")}\{uninstallPath}\{subName}",
                                    FileName = subName,
                                    Reason = $"The installed programs registry contains an entry '{displayName}' matching Halo Infinite cheat pattern '{matched}'. " +
                                             "An entry in the uninstall registry means the cheat was formally installed (not just dropped as a file), " +
                                             "indicating a packaged cheat distribution.",
                                    Detail = $"Display name: {displayName} · Install location: {displayLocation} · Registry: {uninstallPath}\\{subName}"
                                });
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }

            ctx.Report(0.90, "Halo Installed Software", "Halo Infinite installed software scan complete");
        }, ct);

    private Task CheckScheduledTaskArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.91, "Halo Scheduled Tasks", "Scanning scheduled tasks for Halo Infinite cheat persistence...");

            var taskDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "System32", "Tasks"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "SysWOW64", "Tasks"),
            };

            var cheatPatterns = new[]
            {
                "halo_cheat", "halo_hack", "halo_aimbot", "halo_loader",
                "halo_injector", "halo_bypass", "halo_spoofer", "halo_driver",
                "halo_eac", "halo_infinite_cheat", "halo_infinite_hack",
                "halo_infinite_loader", "halocheat", "halohack", "halotrainer",
                "hi_cheat", "hi_hack", "hi_loader",
            };

            foreach (var taskDir in taskDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(taskDir)) continue;

                string[] taskFiles;
                try { taskFiles = Directory.GetFiles(taskDir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var taskFile in taskFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var taskName = Path.GetFileName(taskFile).ToLowerInvariant();
                    var matched = cheatPatterns.FirstOrDefault(p =>
                        taskName.Contains(p.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));

                    if (matched is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Halo Infinite Cheat Scheduled Task: {Path.GetFileName(taskFile)}",
                        Risk = RiskLevel.Critical,
                        Location = taskFile,
                        FileName = Path.GetFileName(taskFile),
                        Reason = $"A scheduled task named '{Path.GetFileName(taskFile)}' matches the Halo Infinite cheat pattern '{matched}'. " +
                                 "Cheat loaders use scheduled tasks for persistence, ensuring the cheat or its driver loads " +
                                 "at system boot or before game launch. This is a common technique to survive reboots and " +
                                 "to load kernel-mode cheat drivers before the anti-cheat initializes.",
                        Detail = $"Matched pattern: {matched} · Task file: {taskFile}"
                    });
                }
            }

            ctx.Report(0.95, "Halo Scheduled Tasks", "Halo Infinite scheduled task scan complete");
        }, ct);

    private Task CheckDownloadsFolderArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.96, "Halo Downloads", "Scanning Downloads folder for Halo Infinite cheat artifacts...");

            var downloadsDir = KnownPaths.Downloads;
            if (!Directory.Exists(downloadsDir)) return;

            var allCheatNames = new HashSet<string>(
                CheatExecutableNames
                    .Concat(EacBypassArtifacts)
                    .Concat(XboxGamePassBypassArtifacts)
                    .Concat(XboxOverlayAbuseArtifacts)
                    .Concat(OffsetFileNames)
                    .Concat(CheatConfigFileNames)
                    .Select(n => n.ToLowerInvariant()),
                StringComparer.OrdinalIgnoreCase);

            string[] files;
            try { files = Directory.GetFiles(downloadsDir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                if (allCheatNames.Contains(fileName.ToLowerInvariant()))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Halo Infinite Cheat Artifact in Downloads: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' in the Downloads folder matches a known Halo Infinite cheat artifact. " +
                                 "Downloaded cheat files in the Downloads folder are a primary forensic indicator of cheat acquisition. " +
                                 "Even if the cheat was later moved or installed elsewhere, the downloaded copy proves intent.",
                        Detail = $"Artifact type: Halo Infinite cheat download artifact · Path: {file}"
                    });
                    continue;
                }

                var fileNameLower = fileName.ToLowerInvariant();
                var matchedPattern = TempCheatFilePatterns.FirstOrDefault(p =>
                    fileNameLower.Contains(p.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));

                if (matchedPattern is null) continue;

                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext is not (".exe" or ".dll" or ".sys" or ".zip" or ".rar" or ".7z" or ".tar" or ".gz" or ".json" or ".cfg" or ".ini" or ".txt" or ".h" or ".hpp")) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Halo Infinite Cheat-Related Download: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' in the Downloads folder matches the Halo Infinite cheat file pattern '{matchedPattern}'. " +
                             "Files with Halo Infinite cheat naming patterns found in Downloads indicate recent cheat download activity. " +
                             "Archive files may contain cheat packages; executable files may be ready-to-run cheat tools.",
                    Detail = $"Matched pattern: {matchedPattern} · Path: {file}"
                });
            }

            ctx.Report(1.0, "Halo Downloads", "Halo Infinite Downloads folder scan complete");
        }, ct);

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
}
