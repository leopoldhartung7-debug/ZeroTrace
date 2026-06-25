using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

public sealed class Battlefield2042CheatScanModule : IScanModule
{
    public string Name => "Battlefield 2042 Cheat Forensic Scan";
    public double Weight => 3.4;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] CheatExecutableNames =
    {
        "bf2042_cheat.exe",
        "bf2042_aimbot.exe",
        "bf2042_esp.dll",
        "bf2042_wh.exe",
        "bf2042_hack.exe",
        "bf2042_trigger.exe",
        "bf2042_recoil.exe",
        "bf2042_speed.exe",
        "bf2042_radar.exe",
        "bf2042_radar.html",
        "bf2042_nofall.exe",
        "bf2042_wallhack.dll",
        "battlefield2042_cheat.exe",
        "bf_hack.exe",
        "bf2042_loader.exe",
        "bf2042_injector.exe",
        "bf2042_driver.sys",
        "bf2042_kmode.sys",
        "bf2042_bypass.exe",
        "bf2042_spoofer.exe",
        "bf2042_unlocker.exe",
        "bf2042_softaim.exe",
        "bf2042_silent.exe",
        "bf2042_legit.exe",
        "bf2042_rcs.exe",
        "bf2042_bhop.exe",
        "bf2042_fov.exe",
        "bf2042_distance.exe",
        "bf2042_loot.exe",
        "bf2042_vehicle.exe",
        "bf2042_no_recoil.exe",
        "bf2042_no_spread.exe",
        "bf2042_unlock_all.exe",
        "bf2042_unlock.exe",
        "bf2042_skin.exe",
        "bf2042_gadget.exe",
        "bf2042_super.exe",
        "bf2042_god.exe",
        "bf2042_inf_ammo.exe",
        "bf2042_ammo.exe",
        "bf2042_menu.exe",
        "bf2042_gui.exe",
        "bf2042_internal.dll",
        "bf2042_external.exe",
        "bf2042_d3d.dll",
        "bf2042_dx11.dll",
        "bf2042_dx12.dll",
        "bf2042_render.dll",
        "bf2042_hook.dll",
        "bf2042_patch.exe",
        "bf2042_crack.exe",
        "bf2042_keygen.exe",
        "bf2042trainer.exe",
        "bf2042cheat.exe",
        "bf2042hack.exe",
        "bf2042esp.exe",
        "bf2042aimbot.exe",
        "battlefield_hack.exe",
        "battlefield_cheat.exe",
        "battlefield_aimbot.exe",
        "battlefield2042_hack.exe",
        "bfield2042cheat.exe",
        "bf42hack.exe",
        "bf42cheat.exe",
        "bf42aimbot.exe",
    };

    private static readonly string[] EacBypassArtifacts =
    {
        "bf2042_eac_bypass.dll",
        "eac_bf2042.exe",
        "easyanticheat_bypass_bf2042.dll",
        "eac_bypass_bf2042.exe",
        "bf2042_eac_loader.exe",
        "bf2042_anticheat_bypass.dll",
        "easyanticheat_bf2042.dll",
        "eac_bf2042_patcher.exe",
        "bf2042_eac_patcher.exe",
        "bf2042_eac_hook.dll",
        "eac_hook_bf2042.dll",
        "bf2042_eac_spoof.exe",
        "eac_spoof_bf2042.dll",
        "bf2042_eac_disable.exe",
        "bf2042_eac_kill.exe",
        "easyanticheat_patcher.exe",
        "eac_patcher_bf2042.dll",
        "bf2042_eac_patch.dat",
        "eac_bypass_loader.exe",
        "bf2042_cheat_driver.sys",
        "bf2042_km_bypass.sys",
        "bf2042_kmode_bypass.sys",
        "battlefield2042_eac_bypass.dll",
    };

    private static readonly string[] OriginEaBypassArtifacts =
    {
        "ea_app_bypass.exe",
        "origin_bypass.exe",
        "ea_bypass.dll",
        "origin_hook.dll",
        "ea_crack.exe",
        "origin_crack.exe",
        "ea_emulator.dll",
        "origin_emulator.dll",
        "ea_patcher.exe",
        "origin_patcher.exe",
        "ea_spoofer.exe",
        "origin_spoofer.exe",
        "ea_token_stealer.exe",
        "origin_token_bypass.dll",
        "ea_account_bypass.exe",
        "ea_app_hook.dll",
        "origin_offline.exe",
        "ea_offline.exe",
        "ea_dlc_unlocker.exe",
        "origin_dlc_unlocker.exe",
        "bf2042_origin_bypass.dll",
        "bf2042_ea_bypass.dll",
        "ealauncher_bypass.exe",
        "bf2042_drm_bypass.exe",
        "denuvo_bypass_bf2042.exe",
        "denuvo_crack_bf2042.exe",
    };

    private static readonly string[] CheatConfigFileNames =
    {
        "bf2042_cheat_config.json",
        "bf2042_config.cfg",
        "bf2042_settings.json",
        "bf2042_aimbot.cfg",
        "bf2042_esp.cfg",
        "bf2042_wallhack.cfg",
        "bf2042_triggerbot.cfg",
        "bf2042_recoil.cfg",
        "bf2042_menu.json",
        "bf2042_cheat.ini",
        "bf2042_hack.ini",
        "bf2042_options.json",
        "bf2042_profile.json",
        "bf2042_keys.json",
        "bf2042_hotkeys.cfg",
        "bf2042_loot.json",
        "bf2042_vehicle.json",
        "bf2042_colors.json",
        "bf2042_esp_colors.json",
        "bf2042_bones.json",
        "cheat_config_bf2042.json",
        "hack_config_bf2042.json",
        "bf2042_internal_config.json",
        "bf2042_external_config.json",
        "bf42_cheat.cfg",
        "bf42_aimbot.cfg",
    };

    private static readonly string[] OffsetFileNames =
    {
        "bf2042_offsets.json",
        "bf2042_addresses.txt",
        "bf2042_bone_ids.json",
        "bf2042_patterns.txt",
        "bf2042_signatures.json",
        "bf2042_ptrs.json",
        "bf2042_netvar.json",
        "bf2042_sdk.hpp",
        "bf2042_sdk.h",
        "bf2042_sdk.cpp",
        "bf2042_offsets.h",
        "bf2042_offsets.hpp",
        "bf2042_offsets.txt",
        "bf2042_dump.json",
        "bf2042_dump.txt",
        "bf2042_structs.json",
        "bf2042_structs.h",
        "bf2042_classes.hpp",
        "bf2042_mem.json",
        "bf2042_memory.json",
        "bf2042_base.txt",
        "bf2042_gamebase.txt",
        "bf2042_entitylist.txt",
        "bf2042_localplayer.txt",
        "bf2042_viewmatrix.txt",
        "bf2042_viewangles.txt",
        "bf2042_bones.txt",
        "bf2042_weapon.txt",
        "bf2042_ammo.txt",
        "bf2042_vehicle_offsets.json",
        "bf2042_render_offset.txt",
        "bf_offsets.json",
        "bf_addresses.txt",
        "battlefield2042_offsets.json",
    };

    private static readonly string[] ProconOverlayArtifacts =
    {
        "bf2042_procon.exe",
        "bf2042_procon_bypass.exe",
        "bf2042_server_overlay.exe",
        "bf2042_scoreboard_hack.exe",
        "bf2042_server_browser_hack.exe",
        "bf2042_hackerlist.txt",
        "bf2042_report_bypass.exe",
        "bf2042_admin_bypass.exe",
        "bf2042_punkbuster_bypass.exe",
        "bf2042_fairfight_bypass.exe",
        "bf2042_fairfight_hook.dll",
        "fairfight_bypass_bf2042.exe",
        "bf2042_portal_bypass.exe",
        "bf2042_hazardzone_cheat.exe",
        "bf2042_breakthrough_hack.exe",
        "bf2042_conquest_hack.exe",
        "bf2042_sector_hack.exe",
    };

    private static readonly string[] CheatKeywordsInConfigs =
    {
        "aimbot", "triggerbot", "wallhack", "wallhacks", "esp", "norecoil", "no_recoil",
        "nospread", "no_spread", "nofall", "no_fall", "bhop", "bunny_hop", "speedhack",
        "god_mode", "godmode", "infinite_ammo", "inf_ammo", "unlock_all", "skinchanger",
        "silent_aim", "silentaim", "fov_aimbot", "bone_aimbot", "head_aimbot",
        "smoothness", "aim_smooth", "aim_fov", "aim_bone", "aim_key", "aimkey",
        "draw_esp", "draw_box", "draw_skeleton", "draw_health", "draw_distance",
        "vehicle_esp", "vehicle_hack", "radar_hack", "radar_overlay", "cheat_enabled",
        "bypass_enabled", "eac_bypass", "anticheat_bypass",
    };

    private static readonly string[] UserAssistCheatNames =
    {
        "bf2042_cheat",
        "bf2042_aimbot",
        "bf2042_hack",
        "bf2042_esp",
        "bf2042_wh",
        "bf2042_trigger",
        "bf2042_recoil",
        "bf2042_speed",
        "bf2042_radar",
        "bf2042_nofall",
        "bf2042_loader",
        "bf2042_injector",
        "bf2042_bypass",
        "bf2042_spoofer",
        "bf2042_unlock",
        "battlefield2042_cheat",
        "bf_hack",
        "bf2042_eac_bypass",
        "eac_bf2042",
        "bf2042trainer",
        "bf2042cheat",
        "bf2042hack",
    };

    private static readonly string[] RunKeyCheatPatterns =
    {
        "bf2042_cheat",
        "bf2042_aimbot",
        "bf2042_hack",
        "bf2042_loader",
        "bf2042_injector",
        "bf2042_bypass",
        "bf2042_spoofer",
        "bf2042_driver",
        "bf2042_kmode",
        "bf2042_eac",
        "battlefield2042_cheat",
        "bf_hack",
        "bf2042trainer",
    };

    private static readonly string[] TempCheatFilePatterns =
    {
        "bf2042_cheat",
        "bf2042_aimbot",
        "bf2042_hack",
        "bf2042_esp",
        "bf2042_loader",
        "bf2042_injector",
        "bf2042_bypass",
        "bf2042_spoofer",
        "bf2042_radar",
        "bf2042_offsets",
        "bf2042_dump",
        "bf2042_sdk",
        "bf2042_update",
        "bf2042_patch",
        "bf2042_crack",
        "bf2042_keygen",
        "bf2042_unpack",
        "bf2042_extract",
        "bf2042_install",
        "bf2042_setup",
        "bf2042_payload",
        "bf2042_kernel",
        "bf2042_km_",
        "battlefield2042_cheat",
        "battlefield2042_hack",
        "bf42cheat",
        "bf42hack",
        "bf42aimbot",
    };

    private static readonly string[] Bf2042LogCheatPatterns =
    {
        "cheat", "aimbot", "wallhack", "triggerbot", "esp", "norecoil",
        "no_recoil", "bypass", "injector", "loader", "exploit", "hack",
        "speedhack", "nofall", "godmode", "god_mode", "unlock_all",
        "silent_aim", "silentaim", "radar_hack", "bhop", "bunny_hop",
        "vehicle_hack", "eac_bypass", "anticheat_bypass", "fairfight_bypass",
        "offset_dump", "memory_read", "process_inject", "dll_inject",
        "kernel_driver", "km_cheat", "dma_cheat",
    };

    private static readonly string[] SuspiciousRegistryValuePatterns =
    {
        "bf2042_cheat",
        "bf2042_aimbot",
        "bf2042_hack",
        "bf2042_esp",
        "bf2042_wallhack",
        "bf2042_triggerbot",
        "bf2042_loader",
        "bf2042_injector",
        "bf2042_bypass",
        "bf2042_spoofer",
        "bf2042_eac_bypass",
        "eac_bf2042",
        "battlefield2042_cheat",
        "bf_hack",
        "bf2042trainer",
    };

    private static readonly string[] KnownCheatFolderNames =
    {
        "bf2042_cheat",
        "bf2042_aimbot",
        "bf2042_hack",
        "bf2042_esp",
        "bf2042_loader",
        "bf2042_injector",
        "bf2042cheat",
        "bf2042hack",
        "bf2042aimbot",
        "bf2042esp",
        "bf42cheat",
        "bf42hack",
        "battlefield2042_cheat",
        "bf2042_tools",
        "bf2042_bypass",
        "bf2042_spoofer",
    };

    private static readonly string[] SteamOverlaySuspiciousPatterns =
    {
        "bf2042_steam_inject",
        "steam_bf2042_bypass",
        "bf2042_steamoverlay_hook",
        "bf2042_overlay_hack",
        "steam_overlay_bf2042",
        "bf2042_steamapi_hook",
        "steamapi_bf2042_bypass",
    };

    private static readonly string[] MuiCacheCheatPatterns =
    {
        "bf2042_cheat",
        "bf2042_aimbot",
        "bf2042_hack",
        "bf2042_esp",
        "bf2042_wh",
        "bf2042_trigger",
        "bf2042_recoil",
        "bf2042_speed",
        "bf2042_radar",
        "bf2042_nofall",
        "bf2042_loader",
        "bf2042_injector",
        "bf2042_bypass",
        "bf2042_spoofer",
        "bf2042_unlock",
        "battlefield2042_cheat",
        "battlefield2042_hack",
        "bf_hack",
        "bf2042_eac_bypass",
        "eac_bf2042",
        "bf2042trainer",
        "bf2042cheat",
        "bf2042hack",
        "bf2042aimbot",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.WhenAll(
            CheckCheatExecutables(ctx, ct),
            CheckEacBypassArtifacts(ctx, ct),
            CheckOriginEaBypassArtifacts(ctx, ct),
            CheckProconOverlayArtifacts(ctx, ct),
            CheckCheatConfigFiles(ctx, ct),
            CheckOffsetFiles(ctx, ct),
            CheckUserAssistRegistry(ctx, ct),
            CheckMuiCacheRegistry(ctx, ct),
            CheckRunKeyRegistry(ctx, ct),
            CheckTempFolderArtifacts(ctx, ct),
            CheckBf2042LogFiles(ctx, ct),
            CheckKnownCheatFolders(ctx, ct),
            CheckSteamOverlayArtifacts(ctx, ct),
            CheckInstalledSoftwareRegistry(ctx, ct),
            CheckScheduledTaskArtifacts(ctx, ct),
            CheckDownloadsFolderArtifacts(ctx, ct)
        );
    }

    private Task CheckCheatExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.02, "BF2042 Cheat EXEs", "Scanning for BF2042 cheat executables...");

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
                @"C:\BF2042",
                @"C:\bf2042_cheat",
                @"C:\bf2042",
                @"C:\cheats",
                @"C:\hacks",
                @"C:\tools",
            };

            var steamDir = KnownPaths.FindSteamDirectory();
            if (steamDir is not null)
                searchRoots.Add(steamDir);

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
                        Title = $"BF2042 Cheat Executable Found: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' at '{file}' matches a known Battlefield 2042 cheat executable name. " +
                                 "This artifact indicates the presence of cheat software targeting Battlefield 2042. " +
                                 "Known cheat tools with this exact filename have been observed in cheat distribution channels.",
                        Detail = $"Artifact type: BF2042 cheat executable · Path: {file}"
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
                            Title = $"BF2042 Cheat Executable Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"The file '{fileName}' at '{file}' matches a known Battlefield 2042 cheat executable name. " +
                                     "This artifact indicates the presence of cheat software targeting Battlefield 2042.",
                            Detail = $"Artifact type: BF2042 cheat executable · Path: {file}"
                        });
                    }
                }
            }

            ctx.Report(0.08, "BF2042 Cheat EXEs", "BF2042 cheat executable scan complete");
        }, ct);

    private Task CheckEacBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.10, "BF2042 EAC Bypass", "Scanning for BF2042 EasyAntiCheat bypass artifacts...");

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
                var eacSteam = Path.Combine(steamDir, "steamapps", "common", "Battlefield 2042", "EasyAntiCheat");
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
                        Title = $"BF2042 EAC Bypass Artifact: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' is a known EasyAntiCheat bypass artifact targeting Battlefield 2042. " +
                                 "EAC bypass tools are used to disable or circumvent the anti-cheat system, " +
                                 "allowing cheats to operate undetected. This artifact strongly indicates cheat usage.",
                        Detail = $"Artifact type: EAC bypass · Path: {file}"
                    });
                }
            }

            ctx.Report(0.16, "BF2042 EAC Bypass", "BF2042 EAC bypass scan complete");
        }, ct);

    private Task CheckOriginEaBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.18, "BF2042 EA/Origin Bypass", "Scanning for Origin/EA App bypass artifacts...");

            var bypassNamesLower = new HashSet<string>(
                OriginEaBypassArtifacts.Select(n => n.ToLowerInvariant()),
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
                @"C:\Program Files (x86)\Origin",
                @"C:\Program Files\Origin",
                Path.Combine(KnownPaths.LocalAppData, "Origin"),
                Path.Combine(KnownPaths.RoamingAppData, "Origin"),
                Path.Combine(KnownPaths.LocalAppData, "Electronic Arts"),
                Path.Combine(KnownPaths.RoamingAppData, "Electronic Arts"),
                @"C:\Program Files\EA Games",
                @"C:\Program Files (x86)\EA Games",
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
                        Title = $"BF2042 EA/Origin Bypass Artifact: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' is a known EA App or Origin platform bypass artifact. " +
                                 "Such tools are used to bypass EA's DRM, authentication, or platform restrictions " +
                                 "that protect Battlefield 2042, commonly paired with cheat software. " +
                                 "This artifact is a strong forensic indicator of unauthorized play session manipulation.",
                        Detail = $"Artifact type: EA/Origin bypass · Path: {file}"
                    });
                }
            }

            ctx.Report(0.23, "BF2042 EA/Origin Bypass", "BF2042 EA/Origin bypass scan complete");
        }, ct);

    private Task CheckProconOverlayArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.25, "BF2042 Procon/Server Overlay", "Scanning for BF2042 server overlay bypass artifacts...");

            var artifactNamesLower = new HashSet<string>(
                ProconOverlayArtifacts.Select(n => n.ToLowerInvariant()),
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
                Path.Combine(KnownPaths.RoamingAppData, "PRoCon"),
                Path.Combine(KnownPaths.LocalAppData, "PRoCon"),
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
                        Title = $"BF2042 Server Overlay/Procon Bypass: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' matches a known Battlefield 2042 server overlay or Procon bypass artifact. " +
                                 "These tools can be used to manipulate server-side protections, abuse admin interfaces, " +
                                 "or inject fake scoring and events into Battlefield 2042 server sessions.",
                        Detail = $"Artifact type: BF2042 server overlay/Procon bypass · Path: {file}"
                    });
                }
            }

            ctx.Report(0.30, "BF2042 Procon/Server Overlay", "BF2042 server overlay bypass scan complete");
        }, ct);

    private Task CheckCheatConfigFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.32, "BF2042 Cheat Configs", "Scanning for BF2042 cheat configuration files...");

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
                Path.Combine(KnownPaths.LocalAppData, "Battlefield 2042"),
                Path.Combine(KnownPaths.RoamingAppData, "Battlefield 2042"),
                Path.Combine(KnownPaths.LocalAppData, "Battlefield"),
                Path.Combine(KnownPaths.RoamingAppData, "Battlefield"),
            };

            var steamDir = KnownPaths.FindSteamDirectory();
            if (steamDir is not null)
            {
                searchRoots.Add(Path.Combine(steamDir, "steamapps", "common", "Battlefield 2042"));
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
                            Title = $"BF2042 Cheat Config File: {fileName}",
                            Risk = hasCheatKeyword ? RiskLevel.Critical : RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"The file '{fileName}' matches a known Battlefield 2042 cheat configuration filename. " +
                                     (hasCheatKeyword
                                         ? "The file content also contains known cheat configuration keywords, confirming its nature as a cheat config file. "
                                         : "The filename itself strongly indicates a cheat configuration artifact. ") +
                                     "Cheat config files store aimbot settings, ESP colors, keybinds, and bypass options.",
                            Detail = $"Artifact type: BF2042 cheat config · Keywords found: {hasCheatKeyword} · Path: {file}"
                        });
                        continue;
                    }

                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext is not (".cfg" or ".ini" or ".json")) continue;

                    if (!fileName.StartsWith("bf2042", StringComparison.OrdinalIgnoreCase) &&
                        !fileName.StartsWith("bf42", StringComparison.OrdinalIgnoreCase) &&
                        !fileName.StartsWith("battlefield2042", StringComparison.OrdinalIgnoreCase))
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
                        Title = $"BF2042 Config File with Cheat Keywords: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The config file '{fileName}' contains the cheat-related keyword '{matchedKeyword}'. " +
                                 "Config files with BF2042-related names that contain cheat keywords are artifacts " +
                                 "of cheat tools that store their settings alongside game configuration.",
                        Detail = $"Keyword found: '{matchedKeyword}' · Path: {file}"
                    });
                }
            }

            ctx.Report(0.38, "BF2042 Cheat Configs", "BF2042 cheat config scan complete");
        }, ct);

    private Task CheckOffsetFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.40, "BF2042 Offset Files", "Scanning for BF2042 memory offset/address files...");

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
                        Title = $"BF2042 Offset/Address File: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' matches a known Battlefield 2042 memory offset or address dump file. " +
                                 "Offset files contain game memory layout information (entity list offsets, bone matrix addresses, " +
                                 "view matrix, local player, weapon data) required to build or run cheat software. " +
                                 "These files are exclusively created by cheat developers and users performing game memory analysis.",
                        Detail = $"Artifact type: BF2042 offset/address dump · Path: {file}"
                    });
                }
            }

            ctx.Report(0.45, "BF2042 Offset Files", "BF2042 offset file scan complete");
        }, ct);

    private Task CheckUserAssistRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.47, "BF2042 UserAssist", "Scanning UserAssist registry for BF2042 cheat execution history...");

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
                            Title = $"BF2042 Cheat Executed (UserAssist): {Path.GetFileName(decoded)}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason = $"UserAssist registry records the execution of '{decoded}', which matches the known BF2042 cheat name pattern '{matched}'. " +
                                     "UserAssist logs GUI application launches; this entry proves the cheat executable was run on this system, " +
                                     "even if the file has since been deleted.",
                            Detail = $"Decoded name: {decoded} · Last run: {(lastRun.HasValue ? lastRun.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm") : "unknown")} · ROT13 source: {valueName}"
                        });
                    }
                }
            }
            catch { }

            ctx.Report(0.52, "BF2042 UserAssist", "BF2042 UserAssist scan complete");
        }, ct);

    private Task CheckMuiCacheRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.53, "BF2042 MUICache", "Scanning MUICache registry for BF2042 cheat artifacts...");

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
                            Title = $"BF2042 Cheat in MUICache: {Path.GetFileName(val)}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\{regPath}",
                            FileName = Path.GetFileName(val),
                            Reason = $"MUICache contains a reference to '{val}', which matches the BF2042 cheat pattern '{matched}'. " +
                                     "MUICache records the display names of executables that were launched in the Windows shell. " +
                                     "This proves the cheat executable was run on this system.",
                            Detail = $"Registry path: HKCU\\{regPath} · Value: {val} · Matched pattern: {matched}"
                        });
                    }
                }
                catch { }
            }

            ctx.Report(0.57, "BF2042 MUICache", "BF2042 MUICache scan complete");
        }, ct);

    private Task CheckRunKeyRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.58, "BF2042 Run Keys", "Scanning registry Run keys for BF2042 cheat persistence...");

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
                                Title = $"BF2042 Cheat Autostart (Run Key): {valName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"{(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM")}\{runPath}",
                                FileName = valName,
                                Reason = $"Registry Run key '{valName}' = '{valData}' matches BF2042 cheat pattern '{matched}'. " +
                                         "A Run key entry causes the referenced program to execute at user login. " +
                                         "BF2042 cheat loaders and kernel drivers use Run keys to ensure they start automatically " +
                                         "before Battlefield 2042 launches.",
                                Detail = $"Hive: {(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM")} · Key: {runPath} · Value: {valName} = {valData}"
                            });
                        }
                    }
                    catch { }
                }
            }

            ctx.Report(0.62, "BF2042 Run Keys", "BF2042 Run key scan complete");
        }, ct);

    private Task CheckTempFolderArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.63, "BF2042 Temp Artifacts", "Scanning temp folders for BF2042 cheat artifacts...");

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
                        Title = $"BF2042 Cheat Artifact in Temp: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"A file matching the BF2042 cheat pattern '{matched}' was found in a temporary folder at '{file}'. " +
                                 "Cheat loaders and installers commonly drop payloads into temp directories before injection or installation. " +
                                 "Temp-resident cheat artifacts may indicate an in-progress or recently completed cheat deployment.",
                        Detail = $"Artifact type: BF2042 temp cheat file · Matched pattern: {matched} · Path: {file}"
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
                            Title = $"BF2042 Cheat Folder in Temp: {Path.GetFileName(sub)}",
                            Risk = RiskLevel.High,
                            Location = sub,
                            FileName = Path.GetFileName(sub),
                            Reason = $"A directory matching BF2042 cheat pattern '{dirMatched}' was found in a temporary folder. " +
                                     "Cheat software frequently creates subdirectories in temp for storing unpacked components, " +
                                     "driver files, or configuration data during or after installation.",
                            Detail = $"Artifact type: BF2042 temp cheat folder · Matched: {dirMatched} · Path: {sub}"
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
                            Title = $"BF2042 Cheat File in Temp Subfolder: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"A file matching BF2042 cheat pattern '{fileMatched}' was found in a temp subdirectory. " +
                                     "This is consistent with cheat installer or loader activity.",
                            Detail = $"Matched pattern: {fileMatched} · Path: {file}"
                        });
                    }
                }
            }

            ctx.Report(0.68, "BF2042 Temp Artifacts", "BF2042 temp folder scan complete");
        }, ct);

    private Task CheckBf2042LogFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            ctx.Report(0.70, "BF2042 Log Files", "Scanning BF2042 log files for cheat-related patterns...");

            var bf2042LogDirs = new List<string>
            {
                Path.Combine(KnownPaths.LocalAppData, "Battlefield 2042"),
                Path.Combine(KnownPaths.RoamingAppData, "Battlefield 2042"),
                Path.Combine(KnownPaths.LocalAppData, "Battlefield"),
                Path.Combine(KnownPaths.RoamingAppData, "Battlefield"),
                Path.Combine(KnownPaths.LocalAppData, "Origin", "Battlefield 2042"),
                Path.Combine(KnownPaths.RoamingAppData, "Origin", "Battlefield 2042"),
                Path.Combine(KnownPaths.LocalAppData, "Electronic Arts", "Battlefield 2042"),
                Path.Combine(KnownPaths.RoamingAppData, "Electronic Arts", "Battlefield 2042"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Documents", "Battlefield 2042"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Documents", "Battlefield"),
            };

            var steamDir = KnownPaths.FindSteamDirectory();
            if (steamDir is not null)
            {
                bf2042LogDirs.Add(Path.Combine(steamDir, "steamapps", "common", "Battlefield 2042"));
                bf2042LogDirs.Add(Path.Combine(steamDir, "logs"));
            }

            foreach (var logDir in bf2042LogDirs)
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

                    var matchedPatterns = Bf2042LogCheatPatterns
                        .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchedPatterns.Count == 0) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"BF2042 Log Contains Cheat Patterns: {Path.GetFileName(logFile)}",
                        Risk = RiskLevel.High,
                        Location = logFile,
                        FileName = Path.GetFileName(logFile),
                        Reason = $"The Battlefield 2042 log file '{logFile}' contains cheat-related keywords: " +
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

                    var matchedPatterns = Bf2042LogCheatPatterns
                        .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchedPatterns.Count < 2) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"BF2042 Text File with Cheat Keywords: {Path.GetFileName(txtFile)}",
                        Risk = RiskLevel.Medium,
                        Location = txtFile,
                        FileName = Path.GetFileName(txtFile),
                        Reason = $"A text file in the Battlefield 2042 data directory contains multiple cheat-related keywords: " +
                                 $"{string.Join(", ", matchedPatterns.Take(5).Select(p => $"'{p}'"))}. " +
                                 "This may indicate a cheat's own log file or output file left in the BF2042 data directory.",
                        Detail = $"Matched patterns: {string.Join(", ", matchedPatterns.Take(10))} · File: {txtFile}"
                    });
                }
            }

            ctx.Report(0.75, "BF2042 Log Files", "BF2042 log file scan complete");
        }, ct);

    private Task CheckKnownCheatFolders(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.77, "BF2042 Cheat Folders", "Scanning for known BF2042 cheat installation directories...");

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
                        Title = $"Known BF2042 Cheat Directory: {dirName}",
                        Risk = RiskLevel.Critical,
                        Location = dir,
                        FileName = dirName,
                        Reason = $"The directory '{dirName}' at '{dir}' matches a known Battlefield 2042 cheat installation folder name. " +
                                 "Cheat software typically creates named directories for storing executables, configs, and DLLs. " +
                                 "This directory name is associated with known BF2042 cheat packages.",
                        Detail = $"Matched folder pattern: {matched} · Full path: {dir}"
                    });
                }
            }

            ctx.Report(0.81, "BF2042 Cheat Folders", "BF2042 cheat folder scan complete");
        }, ct);

    private Task CheckSteamOverlayArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.82, "BF2042 Steam Overlay", "Scanning for BF2042 Steam overlay abuse artifacts...");

            var artifactNamesLower = new HashSet<string>(
                SteamOverlaySuspiciousPatterns.Select(n => n.ToLowerInvariant()),
                StringComparer.OrdinalIgnoreCase);

            var steamDir = KnownPaths.FindSteamDirectory();
            var searchRoots = new List<string>
            {
                KnownPaths.Downloads,
                KnownPaths.LocalAppData,
                KnownPaths.Temp,
                Path.Combine(KnownPaths.LocalAppData, "Temp"),
            };
            if (steamDir is not null)
            {
                searchRoots.Add(steamDir);
                searchRoots.Add(Path.Combine(steamDir, "steamapps", "common", "Battlefield 2042"));
                searchRoots.Add(Path.Combine(steamDir, "steamapps", "common"));
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
                    if (!artifactNamesLower.Contains(fileName.ToLowerInvariant())) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"BF2042 Steam Overlay Abuse Artifact: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' matches a known artifact of Steam overlay injection or hooking targeting Battlefield 2042. " +
                                 "Cheats that abuse the Steam overlay can inject code into the game process using the overlay's rendering pipeline, " +
                                 "bypassing injection detection that watches for standard injection methods.",
                        Detail = $"Artifact type: BF2042 Steam overlay abuse · Path: {file}"
                    });
                }
            }

            ctx.Report(0.86, "BF2042 Steam Overlay", "BF2042 Steam overlay artifact scan complete");
        }, ct);

    private Task CheckInstalledSoftwareRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.87, "BF2042 Installed Software", "Scanning installed software registry for BF2042 cheat entries...");

            var uninstallPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };

            var cheatNameFragments = new[]
            {
                "bf2042_cheat", "bf2042_hack", "bf2042_aimbot", "bf2042_esp",
                "bf2042_loader", "bf2042_injector", "bf2042_bypass", "bf2042_spoofer",
                "bf2042_trainer", "battlefield2042_cheat", "bf2042 cheat", "bf2042 hack",
                "bf2042 aimbot", "bf2042 trainer", "battlefield 2042 cheat",
                "bf42cheat", "bf42hack", "bf2042_eac_bypass",
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
                                    Title = $"BF2042 Cheat in Installed Programs: {displayName}",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"{(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM")}\{uninstallPath}\{subName}",
                                    FileName = subName,
                                    Reason = $"The installed programs registry contains an entry '{displayName}' matching BF2042 cheat pattern '{matched}'. " +
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

            ctx.Report(0.91, "BF2042 Installed Software", "BF2042 installed software scan complete");
        }, ct);

    private Task CheckScheduledTaskArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.92, "BF2042 Scheduled Tasks", "Scanning scheduled tasks for BF2042 cheat persistence...");

            var taskDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "System32", "Tasks"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "SysWOW64", "Tasks"),
            };

            var cheatPatterns = new[]
            {
                "bf2042_cheat", "bf2042_hack", "bf2042_aimbot", "bf2042_loader",
                "bf2042_injector", "bf2042_bypass", "bf2042_spoofer", "bf2042_driver",
                "bf2042_eac", "battlefield2042_cheat", "bf_hack", "bf2042trainer",
                "bf2042cheat", "bf2042aimbot",
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
                        Title = $"BF2042 Cheat Scheduled Task: {Path.GetFileName(taskFile)}",
                        Risk = RiskLevel.Critical,
                        Location = taskFile,
                        FileName = Path.GetFileName(taskFile),
                        Reason = $"A scheduled task named '{Path.GetFileName(taskFile)}' matches the BF2042 cheat pattern '{matched}'. " +
                                 "Cheat loaders use scheduled tasks for persistence, ensuring the cheat or its driver loads " +
                                 "at system boot or before game launch. This is a common technique to survive reboots.",
                        Detail = $"Matched pattern: {matched} · Task file: {taskFile}"
                    });
                }
            }

            ctx.Report(0.95, "BF2042 Scheduled Tasks", "BF2042 scheduled task scan complete");
        }, ct);

    private Task CheckDownloadsFolderArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.96, "BF2042 Downloads", "Scanning Downloads folder for BF2042 cheat artifacts...");

            var downloadsDir = KnownPaths.Downloads;
            if (!Directory.Exists(downloadsDir)) return;

            var allCheatNames = new HashSet<string>(
                CheatExecutableNames
                    .Concat(EacBypassArtifacts)
                    .Concat(OriginEaBypassArtifacts)
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
                        Title = $"BF2042 Cheat Artifact in Downloads: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' in the Downloads folder matches a known Battlefield 2042 cheat artifact. " +
                                 "Downloaded cheat files in the Downloads folder are a primary forensic indicator of cheat acquisition. " +
                                 "Even if the cheat was later moved or installed elsewhere, the downloaded copy proves intent.",
                        Detail = $"Artifact type: BF2042 cheat download artifact · Path: {file}"
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
                    Title = $"BF2042 Cheat-Related Download: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' in the Downloads folder matches the BF2042 cheat file pattern '{matchedPattern}'. " +
                             "Files with BF2042 cheat naming patterns found in Downloads indicate recent cheat download activity. " +
                             "Archive files may contain cheat packages; executable files may be ready-to-run cheat tools.",
                    Detail = $"Matched pattern: {matchedPattern} · Path: {file}"
                });
            }

            ctx.Report(1.0, "BF2042 Downloads", "BF2042 Downloads folder scan complete");
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
