using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class ValorantCheatScanModule : IScanModule
{
    public string Name => "Valorant Cheat Deep Scan";
    public double Weight => 4.0;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] KnownCheatFileNames =
    [
        // Vanguard bypass tools
        "vanguard_bypass.exe", "vgc_kill.exe", "vgk_bypass.dll",
        "vanguard_bypass.dll", "vgc_bypass.exe", "vgk_kill.exe",
        "vanguard_disable.exe", "vgc_disable.dll", "vgk_disable.exe",
        "anti_vanguard.exe", "vanguard_hook.dll", "vgc_hook.dll",
        "vgk_hook.dll", "vanguard_patch.exe", "vgc_patch.dll",
        "vgk_patch.exe", "vanguard_loader.exe", "vanguard_spoof.dll",
        "vgk_spoof.dll", "vanguard_unload.exe", "vgc_unload.exe",
        "vgk_unload.dll", "bypass_vanguard.exe", "kill_vanguard.exe",
        "disable_vanguard.exe", "vanguard_remover.exe", "vgremover.exe",
        "vanguard_injector.dll", "vgc_injector.exe",
        // Aimbot tools
        "valorant_aim.exe", "aim_valorant.dll", "val_aimbot.exe",
        "valorant_aimbot.exe", "val_aim.dll", "valo_aimbot.exe",
        "valo_aim.dll", "valorant_silent_aim.exe", "val_silent_aim.dll",
        "valorant_legit_aim.exe", "val_legit_aim.dll", "valorant_rage_aim.exe",
        "valorant_aim_assist.exe", "val_aim_assist.dll", "valo_aim_assist.exe",
        "valorant_fov_aim.dll", "valorant_bone_aim.dll", "valorant_predict_aim.dll",
        "val_prediction.dll", "valorant_smooth_aim.dll", "val_smooth.dll",
        "valo_silentaim.dll", "val_novischeck.dll", "valorant_novis.dll",
        "valorant_triggerbot.exe", "val_triggerbot.dll", "valo_triggerbot.exe",
        // Wallhack / ESP tools
        "val_esp.dll", "valorant_wh.exe", "valo_esp.exe",
        "valorant_esp.dll", "val_wallhack.exe", "valo_wallhack.dll",
        "valorant_esp_box.dll", "val_esp_health.dll", "valo_esp_bone.dll",
        "valorant_chams.dll", "val_glow.dll", "valo_glow.exe",
        "valorant_vischeck_bypass.dll", "val_visibility.dll", "valo_xray.dll",
        "valorant_distance_esp.dll", "val_item_esp.dll", "valo_radar.dll",
        "valorant_sound_esp.dll", "val_footstep_esp.dll",
        // Trigger bot
        "val_trigger.exe", "trigger_valorant.dll", "valo_trigger.exe",
        "val_auto_trigger.dll", "valorant_auto_shoot.exe", "val_clickbot.dll",
        // Skin changers
        "val_skin.exe", "valorant_skins.dll", "val_skinchanger.exe",
        "valorant_skin_changer.dll", "valo_skins.exe", "val_knife.dll",
        "valorant_knife_changer.exe", "val_buddy.dll", "valo_knife.exe",
        "val_gun_buddy.dll", "valorant_skin_unlocker.exe", "val_card.dll",
        "valorant_playercard.dll", "val_spray.dll", "val_title.dll",
        "valorant_unlock_all.exe", "val_inventory_unlock.dll",
        // HWID spoofer / ban evasion
        "riot_hwid_spoofer.exe", "val_hwid_spoofer.dll", "valo_spoofer.exe",
        "riot_spoofer.exe", "valorant_spoofer.exe", "val_ban_evasion.exe",
        "riot_ban_bypass.exe", "val_unban.exe", "valo_unban.exe",
        "riot_account_bypass.dll", "val_id_change.exe",
        // Riot client bypass
        "riot_bypass.exe", "riot_client_bypass.dll", "riotclient_bypass.exe",
        "riot_launch_bypass.exe", "riot_auth_bypass.dll",
        "riot_client_hook.dll", "riotclient_hook.exe",
        "riot_client_patch.dll", "riot_services_bypass.exe",
        // Loaders / injectors
        "val_loader.exe", "valorant_loader.exe", "valo_loader.exe",
        "val_injector.exe", "valorant_injector.exe", "valo_injector.dll",
        "valorant_hack.dll", "val_hack.dll", "valo_cheat.dll",
        "valorant_internal.dll", "val_external.exe", "valo_external.dll",
        "valorant_driver.sys", "val_memory.dll", "valo_memory.exe",
        // Other known cheat files
        "vncheat.dll", "vncheat.exe", "valo_hvh.dll", "val_hvh.exe",
        "valorant_no_recoil.dll", "val_rcs.dll", "valo_rcs.exe",
        "valorant_backtrack.dll", "val_resolver.dll", "valo_resolver.exe",
        "val_antiaim.dll", "valorant_antiaim.dll", "valo_fakelag.dll",
        "val_offsets.dll", "valorant_offsets.dll", "val_sdk.dll",
        "valorant_cheat.dll", "valorant_cheat.exe", "val_cheat.dll",
    ];

    private static readonly string[] KnownCheatProcessNames =
    [
        "valorant_hack", "valo_cheat", "vncheat", "valorant_esp",
        "valo_aim", "val_aimbot", "valorant_aimbot", "val_esp",
        "valo_esp", "val_wallhack", "valorant_wallhack", "valo_wallhack",
        "val_trigger", "valo_triggerbot", "val_skinchanger", "valo_skins",
        "vanguard_bypass", "vgc_kill", "vgk_bypass", "val_loader",
        "valorant_loader", "valo_loader", "val_injector", "valorant_injector",
        "riot_bypass", "riot_hwid_spoofer", "val_spoofer", "valo_spoofer",
        "val_hack", "valo_hack", "valorant_driver", "val_memory",
        "valo_memory", "val_resolver", "valo_resolver", "val_antiaim",
        "valo_antiaim", "val_external", "valo_external",
    ];

    private static readonly string[] VgkBypassDriverNames =
    [
        "vgk_bypass.sys", "vanguard_bypass.sys", "vgc_bypass.sys",
        "vgk_hook.sys", "vanguard_hook.sys", "anti_vgk.sys",
        "vgk_kill.sys", "vgk_disable.sys", "vanguard_disable.sys",
        "vgk_spoof.sys", "vanguard_spoof.sys", "bypass_vgk.sys",
        "vgk_patch.sys", "vanguard_patch.sys", "vgk_unload.sys",
        "riot_bypass.sys", "riot_kernel.sys",
    ];

    private static readonly string[] SuspiciousLogKeywords =
    [
        "vanguard bypass", "vgk bypass", "vanguard disabled",
        "vgc stopped", "kernel tamper", "driver bypass",
        "aim assist enabled", "esp enabled", "wallhack enabled",
        "triggerbot enabled", "silent aim enabled", "aimbot loaded",
        "cheat loaded", "hook installed", "dll injected",
        "memory read valorant", "valorant memory", "valo hack",
        "skin changer loaded", "unlock all skins", "knife changer",
        "hwid spoofed", "ban bypass", "riot auth bypass",
        "recoil control enabled", "no recoil loaded",
    ];

    private static readonly string[] CheatConfigKeywords =
    [
        "aimbot_enabled", "aimbot_fov", "aimbot_smooth", "aimbot_bone",
        "esp_enabled", "esp_box", "esp_health", "esp_name", "esp_distance",
        "wallhack_enabled", "chams_enabled", "glow_enabled",
        "triggerbot_enabled", "trigger_key", "trigger_delay",
        "silent_aim_enabled", "legit_aim_enabled", "rage_aim_enabled",
        "skinchanger_enabled", "knife_model", "gun_buddy",
        "val_aimbot", "val_esp", "val_wallhack", "vanguard_bypass",
        "no_recoil_val", "rcs_enabled_val", "backtrack_val",
        "resolver_val", "antiaim_val", "fakelag_val",
        "hwid_spoof_riot", "ban_bypass_riot", "riot_auth_bypass",
        "unlock_all_skins", "skin_changer_val", "knife_changer_val",
        "val_memory_read", "valorant_offsets", "val_sdk_enabled",
    ];

    private static readonly string[] HostsRiotEntries =
    [
        "auth.riotgames.com", "api.riotgames.com", "entitlements.auth.riotgames.com",
        "playerpreferences.riotgames.com", "shared.riotgames.com",
        "riot.direct", "riotgames.com", "na.lol.riotgames.com",
        "rms.auth.riotgames.com", "geo.valorantesports.com",
        "valorant.secure.dyn.riotgames.com", "clientconfig.rpg.riotgames.com",
        "session.na.lol.riotgames.com", "ledge.na.lol.riotgames.com",
        "pd.na.a.pvp.net", "glz-na-1.na.a.pvp.net", "shared.na.a.pvp.net",
        "keystone.na.pvp.net", "vanguard-kernel.riotgames.com",
        "vanguard.riotgames.com", "vgk.riotgames.com",
        "anti-cheat.riotgames.com", "penaltyservice.riotgames.com",
    ];

    private static readonly string[] UserAssistCheatKeywords =
    [
        "vanguard_bypass", "vgc_kill", "vgk_bypass", "valorant_aim",
        "aim_valorant", "val_aimbot", "val_esp", "valorant_esp",
        "valo_esp", "val_wallhack", "valorant_wh", "val_trigger",
        "trigger_valorant", "val_skin", "valorant_skins", "val_spoofer",
        "riot_bypass", "riot_hwid", "valorant_loader", "val_injector",
        "vncheat", "valorant_hack", "valo_cheat", "valorant_cheat",
        "val_hack", "valo_hack", "val_loader", "valo_loader",
        "valo_triggerbot", "val_skinchanger", "valo_skins", "val_resolver",
    ];

    private static readonly string[] MuiCacheCheatKeywords =
    [
        "vanguard_bypass", "vgc_kill", "vgk_bypass", "valorant_aim",
        "val_aimbot", "val_esp", "valorant_esp", "valorant_wh",
        "val_trigger", "val_skin", "valorant_skins", "val_spoofer",
        "riot_bypass", "riot_hwid", "valorant_loader", "val_injector",
        "vncheat", "valorant_hack", "valo_cheat", "val_hack",
        "valo_hack", "val_loader", "valo_triggerbot", "val_skinchanger",
        "val_resolver", "valo_skins", "valo_loader", "valo_wallhack",
    ];

    private static readonly string[] SuspiciousDllsInValorantDir =
    [
        "val_esp.dll", "val_aim.dll", "val_trigger.dll", "val_skins.dll",
        "valorant_esp.dll", "valorant_aim.dll", "valo_esp.dll", "valo_aim.dll",
        "d3d11_proxy.dll", "d3d12_proxy.dll", "xinput1_4_hook.dll",
        "winmm_hook.dll", "version_hook.dll", "dinput8_hook.dll",
        "dxgi_hook.dll", "d3dcompiler_hook.dll", "opengl32_hook.dll",
        "wsock32_hook.dll", "ws2_32_hook.dll",
    ];

    private static readonly string[] TempCheatArtifactPatterns =
    [
        "valorant", "valo", "val_", "vanguard_bypass", "vgk_bypass",
        "riot_bypass", "riot_hwid", "val_aimbot", "val_esp",
        "val_wallhack", "val_trigger", "val_skin", "val_spoofer",
        "vncheat", "valo_cheat", "valo_aim", "valo_esp",
        "riot_bypass", "riot_spoofer", "vgc_kill", "vgk_kill",
    ];

    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Valorant cheat deep scan...");

        await Task.WhenAll(
            CheckKnownCheatFilesAsync(ctx, ct),
            CheckCheatProcessesAsync(ctx, ct),
            CheckVanguardServiceTamperingAsync(ctx, ct),
            CheckVgkBypassDriversAsync(ctx, ct),
            CheckIFEOHijackAsync(ctx, ct),
            CheckRegistryRunKeysAsync(ctx, ct),
            CheckHostsFileRiotBlockingAsync(ctx, ct),
            CheckValorantLogsAsync(ctx, ct),
            CheckSuspiciousDllsInGameDirAsync(ctx, ct),
            CheckTempFolderArtifactsAsync(ctx, ct),
            CheckUserAssistAsync(ctx, ct),
            CheckMuiCacheAsync(ctx, ct),
            CheckDownloadsFolderAsync(ctx, ct),
            CheckValorantAppDataAsync(ctx, ct),
            CheckCheatConfigFoldersAsync(ctx, ct)
        );

        ctx.Report(1.0, Name, "Valorant cheat deep scan complete.");
    }

    private Task CheckKnownCheatFilesAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var scanPaths = BuildValorantScanPaths();
            foreach (var dir in scanPaths)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try
                {
                    files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    var matchedCheat = KnownCheatFileNames.FirstOrDefault(c =>
                        fn.Equals(c, StringComparison.OrdinalIgnoreCase));

                    if (matchedCheat is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Valorant Cheat File Found: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known Valorant cheat tool file '{fn}' was found at '{file}'. " +
                                     $"This file matches the known cheat artifact '{matchedCheat}' " +
                                     "and confirms cheating software was present on this system.",
                            Detail = $"File: {file} | Matched: {matchedCheat}"
                        });
                        continue;
                    }

                    var fnLower = fn.ToLowerInvariant();
                    bool hasCheatKeyword =
                        fnLower.Contains("val_aimbot") || fnLower.Contains("valo_aim") ||
                        fnLower.Contains("valorant_aim") || fnLower.Contains("val_esp") ||
                        fnLower.Contains("valo_esp") || fnLower.Contains("valorant_esp") ||
                        fnLower.Contains("vanguard_bypass") || fnLower.Contains("vgk_bypass") ||
                        fnLower.Contains("vgc_kill") || fnLower.Contains("val_trigger") ||
                        fnLower.Contains("val_wallhack") || fnLower.Contains("valo_wallhack");

                    var ext = Path.GetExtension(fn).ToLowerInvariant();
                    if (hasCheatKeyword && ext is ".exe" or ".dll" or ".sys")
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Valorant Suspicious File (Heuristic): {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"File '{fn}' contains Valorant cheat-related keywords in its name " +
                                     "and was found in a Valorant-related scan directory. " +
                                     "This is a strong heuristic indicator of cheat software targeting Valorant.",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckCheatProcessesAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var processes = ctx.GetProcessSnapshot();
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementProcesses();

                var pname = proc.ProcessName;
                var matched = KnownCheatProcessNames.FirstOrDefault(c =>
                    pname.Equals(c, StringComparison.OrdinalIgnoreCase) ||
                    pname.Equals(c.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase));

                if (matched is null) continue;

                string procPath = string.Empty;
                try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Valorant Cheat Process Running: {pname}",
                    Risk = RiskLevel.Critical,
                    Location = procPath.Length > 0 ? procPath : $"PID {proc.Id}",
                    FileName = pname,
                    Reason = $"Known Valorant cheat process '{pname}' is currently running (PID {proc.Id}). " +
                             $"Process matches known cheat pattern '{matched}'. " +
                             "This is an active cheat tool targeting Valorant, currently loaded in memory.",
                    Detail = $"PID: {proc.Id} | Name: {pname} | Path: {procPath}"
                });
            }
        }, ct);

    private Task CheckVanguardServiceTamperingAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var vanguardServices = new[]
            {
                ("vgc", "Vanguard user-mode service (vgc.exe)"),
                ("vgk", "Vanguard kernel driver (vgk.sys)"),
            };

            foreach (var (svcName, svcDesc) in vanguardServices)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var svcKey = Registry.LocalMachine.OpenSubKey(
                        $@"SYSTEM\CurrentControlSet\Services\{svcName}", writable: false);

                    if (svcKey is null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Vanguard Service Missing: {svcName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = svcName,
                            Reason = $"Vanguard service '{svcName}' ({svcDesc}) registry entry is missing. " +
                                     "This service is installed with Valorant and its absence while Valorant " +
                                     "is installed suggests it was forcibly removed by a bypass tool. " +
                                     "Vanguard bypass tools commonly unregister or delete Vanguard services.",
                            Detail = $"Expected registry key not found: HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svcName}"
                        });
                        continue;
                    }

                    ctx.IncrementRegistryKeys();
                    var startType = svcKey.GetValue("Start") as int? ?? -1;
                    var imagePath = (svcKey.GetValue("ImagePath") as string ?? "").Trim();

                    if (startType == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Vanguard Service Disabled: {svcName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = svcName,
                            Reason = $"Vanguard service '{svcName}' ({svcDesc}) has been set to disabled " +
                                     "(Start=4) in the registry. This is the primary method used by Vanguard " +
                                     "bypass tools: they disable the anti-cheat service before launching Valorant " +
                                     "so that no kernel-level protection is active during gameplay.",
                            Detail = $"Service: {svcName} | Start type: {startType} (4=Disabled) | ImagePath: {imagePath}"
                        });
                    }

                    if (!string.IsNullOrEmpty(imagePath) &&
                        !imagePath.Contains("Riot Vanguard", StringComparison.OrdinalIgnoreCase) &&
                        !imagePath.Contains("vgk.sys", StringComparison.OrdinalIgnoreCase) &&
                        !imagePath.Contains("vgc.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Vanguard Service ImagePath Tampered: {svcName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = svcName,
                            Reason = $"Vanguard service '{svcName}' has an unexpected ImagePath: '{imagePath}'. " +
                                     "The legitimate Vanguard service should reference the official Riot Vanguard " +
                                     "installation path. A modified ImagePath indicates the service was " +
                                     "redirected to a fake or empty binary to neutralize Vanguard.",
                            Detail = $"Service: {svcName} | ImagePath: {imagePath}"
                        });
                    }
                }
                catch { }
            }

            var vgkExpectedPath = @"C:\Program Files\Riot Vanguard\vgk.sys";
            if (File.Exists(vgkExpectedPath))
            {
                ctx.IncrementFiles();
                try
                {
                    var fi = new FileInfo(vgkExpectedPath);
                    if (fi.Length < 1024)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Vanguard vgk.sys Suspiciously Small (Possible Hollowing)",
                            Risk = RiskLevel.Critical,
                            Location = vgkExpectedPath,
                            FileName = "vgk.sys",
                            Reason = $"Vanguard kernel driver 'vgk.sys' exists at its expected location but " +
                                     $"is only {fi.Length} bytes in size, which is far too small for a " +
                                     "legitimate driver. Cheat bypass tools sometimes replace vgk.sys with a " +
                                     "hollow stub (empty or minimal binary) that satisfies file existence " +
                                     "checks while providing no actual anti-cheat protection.",
                            Detail = $"Path: {vgkExpectedPath} | Size: {fi.Length} bytes"
                        });
                    }
                }
                catch { }
            }
            else
            {
                var riotGamesPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Riot Games");
                if (Directory.Exists(riotGamesPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Vanguard vgk.sys Not Found (Riot Games Installed)",
                        Risk = RiskLevel.High,
                        Location = vgkExpectedPath,
                        FileName = "vgk.sys",
                        Reason = "Riot Games is installed but vgk.sys (Vanguard kernel driver) is absent from " +
                                 "its expected path 'C:\\Program Files\\Riot Vanguard\\vgk.sys'. " +
                                 "Bypass tools may delete or relocate vgk.sys to prevent Vanguard from " +
                                 "loading its kernel component, fully disabling kernel-level protection.",
                        Detail = $"Expected path: {vgkExpectedPath} | Riot Games dir: {riotGamesPath}"
                    });
                }
            }
        }, ct);

    private Task CheckVgkBypassDriversAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var driversDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");

            if (Directory.Exists(driversDir))
            {
                string[] driverFiles;
                try { driverFiles = Directory.GetFiles(driversDir, "*.sys"); }
                catch (UnauthorizedAccessException) { driverFiles = Array.Empty<string>(); }

                foreach (var file in driverFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var matched = VgkBypassDriverNames.FirstOrDefault(d =>
                        fn.Equals(d, StringComparison.OrdinalIgnoreCase));

                    if (matched is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Vanguard Bypass Driver Found: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known Vanguard bypass kernel driver '{fn}' found in the system " +
                                     "drivers directory. This driver is specifically designed to intercept " +
                                     "and neutralize Riot Vanguard's kernel-mode anti-cheat scanning, " +
                                     "enabling cheat software to operate undetected. Pattern: " + matched,
                            Detail = $"Driver path: {file}"
                        });
                    }
                }
            }

            try
            {
                using var servicesKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services", writable: false);
                if (servicesKey is null) return;

                foreach (var svcName in servicesKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var svc = servicesKey.OpenSubKey(svcName, writable: false);
                        if (svc is null) continue;

                        var imgPath = (svc.GetValue("ImagePath") as string ?? "").ToLowerInvariant();
                        var type = svc.GetValue("Type") as int? ?? 0;
                        if (type != 1) continue;

                        var matched = VgkBypassDriverNames.FirstOrDefault(d =>
                            imgPath.Contains(d, StringComparison.OrdinalIgnoreCase) ||
                            svcName.Contains(d.Replace(".sys", ""), StringComparison.OrdinalIgnoreCase));

                        if (matched is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Vanguard Bypass Driver Service: {svcName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = svcName,
                                Reason = $"Kernel driver service '{svcName}' matches a known Vanguard bypass " +
                                         $"driver pattern '{matched}'. ImagePath: '{imgPath}'. " +
                                         "This driver-level bypass operates before Vanguard starts to prevent " +
                                         "it from loading or to intercept its kernel callbacks.",
                                Detail = $"Service: {svcName} | ImagePath: {imgPath} | Matched: {matched}"
                            });
                        }

                        var svcNameLower = svcName.ToLowerInvariant();
                        if ((svcNameLower.Contains("vgk") || svcNameLower.Contains("vanguard") ||
                             svcNameLower.Contains("vgc")) &&
                            (svcNameLower.Contains("bypass") || svcNameLower.Contains("kill") ||
                             svcNameLower.Contains("disable") || svcNameLower.Contains("patch") ||
                             svcNameLower.Contains("hook") || svcNameLower.Contains("spoof")))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious Vanguard-Targeting Service: {svcName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = svcName,
                                Reason = $"Kernel driver service '{svcName}' has a name that indicates it " +
                                         "specifically targets Vanguard anti-cheat (vgk/vgc) with bypass, " +
                                         "kill, disable, patch, hook, or spoof operations. " +
                                         "This pattern is exclusive to Vanguard bypass tools.",
                                Detail = $"Service: {svcName} | ImagePath: {imgPath}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);

    private Task CheckIFEOHijackAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string ifeoBase =
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

            var targetExecutables = new[]
            {
                "VALORANT.exe", "VALORANT-Win64-Shipping.exe",
                "RiotClientServices.exe", "RiotClientUx.exe",
                "RiotClientUxRender.exe", "vgc.exe", "vgk.sys",
                "RiotClientCrashHandler.exe",
            };

            foreach (var targetExe in targetExecutables)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var ifeoKey = Registry.LocalMachine.OpenSubKey(
                        $@"{ifeoBase}\{targetExe}", writable: false);

                    if (ifeoKey is null) continue;
                    ctx.IncrementRegistryKeys();

                    var debugger = ifeoKey.GetValue("Debugger") as string;
                    var globalFlag = ifeoKey.GetValue("GlobalFlag") as int?;

                    if (!string.IsNullOrEmpty(debugger))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"IFEO Hijack on Valorant/Vanguard Binary: {targetExe}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{ifeoBase}\{targetExe}",
                            FileName = targetExe,
                            Reason = $"Image File Execution Options (IFEO) Debugger key set for '{targetExe}'. " +
                                     $"Debugger value: '{debugger}'. " +
                                     "This causes Windows to launch the debugger binary instead of the legitimate " +
                                     $"'{targetExe}' whenever it is executed. Attackers use this to intercept " +
                                     "Valorant or Vanguard startup and redirect execution to a cheat loader " +
                                     "or to prevent Vanguard from starting at all.",
                            Detail = $"Debugger: {debugger} | GlobalFlag: {globalFlag}"
                        });
                    }

                    if (globalFlag.HasValue && globalFlag.Value != 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"IFEO GlobalFlag Set for Valorant Binary: {targetExe}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{ifeoBase}\{targetExe}",
                            FileName = targetExe,
                            Reason = $"Image File Execution Options GlobalFlag is non-zero ({globalFlag}) " +
                                     $"for '{targetExe}'. Attackers may set GlobalFlag to enable silent " +
                                     "process exit behavior or heap debugging flags that interfere with " +
                                     "Vanguard's integrity checks.",
                            Detail = $"GlobalFlag: 0x{globalFlag:X8}"
                        });
                    }
                }
                catch { }
            }
        }, ct);

    private Task CheckRegistryRunKeysAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var runKeyPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            };

            var roots = new[] { Registry.CurrentUser, Registry.LocalMachine };

            foreach (var root in roots)
            {
                foreach (var keyPath in runKeyPaths)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var key = root.OpenSubKey(keyPath, writable: false);
                        if (key is null) continue;

                        foreach (var valueName in key.GetValueNames())
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();

                            var value = (key.GetValue(valueName) as string ?? "").ToLowerInvariant();
                            var nameLower = valueName.ToLowerInvariant();
                            var combined = nameLower + " " + value;

                            var cheatMatch = KnownCheatFileNames.FirstOrDefault(c =>
                                combined.Contains(c.Replace(".exe", "").Replace(".dll", ""),
                                    StringComparison.OrdinalIgnoreCase));

                            if (cheatMatch is not null)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Valorant Cheat Loader in Run Key: {valueName}",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"{(root == Registry.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}\{valueName}",
                                    FileName = valueName,
                                    Reason = $"Registry Run key entry '{valueName}' references a known Valorant " +
                                             $"cheat loader pattern '{cheatMatch}'. Command: '{value}'. " +
                                             "This establishes persistence for a cheat tool, ensuring it starts " +
                                             "automatically before Valorant launches.",
                                    Detail = $"Key: {keyPath}\\{valueName} | Value: {value} | Matched: {cheatMatch}"
                                });
                                continue;
                            }

                            if ((value.Contains("vanguard", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("valorant", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("riot", StringComparison.OrdinalIgnoreCase)) &&
                                (value.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("loader", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("injector", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("kill", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("disable", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Suspicious Valorant/Vanguard Run Key: {valueName}",
                                    Risk = RiskLevel.High,
                                    Location = $@"{(root == Registry.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}\{valueName}",
                                    FileName = valueName,
                                    Reason = $"Registry Run key '{valueName}' references a Valorant/Vanguard-related " +
                                             "executable with bypass/loader/injector/cheat/hack/kill/disable keywords. " +
                                             $"Command: '{value}'. This is a strong indicator of cheat persistence.",
                                    Detail = $"Value: {value}"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
        }, ct);

    private Task CheckHostsFileRiotBlockingAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var hostsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "drivers", "etc", "hosts");

            if (!File.Exists(hostsPath)) return;
            ct.ThrowIfCancellationRequested();

            string content;
            try
            {
                using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }

            ctx.IncrementFiles();

            foreach (var riotHost in HostsRiotEntries)
            {
                if (!content.Contains(riotHost, StringComparison.OrdinalIgnoreCase)) continue;

                var lines = content.Split('\n');
                foreach (var line in lines)
                {
                    var trimmed = line.TrimStart();
                    if (trimmed.StartsWith("#")) continue;
                    if (!trimmed.Contains(riotHost, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Hosts File Blocking Riot/Vanguard Server: {riotHost}",
                        Risk = RiskLevel.High,
                        Location = hostsPath,
                        FileName = "hosts",
                        Reason = $"The Windows hosts file contains an active entry redirecting or blocking " +
                                 $"'{riotHost}'. This is used by Valorant/Vanguard bypass tools to " +
                                 "prevent authentication servers, telemetry endpoints, or Vanguard update " +
                                 "servers from being reached. Blocking auth servers can allow ban-evading " +
                                 "accounts to connect, and blocking Vanguard update servers prevents " +
                                 "detection signature updates.",
                        Detail = $"Hosts entry: {trimmed.Trim()} | Blocked host: {riotHost}"
                    });
                    break;
                }
            }
        }, ct);

    private Task CheckValorantLogsAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var logDirs = new[]
            {
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Valorant", "Saved", "Logs"),
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Riot Games", "Riot Client", "Logs"),
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Riot Games", "VALORANT", "Logs"),
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Riot Games", "Logs"),
            };

            foreach (var logDir in logDirs)
            {
                if (!Directory.Exists(logDir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] logFiles;
                try { logFiles = Directory.GetFiles(logDir, "*.log", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var logFile in logFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var fn = Path.GetFileName(logFile);
                    foreach (var keyword in SuspiciousLogKeywords)
                    {
                        if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious Entry in Valorant Log: {fn}",
                            Risk = RiskLevel.High,
                            Location = logFile,
                            FileName = fn,
                            Reason = $"Valorant/Riot log file '{fn}' contains suspicious keyword '{keyword}'. " +
                                     "Cheat tools sometimes write telemetry, debug output, or status messages " +
                                     "to log files, or log files may record anomalous events caused by cheat " +
                                     "interference with the game client or Vanguard.",
                            Detail = $"Log file: {logFile} | Keyword: {keyword}"
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckSuspiciousDllsInGameDirAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var valorantGameDirs = new List<string>
            {
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Valorant"),
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Riot Games", "VALORANT", "live"),
                @"C:\Riot Games\VALORANT\live",
                @"C:\Program Files\Riot Games\VALORANT\live",
            };

            try
            {
                using var riotKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Riot Game valorant.live",
                    writable: false)
                    ?? Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Riot Game valorant.live",
                    writable: false);
                if (riotKey is not null)
                {
                    var installLoc = riotKey.GetValue("InstallLocation") as string;
                    if (!string.IsNullOrEmpty(installLoc))
                        valorantGameDirs.Add(installLoc);
                }
            }
            catch { }

            foreach (var gameDir in valorantGameDirs)
            {
                if (!Directory.Exists(gameDir)) continue;
                ct.ThrowIfCancellationRequested();

                var binDir = Path.Combine(gameDir, "ShooterGame", "Binaries", "Win64");
                if (!Directory.Exists(binDir))
                    binDir = gameDir;

                string[] files;
                try { files = Directory.GetFiles(binDir, "*.dll", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    var cheatMatch = KnownCheatFileNames.FirstOrDefault(c =>
                        fn.Equals(c, StringComparison.OrdinalIgnoreCase) ||
                        (c.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
                         fn.Equals(c, StringComparison.OrdinalIgnoreCase)));

                    if (cheatMatch is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat DLL in Valorant Game Directory: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known Valorant cheat DLL '{fn}' found inside the Valorant game " +
                                     $"binary directory. Pattern: '{cheatMatch}'. " +
                                     "Cheat tools place DLLs in the game's executable directory for " +
                                     "DLL side-loading or hijacking attacks against Valorant.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    var matchedProxy = SuspiciousDllsInValorantDir.FirstOrDefault(d =>
                        fn.Equals(d, StringComparison.OrdinalIgnoreCase));
                    if (matchedProxy is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Proxy/Hook DLL in Valorant Dir: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Suspicious proxy or hook DLL '{fn}' found in the Valorant game directory. " +
                                     "This file matches a known DLL hijacking pattern used to intercept " +
                                     "Windows API calls from Valorant or Vanguard. Cheat tools use this " +
                                     "technique to inject code into the game process without traditional injection.",
                            Detail = $"Path: {file} | Pattern: {matchedProxy}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckTempFolderArtifactsAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var tempPaths = new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            };

            foreach (var tempDir in tempPaths)
            {
                if (!Directory.Exists(tempDir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try { files = Directory.GetFiles(tempDir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var fnLower = fn.ToLowerInvariant();

                    var matchedArtifact = TempCheatArtifactPatterns.FirstOrDefault(p =>
                        fnLower.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (matchedArtifact is null) continue;

                    var ext = Path.GetExtension(fn).ToLowerInvariant();
                    if (ext is not (".exe" or ".dll" or ".sys" or ".dat" or ".log" or ".cfg" or ".ini" or ".zip" or ".rar" or ".7z"))
                        continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Valorant Cheat Artifact in Temp Folder: {fn}",
                        Risk = ext is ".exe" or ".dll" or ".sys"
                            ? RiskLevel.High : RiskLevel.Medium,
                        Location = file,
                        FileName = fn,
                        Reason = $"File '{fn}' in the temp folder contains Valorant cheat-related keywords " +
                                 $"(matched: '{matchedArtifact}'). Cheat tools commonly extract and run from " +
                                 "temp directories to avoid persistent footprints in standard locations " +
                                 "and to complicate forensic attribution.",
                        Detail = $"Path: {file} | Pattern: {matchedArtifact} | Extension: {ext}"
                    });
                }
            }
        }, ct);

    private Task CheckUserAssistAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string userAssistBase =
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

            try
            {
                using var baseKey = Registry.CurrentUser.OpenSubKey(userAssistBase, writable: false);
                if (baseKey is null) return;

                foreach (var guidName in baseKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var countKey = baseKey.OpenSubKey($@"{guidName}\Count", writable: false);
                        if (countKey is null) continue;

                        foreach (var encodedName in countKey.GetValueNames())
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();

                            var decoded = Rot13Decode(encodedName);
                            var decodedLower = decoded.ToLowerInvariant();

                            var keyword = UserAssistCheatKeywords.FirstOrDefault(k =>
                                decodedLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (keyword is null) continue;

                            int runCount = 0;
                            DateTime? lastRun = null;
                            try
                            {
                                var data = countKey.GetValue(encodedName) as byte[];
                                if (data is { Length: >= 16 })
                                {
                                    runCount = BitConverter.ToInt32(data, 4);
                                    var fileTime = BitConverter.ToInt64(data, 8);
                                    if (fileTime > 0)
                                        lastRun = DateTime.FromFileTimeUtc(fileTime);
                                }
                            }
                            catch { }

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"UserAssist: Valorant Cheat Executed — {keyword}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"Windows UserAssist forensic record shows execution of Valorant cheat " +
                                         $"tool matching '{keyword}'. Decoded entry: '{decoded}'. " +
                                         $"Execution count: {runCount}. " +
                                         (lastRun.HasValue
                                             ? $"Last executed: {lastRun.Value:yyyy-MM-dd HH:mm} UTC. "
                                             : "") +
                                         "UserAssist entries survive file deletion and provide irrefutable " +
                                         "forensic evidence of cheat tool execution.",
                                Detail = $"Decoded: {decoded} | Runs: {runCount} | " +
                                         $"Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);

    private Task CheckMuiCacheAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string muiCacheKey =
                @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(muiCacheKey, writable: false);
                if (key is null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    var path = valueName;
                    var dotIdx = valueName.LastIndexOf('.');
                    if (dotIdx > 0 && !valueName[dotIdx..].Contains('\\'))
                        path = valueName[..dotIdx];

                    var friendlyName = key.GetValue(valueName) as string ?? "";
                    var combined = path.ToLowerInvariant() + " " + friendlyName.ToLowerInvariant();

                    var keyword = MuiCacheCheatKeywords.FirstOrDefault(k =>
                        combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (keyword is null) continue;

                    bool fileExists = File.Exists(path);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"MuiCache: Valorant Cheat Tool Executed: {Path.GetFileName(path)}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{muiCacheKey}",
                        FileName = Path.GetFileName(path),
                        Reason = $"MuiCache entry proves execution of Valorant cheat tool '{Path.GetFileName(path)}' " +
                                 $"(keyword match: '{keyword}'). " +
                                 (fileExists
                                     ? "The file still exists on disk."
                                     : "The file has been deleted but its execution is forensically confirmed.") +
                                 " MuiCache records persist even after program uninstallation or file deletion.",
                        Detail = $"Path: {path} | FriendlyName: {friendlyName} | Exists: {fileExists}"
                    });
                }
            }
            catch { }
        }, ct);

    private Task CheckDownloadsFolderAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var downloadsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

            if (!Directory.Exists(downloadsPath)) return;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(downloadsPath, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { return; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                var matchedCheat = KnownCheatFileNames.FirstOrDefault(c =>
                    fn.Equals(c, StringComparison.OrdinalIgnoreCase));

                if (matchedCheat is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Valorant Cheat Download Found: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known Valorant cheat file '{fn}' found in the Downloads folder. " +
                                 "This confirms the user downloaded this cheat tool from the internet. " +
                                 $"Matched known cheat pattern: '{matchedCheat}'.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                var ext = Path.GetExtension(fn).ToLowerInvariant();
                if (ext is not (".exe" or ".dll" or ".zip" or ".rar" or ".7z")) continue;

                var fnLower = fn.ToLowerInvariant();
                var cheatHit = TempCheatArtifactPatterns.FirstOrDefault(p =>
                    fnLower.Contains(p, StringComparison.OrdinalIgnoreCase));

                if (cheatHit is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Valorant Suspicious Download: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"File '{fn}' in Downloads contains Valorant cheat-related keywords " +
                                 $"(matched: '{cheatHit}'). Downloaded archives or executables with " +
                                 "Valorant cheat keywords are a strong indicator of attempted or completed " +
                                 "cheat tool download and installation.",
                        Detail = $"Path: {file} | Pattern: {cheatHit}"
                    });
                }
            }
        }, ct);

    private Task CheckValorantAppDataAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var appDataPaths = new[]
            {
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Valorant"),
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Riot Games"),
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Riot Games"),
                @"C:\Program Files\Riot Vanguard",
            };

            foreach (var appDataPath in appDataPaths)
            {
                if (!Directory.Exists(appDataPath)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try { files = Directory.GetFiles(appDataPath, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(fn).ToLowerInvariant();

                    var cheatMatch = KnownCheatFileNames.FirstOrDefault(c =>
                        fn.Equals(c, StringComparison.OrdinalIgnoreCase));
                    if (cheatMatch is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Valorant Cheat in Riot AppData: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known Valorant cheat file '{fn}' found inside Riot Games AppData " +
                                     $"directory. Matched pattern: '{cheatMatch}'. Cheat tools plant files " +
                                     "in Riot AppData directories to blend in with legitimate Riot/Valorant " +
                                     "application data and avoid filesystem-level detection.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    if (ext is ".exe" or ".dll" or ".sys")
                    {
                        var fnLower = fn.ToLowerInvariant();
                        var heuristicHit = TempCheatArtifactPatterns.FirstOrDefault(p =>
                            fnLower.Contains(p, StringComparison.OrdinalIgnoreCase));

                        if (heuristicHit is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious Executable in Riot AppData: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Executable/DLL '{fn}' with Valorant cheat keyword '{heuristicHit}' " +
                                         "found in Riot Games AppData directory. Cheat loaders frequently " +
                                         "disguise payloads inside Riot AppData to evade simple name-based " +
                                         "detection and to persist across game updates.",
                                Detail = $"Path: {file} | Pattern: {heuristicHit}"
                            });
                        }
                    }

                    if (ext is ".json" or ".cfg" or ".ini" or ".toml" or ".yaml" or ".txt")
                    {
                        string content;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }

                        var cheatConfigHit = CheatConfigKeywords.FirstOrDefault(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (cheatConfigHit is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Valorant Cheat Config in Riot AppData: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Config file '{fn}' in Riot AppData directory contains cheat-specific " +
                                         $"setting '{cheatConfigHit}'. This config was written by a Valorant " +
                                         "cheat tool. Cheat tools store aimbot, ESP, and Vanguard bypass " +
                                         "settings in config files adjacent to legitimate Riot data.",
                                Detail = $"Path: {file} | Config keyword: {cheatConfigHit}"
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckCheatConfigFoldersAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var configSearchPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "valorant_cheat"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "val_esp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "val_aim"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "valo_cheat"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "vncheat"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "vanguard_bypass"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "riot_bypass"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "riot_hwid"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "val_spoofer"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "val_skinchanger"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "val_triggerbot"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "val_wallhack"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "valorant_cheat"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "val_esp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "val_aim"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "valo_cheat"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "vncheat"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "vanguard_bypass"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "riot_bypass"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "val_spoofer"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "val_skinchanger"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "val_triggerbot"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".valorant_cheat"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".vncheat"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".val_aim"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".vanguard_bypass"),
            };

            foreach (var configPath in configSearchPaths)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(configPath)) continue;

                var dirName = Path.GetFileName(configPath);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Valorant Cheat Config Folder Found: {dirName}",
                    Risk = RiskLevel.Critical,
                    Location = configPath,
                    FileName = dirName,
                    Reason = $"Directory '{configPath}' is a known configuration folder for the Valorant " +
                             $"cheat tool '{dirName}'. The existence of this directory confirms the cheat " +
                             "was installed and executed on this machine. These directories are created " +
                             "exclusively by cheat software during installation or first run.",
                    Detail = $"Cheat config dir: {configPath}"
                });

                string[] configFiles;
                try { configFiles = Directory.GetFiles(configPath, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var configFile in configFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(configFile);
                    var ext = Path.GetExtension(fn).ToLowerInvariant();

                    if (ext is ".json" or ".cfg" or ".ini" or ".toml" or ".txt" or ".yaml")
                    {
                        string content;
                        try
                        {
                            using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }

                        var cheatConfigHit = CheatConfigKeywords.FirstOrDefault(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (cheatConfigHit is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Valorant Cheat Config File Content: {fn}",
                                Risk = RiskLevel.High,
                                Location = configFile,
                                FileName = fn,
                                Reason = $"Config file '{fn}' in the cheat folder contains cheat-specific " +
                                         $"setting '{cheatConfigHit}'. This configuration was written by a " +
                                         "Valorant cheat tool and details its operational settings " +
                                         "(aimbot, ESP, Vanguard bypass, skin changer, etc.).",
                                Detail = $"Path: {configFile} | Config key: {cheatConfigHit}"
                            });
                        }
                    }
                }
            }

            // Check for known cheat-related registry software keys
            var riotCheatRegKeys = new[]
            {
                @"SOFTWARE\ValorantCheat",
                @"SOFTWARE\ValESP",
                @"SOFTWARE\ValorantAimbot",
                @"SOFTWARE\ValAimbot",
                @"SOFTWARE\ValorantHack",
                @"SOFTWARE\VanguardBypass",
                @"SOFTWARE\RiotBypass",
                @"SOFTWARE\VGKBypass",
                @"SOFTWARE\VGCKill",
                @"SOFTWARE\ValSpoofer",
                @"SOFTWARE\RiotHWIDSpoofer",
                @"SOFTWARE\ValSkinChanger",
                @"SOFTWARE\ValorantSkinUnlocker",
                @"SOFTWARE\ValTriggerBot",
                @"SOFTWARE\ValorantWallhack",
                @"SOFTWARE\ValResolver",
                @"SOFTWARE\VnCheat",
            };

            foreach (var regKey in riotCheatRegKeys)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(regKey, writable: false)
                                 ?? Registry.CurrentUser.OpenSubKey(regKey, writable: false);
                    if (key is null) continue;

                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Valorant Cheat Registry Key Found: {Path.GetFileName(regKey)}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{regKey}",
                        FileName = Path.GetFileName(regKey),
                        Reason = $"Registry key '{regKey}' belonging to a known Valorant cheat tool was found. " +
                                 "This registry entry is created during cheat tool installation and confirms " +
                                 "the tool was present and configured on this system.",
                        Detail = $"Registry key: {regKey}"
                    });
                }
                catch { }
            }
        }, ct);

    private static List<string> BuildValorantScanPaths()
    {
        var paths = new List<string>();

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        paths.Add(Path.Combine(localAppData, "Valorant"));
        paths.Add(Path.Combine(localAppData, "Riot Games"));
        paths.Add(Path.Combine(appData, "Riot Games"));
        paths.Add(Path.Combine(userProfile, "Downloads"));
        paths.Add(@"C:\Program Files\Riot Vanguard");
        paths.Add(@"C:\Program Files\Riot Games");
        paths.Add(@"C:\Riot Games");

        return paths;
    }
}
