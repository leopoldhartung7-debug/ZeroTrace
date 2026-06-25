using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class CS2CheatScanModule : IScanModule
{
    public string Name => "CS2 Cheat Detection";
    public double Weight => 3.8;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] KnownCheatFileNames =
    [
        // VAC bypass tools
        "vac_bypass.dll", "vac_bypass.exe", "vacbp.dll", "vac_bridge.sys", "vadp.sys",
        "vac_hook.dll", "vacbypasser.exe", "vac_disable.exe", "vac_patch.dll",
        "vacnet_bypass.dll", "vac_unhook.dll", "vacsteam_bypass.dll",
        // Aimbot tools
        "cs2_aimbot.exe", "cs2aim.dll", "aim_cs2.exe", "cs2_aim.dll",
        "csgo_aimbot.exe", "aim_assist_cs2.exe", "cs2_silentaim.dll",
        "cs2_legit_aim.dll", "cs2_rage_aim.dll", "aimware_cs2.dll",
        "cs2_hvh_aim.exe", "cs2_aimassist.dll", "aim_cs.exe",
        "cs2_fov_aim.dll", "cs2_bone_aim.dll", "cs2_prediction_aim.dll",
        // Wallhack / ESP tools
        "cs2_wh.exe", "wh_cs2.dll", "esp_cs2.dll", "cs2_esp.dll",
        "cs2_wallhack.exe", "cs2_chams.dll", "cs2_glow.dll",
        "cs2_esp_box.dll", "cs2_esp_health.dll", "cs2_vischeck.dll",
        "cs2_radar_esp.dll", "cs2_sound_esp.dll", "cs2_skeleton_esp.dll",
        "cs2_distance_esp.dll", "cs2_item_esp.dll", "cs2_bomb_esp.dll",
        // Triggerbot
        "triggerbot.exe", "cs2_trigger.dll", "cs2_triggerbot.exe",
        "trigger_cs2.dll", "cs2_auto_trigger.dll", "triggerbot_cs2.exe",
        "cs2_trigger_delay.dll", "cs2_trigger_key.dll",
        // Bhop tools
        "cs2_bhop.exe", "bhop_cs2.dll", "cs2_bunnyhop.exe",
        "bhop_script_cs2.exe", "cs2_autobhop.dll", "cs2_bhopper.exe",
        "bhop_cs2.exe", "cs2_jumper.dll",
        // Skin changers
        "skinchanger_cs2.exe", "cs2skins.dll", "cs2_skinchanger.exe",
        "cs2_skin_changer.dll", "cs2_skins.exe", "skinchange_cs2.dll",
        "cs2_weapon_skins.dll", "cs2_knife_changer.exe", "cs2_glove_changer.dll",
        "cs2_sticker_changer.dll", "cs2_patch_skins.dll",
        // Radar hacks
        "radarcs2.exe", "cs2_radar.dll", "cs2_maphack.exe",
        "cs2_radar_hack.dll", "radar_cs2.exe", "cs2_minimap.dll",
        "cs2_wallradar.exe", "cs2_radar_server.dll",
        // Known commercial cheat files
        "skeet_cs2.dll", "fatality_cs2.dll", "neverlose_cs2.dll",
        "onetap_cs2.dll", "aimware_cs2.exe", "gamesense_cs2.dll",
        "nixware_cs2.dll", "interwebz_cs2.dll", "lumina_cs2.dll",
        "cs2_interium.dll", "hvh_cs2.dll", "cs2_cheats.exe",
        // Misc cheat components
        "cs2_loader.exe", "cs2_injector.exe", "cs2_bypass.exe",
        "cs2_hack.dll", "cs2_cheat.dll", "cs2_internal.dll",
        "cs2_external.dll", "cs2_offsets.dll", "cs2_sdk.dll",
        "cs2_memory.dll", "cs2_driver.sys", "cs2_anti_untrust.dll",
        "cs2_no_recoil.dll", "cs2_no_spread.dll", "cs2_rcs.dll",
        "cs2_movement_unlocker.dll", "cs2_backtrack.dll",
        "cs2_resolver.dll", "cs2_antiaim.dll", "cs2_fakelag.dll",
        "cheatcs2.dll", "cs2hack.dll", "cs2cheats.dll",
    ];

    private static readonly string[] KnownCheatProcessNames =
    [
        "cheatcs2", "cs2cheats", "skeet", "fatality", "neverlose",
        "interwebz", "gamesense", "aimware", "onetap", "nixware",
        "cs2_aimbot", "cs2_esp", "cs2_loader", "cs2_injector",
        "cs2_bypass", "cs2_hack", "cs2_cheat", "cs2_external",
        "cs2_radar", "cs2_bhop", "cs2_triggerbot", "cs2_skinchanger",
        "vacbypasser", "hvh_cs2", "lumina_cs2", "interium",
        "cs2_silentaim", "cs2_legit", "cs2_resolver", "cs2_antiaim",
        "cs2cheat", "skeet_cs2", "fatality_cs2", "cs2_loader",
        "cs2_driver", "cs2_memory", "cs2_prediction",
    ];

    private static readonly string[] VacBypassDriverNames =
    [
        "vadp.sys", "vac_bridge.sys", "vac_bypass.sys", "vachook.sys",
        "vacnet.sys", "valvac.sys", "vac_driver.sys", "vacpatch.sys",
        "vacprotect.sys", "vac_unhook.sys",
    ];

    private static readonly string[] SuspiciousAutoexecCommands =
    [
        "sv_cheats", "noclip", "aimbot", "wallhack", "esp_draw",
        "bhop", "bunnyhop", "trigger_bot", "triggerbot",
        "r_drawothermodels", "mat_wireframe", "enable_skeleton_draw",
        "r_visualize_teammatefriendly", "cl_showpos 1",
        "net_graph", "r_drawtracers_firstperson", "mat_fullbright",
    ];

    private static readonly string[] CheatConfigKeywords =
    [
        "aimbot_enabled", "aimbot_fov", "aimbot_smooth", "aimbot_bone",
        "esp_enabled", "esp_box", "esp_health", "esp_name", "esp_distance",
        "wallhack_enabled", "chams_enabled", "glow_enabled",
        "triggerbot_enabled", "trigger_key", "trigger_delay",
        "bhop_enabled", "bunnyhop_enabled", "autobhop",
        "skinchanger_enabled", "knife_model", "glove_model",
        "radar_hack_enabled", "no_recoil", "no_spread", "rcs_enabled",
        "backtrack_enabled", "resolver_enabled", "antiaim_enabled",
        "fakelag_enabled", "fake_duck", "silent_aim", "legit_aim",
        "hvh_mode", "rage_mode", "legitbot_mode",
    ];

    private static readonly string[] HostsFileVacEntries =
    [
        "vac.valve.com", "vac2.valve.com", "vac3.valve.com",
        "community.steamspy.com", "steamcommunity.com",
        "api.steampowered.com", "store.steampowered.com",
        "vac-server.valve.net", "vac-check.valve.com",
        "ovh.net", "vacnet.valve.com",
    ];

    private static readonly string[] CS2SteamBinCheatDlls =
    [
        "client.dll.bak", "engine2.dll.bak", "tier0.dll.bak",
        "inputsystem.dll.bak", "filesystem_stdio.dll.bak",
        "vphysics2.dll.bak", "rendersystemdx11.dll.bak",
        "schemasystem.dll.bak", "networksystem.dll.bak",
        "serverbrowser.dll.bak",
    ];

    private static readonly string[] TempCheatArtifactPatterns =
    [
        "cs2", "csgo", "vac_bypass", "aimbot", "wallhack",
        "triggerbot", "bhop", "skinchanger", "radar_hack",
        "skeet", "fatality", "neverlose", "onetap", "aimware",
        "gamesense", "nixware", "cs2cheat", "hvh", "resolver",
        "antiaim", "backtrack", "fakelag", "silentaim",
    ];

    private static readonly string[] UserAssistCheatKeywords =
    [
        "cs2_aimbot", "cs2_esp", "cs2_wallhack", "cs2_cheat",
        "cs2_hack", "cs2_loader", "cs2_bypass", "vacbypasser",
        "skeet", "fatality", "neverlose", "onetap", "aimware",
        "gamesense", "nixware", "interwebz", "lumina", "interium",
        "cs2cheats", "cs2_triggerbot", "cs2_bhop", "cs2_radar",
        "cs2_skinchanger", "hvh_cs2", "cs2_silentaim", "cs2_resolver",
        "cs2_antiaim", "cheatcs2", "cs2_external", "cs2_internal",
    ];

    private static readonly string[] MuiCacheCheatKeywords =
    [
        "cs2_aimbot", "cs2_esp", "cs2_wallhack", "cs2cheat",
        "cs2_hack", "cs2_loader", "cs2_bypass", "vacbypasser",
        "skeet", "fatality", "neverlose", "onetap", "aimware",
        "gamesense", "nixware", "interwebz", "lumina", "hvh_cs2",
        "cs2_triggerbot", "cs2_bhop", "cs2_radar", "cs2_skinchanger",
        "cs2_silentaim", "cs2_resolver", "cs2_antiaim", "cs2_external",
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
        ctx.Report(0.0, Name, "Starting CS2 cheat detection...");

        await Task.WhenAll(
            CheckKnownCheatFilesAsync(ctx, ct),
            CheckCheatProcessesAsync(ctx, ct),
            CheckVacBypassDriversAsync(ctx, ct),
            CheckSteamRegistryLaunchOptionsAsync(ctx, ct),
            CheckRegistryRunKeysAsync(ctx, ct),
            CheckCS2AutoexecConfigAsync(ctx, ct),
            CheckHostsFileVacBlockingAsync(ctx, ct),
            CheckSteamBinCheatDllsAsync(ctx, ct),
            CheckTempFolderArtifactsAsync(ctx, ct),
            CheckUserAssistAsync(ctx, ct),
            CheckMuiCacheAsync(ctx, ct),
            CheckDownloadsFolderAsync(ctx, ct),
            CheckSteamWorkshopInjectionAsync(ctx, ct),
            CheckCS2AppDataAsync(ctx, ct),
            CheckCheatConfigFilesAsync(ctx, ct)
        );

        ctx.Report(1.0, Name, "CS2 cheat detection complete.");
    }

    private Task CheckKnownCheatFilesAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var scanPaths = BuildCS2ScanPaths();
            foreach (var dir in scanPaths)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try
                {
                    files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

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
                            Title = $"CS2 Cheat File Found: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known CS2 cheat tool file '{fn}' was found at '{file}'. " +
                                     $"This file matches the known cheat artifact '{matchedCheat}' " +
                                     "and indicates cheating software was present on this system.",
                            Detail = $"File: {file} | Matched pattern: {matchedCheat}"
                        });
                        continue;
                    }

                    // Heuristic: files in game dirs with cheat-indicative names
                    var fnLower = fn.ToLowerInvariant();
                    if ((fnLower.Contains("aimbot") || fnLower.Contains("wallhack") ||
                         fnLower.Contains("triggerbot") || fnLower.Contains("esp_cs") ||
                         fnLower.Contains("bhop") || fnLower.Contains("vac_bypass") ||
                         fnLower.Contains("skinchanger")) &&
                        (fn.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                         fn.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                         fn.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"CS2 Suspicious File (Heuristic): {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"File '{fn}' contains cheat-related keywords (aimbot, wallhack, " +
                                     "triggerbot, esp, bhop, vac_bypass, skinchanger) in its name " +
                                     $"and was found in a CS2-related scan path: '{dir}'. " +
                                     "This is a strong heuristic indicator of cheat software.",
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
                    Title = $"CS2 Cheat Process Running: {pname}",
                    Risk = RiskLevel.Critical,
                    Location = procPath.Length > 0 ? procPath : $"PID {proc.Id}",
                    FileName = pname,
                    Reason = $"Known CS2 cheat process '{pname}' is currently running (PID {proc.Id}). " +
                             $"Process matches known cheat pattern '{matched}'. " +
                             "This is a live cheat tool that is actively loaded into memory.",
                    Detail = $"PID: {proc.Id} | Name: {pname} | Path: {procPath}"
                });
            }
        }, ct);

    private Task CheckVacBypassDriversAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // Check system32\drivers for VAC bypass driver files
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
                    var matched = VacBypassDriverNames.FirstOrDefault(d =>
                        fn.Equals(d, StringComparison.OrdinalIgnoreCase));

                    if (matched is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"VAC Bypass Driver Found: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known VAC bypass kernel driver '{fn}' was found in the system " +
                                     $"drivers directory. This driver is used to intercept and neutralize " +
                                     "Valve Anti-Cheat (VAC) scanning, allowing cheats to operate " +
                                     "undetected. Matched pattern: " + matched,
                            Detail = $"Driver path: {file}"
                        });
                    }
                }
            }

            // Check registry services for VAC bypass drivers
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

                        var matched = VacBypassDriverNames.FirstOrDefault(d =>
                            imgPath.Contains(d, StringComparison.OrdinalIgnoreCase) ||
                            svcName.Contains(d.Replace(".sys", ""), StringComparison.OrdinalIgnoreCase));

                        if (matched is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"VAC Bypass Driver Service: {svcName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = svcName,
                                Reason = $"Kernel driver service '{svcName}' matches a known VAC bypass " +
                                         $"driver pattern. ImagePath: '{imgPath}'. " +
                                         "VAC bypass drivers operate at kernel level to intercept anti-cheat scanning.",
                                Detail = $"Service: {svcName} | ImagePath: {imgPath} | Matched: {matched}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);

    private Task CheckSteamRegistryLaunchOptionsAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // Check for -insecure flag in Steam CS2 launch options
            var steamAppsRegPaths = new[]
            {
                @"SOFTWARE\Valve\Steam\Apps\730",
                @"SOFTWARE\WOW6432Node\Valve\Steam\Apps\730",
            };

            foreach (var regPath in steamAppsRegPaths)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(regPath, writable: false)
                                 ?? Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                    if (key is null) continue;

                    ctx.IncrementRegistryKeys();
                    var launchOptions = key.GetValue("LaunchOptions") as string ?? "";

                    if (launchOptions.Contains("-insecure", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "CS2 Launch Options: -insecure Flag Detected",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{regPath}",
                            Reason = "CS2 (AppID 730) Steam launch options contain the '-insecure' flag. " +
                                     "This flag disables VAC (Valve Anti-Cheat) for the game session, " +
                                     "which is a prerequisite for running unsigned cheat software without " +
                                     "VAC bans. Legitimate players have no need for this flag.",
                            Detail = $"LaunchOptions: {launchOptions}"
                        });
                    }

                    if (launchOptions.Contains("-allow_third_party_software", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "CS2 Launch Options: -allow_third_party_software Flag",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKCU\{regPath}",
                            Reason = "CS2 launch options contain '-allow_third_party_software', which " +
                                     "reduces game protection and can be used alongside cheat loaders. " +
                                     "This flag is sometimes set by cheat installer scripts.",
                            Detail = $"LaunchOptions: {launchOptions}"
                        });
                    }
                }
                catch { }
            }

            // Also check for CS2 launch options in Steam config
            try
            {
                var steamPath = Registry.GetValue(
                    @"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string;
                if (steamPath is null) return;

                var localConfigVdf = Path.Combine(steamPath, "userdata");
                if (!Directory.Exists(localConfigVdf)) return;

                foreach (var userDir in Directory.GetDirectories(localConfigVdf))
                {
                    ct.ThrowIfCancellationRequested();
                    var configFile = Path.Combine(userDir, "config", "localconfig.vdf");
                    if (!File.Exists(configFile)) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = sr.ReadToEnd();
                    }
                    catch (IOException) { continue; }

                    ctx.IncrementFiles();

                    if (content.Contains("-insecure", StringComparison.OrdinalIgnoreCase) &&
                        content.Contains("730", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "CS2 -insecure Flag in Steam localconfig.vdf",
                            Risk = RiskLevel.High,
                            Location = configFile,
                            FileName = "localconfig.vdf",
                            Reason = "Steam localconfig.vdf contains '-insecure' in the context of " +
                                     "CS2 (App 730) launch options. This disables VAC protection " +
                                     "and is a known cheat-enablement technique.",
                            Detail = $"Config file: {configFile}"
                        });
                    }
                }
            }
            catch { }
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
                                    Title = $"CS2 Cheat Loader in Run Key: {valueName}",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"{(root == Registry.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}\{valueName}",
                                    FileName = valueName,
                                    Reason = $"Registry Run key entry '{valueName}' references a known CS2 cheat " +
                                             $"loader. Command: '{value}'. This establishes persistence for the " +
                                             "cheat tool, causing it to start automatically with Windows or Steam.",
                                    Detail = $"Key: {keyPath}\\{valueName} | Value: {value} | Matched: {cheatMatch}"
                                });
                                continue;
                            }

                            // Heuristic: CS2-related executables in Run keys from suspicious paths
                            if ((value.Contains("cs2", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("csgo", StringComparison.OrdinalIgnoreCase)) &&
                                (value.Contains("loader", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("injector", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("hack", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Suspicious CS2-Related Run Key: {valueName}",
                                    Risk = RiskLevel.High,
                                    Location = $@"{(root == Registry.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}\{valueName}",
                                    FileName = valueName,
                                    Reason = $"Registry Run key '{valueName}' references a CS2/CSGO-related " +
                                             $"executable with suspicious keywords (loader/injector/bypass/cheat/hack). " +
                                             $"Command: '{value}'. This pattern is consistent with cheat persistence.",
                                    Detail = $"Value: {value}"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
        }, ct);

    private Task CheckCS2AutoexecConfigAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var steamPath = Registry.GetValue(
                @"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string;

            var cfgPaths = new List<string>();

            if (steamPath is not null)
            {
                // Standard CS2 cfg path inside steamapps
                var cs2CfgPath = Path.Combine(
                    steamPath, "steamapps", "common",
                    "Counter-Strike Global Offensive", "game", "csgo", "cfg");
                cfgPaths.Add(cs2CfgPath);

                var cs2CfgPathAlt = Path.Combine(
                    steamPath, "steamapps", "common",
                    "Counter-Strike Global Offensive", "csgo", "cfg");
                cfgPaths.Add(cs2CfgPathAlt);
            }

            // Standard drive paths
            foreach (var drive in new[] { @"C:\", @"D:\", @"E:\", @"F:\" })
            {
                cfgPaths.Add(Path.Combine(drive, "Program Files (x86)", "Steam", "steamapps",
                    "common", "Counter-Strike Global Offensive", "game", "csgo", "cfg"));
                cfgPaths.Add(Path.Combine(drive, "SteamLibrary", "steamapps",
                    "common", "Counter-Strike Global Offensive", "game", "csgo", "cfg"));
            }

            foreach (var cfgDir in cfgPaths)
            {
                if (!Directory.Exists(cfgDir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] cfgFiles;
                try { cfgFiles = Directory.GetFiles(cfgDir, "*.cfg", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var cfgFile in cfgFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(cfgFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var fn = Path.GetFileName(cfgFile);
                    foreach (var suspCmd in SuspiciousAutoexecCommands)
                    {
                        if (!content.Contains(suspCmd, StringComparison.OrdinalIgnoreCase)) continue;

                        // Ignore if this is a comment line
                        var lines = content.Split('\n');
                        bool inActive = lines.Any(l =>
                        {
                            var trimmed = l.TrimStart();
                            return !trimmed.StartsWith("//") &&
                                   trimmed.Contains(suspCmd, StringComparison.OrdinalIgnoreCase);
                        });

                        if (!inActive) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"CS2 Config with Cheat Command: {fn}",
                            Risk = suspCmd.Contains("sv_cheats", StringComparison.OrdinalIgnoreCase)
                                ? RiskLevel.High : RiskLevel.Medium,
                            Location = cfgFile,
                            FileName = fn,
                            Reason = $"CS2 configuration file '{fn}' contains the suspicious command " +
                                     $"'{suspCmd}'. This command is associated with cheat functionality " +
                                     "or enables server-side cheat flags that should never appear in " +
                                     "a legitimate player's config file.",
                            Detail = $"File: {cfgFile} | Command: {suspCmd}"
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckHostsFileVacBlockingAsync(ScanContext ctx, CancellationToken ct) =>
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

            foreach (var vacHost in HostsFileVacEntries)
            {
                if (!content.Contains(vacHost, StringComparison.OrdinalIgnoreCase)) continue;

                // Check it's not just a comment
                var lines = content.Split('\n');
                foreach (var line in lines)
                {
                    var trimmed = line.TrimStart();
                    if (trimmed.StartsWith("#")) continue;
                    if (!trimmed.Contains(vacHost, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Hosts File Blocking VAC/Steam Server: {vacHost}",
                        Risk = RiskLevel.High,
                        Location = hostsPath,
                        FileName = "hosts",
                        Reason = $"The Windows hosts file contains an active entry redirecting or blocking " +
                                 $"'{vacHost}'. This is a known technique used by VAC bypass tools to " +
                                 "prevent Valve Anti-Cheat from reporting cheat detection data to Valve's " +
                                 "servers, effectively neutralizing VAC's cloud reporting capability.",
                        Detail = $"Hosts entry: {trimmed.Trim()} | Blocked host: {vacHost}"
                    });
                    break;
                }
            }
        }, ct);

    private Task CheckSteamBinCheatDllsAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var steamPath = Registry.GetValue(
                @"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string;

            if (steamPath is null) return;

            var steamBinPaths = new[]
            {
                Path.Combine(steamPath, "bin"),
                Path.Combine(steamPath, "bin", "cef"),
                Path.Combine(steamPath, "steamapps", "common",
                    "Counter-Strike Global Offensive", "bin", "win64"),
                Path.Combine(steamPath, "steamapps", "common",
                    "Counter-Strike Global Offensive", "game", "bin", "win64"),
                Path.Combine(steamPath, "steamapps", "common",
                    "Counter-Strike Global Offensive", "csgo", "bin"),
            };

            foreach (var binDir in steamBinPaths)
            {
                if (!Directory.Exists(binDir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try { files = Directory.GetFiles(binDir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    // Check for known backup/replacement DLL patterns
                    var matchedBackup = CS2SteamBinCheatDlls.FirstOrDefault(d =>
                        fn.Equals(d, StringComparison.OrdinalIgnoreCase));
                    if (matchedBackup is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"CS2 Replaced DLL Backup Found: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"A backup of a core CS2/Steam DLL '{fn}' was found in the Steam bin " +
                                     "directory. Cheat tools typically rename legitimate DLLs to '.bak' " +
                                     "when replacing them with hooked/modified versions. " +
                                     "This is a strong indicator of DLL replacement attack.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    // Check for unknown DLLs in Steam bin (injected components)
                    if (fn.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    {
                        var fnLower = fn.ToLowerInvariant();
                        foreach (var cheatFile in KnownCheatFileNames)
                        {
                            if (fnLower.Equals(cheatFile, StringComparison.OrdinalIgnoreCase) ||
                                fnLower.Contains(cheatFile.Replace(".dll", "").Replace(".exe", ""),
                                    StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"CS2 Cheat DLL in Steam Bin: {fn}",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = $"Known CS2 cheat DLL '{fn}' found inside Steam's binary " +
                                             "directory. Cheat tools place DLLs here to get them loaded " +
                                             "automatically when CS2 or Steam starts, bypassing injection detection.",
                                    Detail = $"Path: {file} | Matched: {cheatFile}"
                                });
                                break;
                            }
                        }
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
                try
                {
                    files = Directory.GetFiles(tempDir, "*", SearchOption.TopDirectoryOnly);
                }
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
                        Title = $"CS2 Cheat Artifact in Temp Folder: {fn}",
                        Risk = ext is ".exe" or ".dll" or ".sys"
                            ? RiskLevel.High : RiskLevel.Medium,
                        Location = file,
                        FileName = fn,
                        Reason = $"File '{fn}' in the temp folder contains CS2 cheat-related keywords " +
                                 $"(matched: '{matchedArtifact}'). Cheat tools commonly extract and execute " +
                                 "from temp directories to avoid detection and leave minimal traces " +
                                 "on the main file system.",
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
                                Title = $"UserAssist: CS2 Cheat Executed — {keyword}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"Windows UserAssist forensic record shows execution of CS2 cheat " +
                                         $"tool matching '{keyword}'. Decoded entry: '{decoded}'. " +
                                         $"Execution count: {runCount}. " +
                                         (lastRun.HasValue
                                             ? $"Last executed: {lastRun.Value:yyyy-MM-dd HH:mm} UTC. "
                                             : "") +
                                         "UserAssist entries persist even after the file is deleted.",
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
                        Title = $"MuiCache: CS2 Cheat Tool Executed: {Path.GetFileName(path)}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{muiCacheKey}",
                        FileName = Path.GetFileName(path),
                        Reason = $"MuiCache entry proves execution of CS2 cheat tool '{Path.GetFileName(path)}' " +
                                 $"(keyword match: '{keyword}'). " +
                                 (fileExists
                                     ? "The file still exists on disk."
                                     : "The file has been deleted, but its execution is forensically recorded.") +
                                 " MuiCache records survive file deletion.",
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
                var fnLower = fn.ToLowerInvariant();

                var matchedCheat = KnownCheatFileNames.FirstOrDefault(c =>
                    fn.Equals(c, StringComparison.OrdinalIgnoreCase));

                if (matchedCheat is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 Cheat Download Found: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known CS2 cheat file '{fn}' found in the Downloads folder. " +
                                 "This indicates the user downloaded this cheat tool from the internet. " +
                                 $"Matched known cheat pattern: '{matchedCheat}'.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                // Heuristic: archives/executables in downloads with cheat keyword patterns
                var ext = Path.GetExtension(fn).ToLowerInvariant();
                if (ext is not (".exe" or ".dll" or ".zip" or ".rar" or ".7z")) continue;

                var cheatHit = TempCheatArtifactPatterns.FirstOrDefault(p =>
                    fnLower.Contains(p, StringComparison.OrdinalIgnoreCase));

                if (cheatHit is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 Suspicious Download: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"File '{fn}' in Downloads folder contains CS2 cheat-related keywords " +
                                 $"(matched: '{cheatHit}'). Downloaded archives and executables with " +
                                 "cheat-related names in Downloads are a strong indicator of attempted " +
                                 "or completed cheat tool installation.",
                        Detail = $"Path: {file} | Pattern: {cheatHit}"
                    });
                }
            }
        }, ct);

    private Task CheckSteamWorkshopInjectionAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var steamPath = Registry.GetValue(
                @"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string;
            if (steamPath is null) return;

            // CS2 Steam Workshop content for App 730
            var workshopPath = Path.Combine(
                steamPath, "steamapps", "workshop", "content", "730");

            if (!Directory.Exists(workshopPath)) return;
            ct.ThrowIfCancellationRequested();

            var suspiciousExtensions = new[] { ".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs" };

            try
            {
                foreach (var workshopItem in Directory.GetDirectories(workshopPath))
                {
                    ct.ThrowIfCancellationRequested();
                    string[] itemFiles;
                    try { itemFiles = Directory.GetFiles(workshopItem, "*", SearchOption.AllDirectories); }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var file in itemFiles)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        var ext = Path.GetExtension(fn).ToLowerInvariant();

                        if (!suspiciousExtensions.Contains(ext)) continue;

                        var fnLower = fn.ToLowerInvariant();
                        var cheatMatch = KnownCheatFileNames.FirstOrDefault(c =>
                            fn.Equals(c, StringComparison.OrdinalIgnoreCase));

                        if (cheatMatch is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"CS2 Cheat in Steam Workshop Item: {fn}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fn,
                                Reason = $"Known CS2 cheat file '{fn}' found inside a Steam Workshop " +
                                         "content item. Some cheats exploit the Workshop delivery " +
                                         "mechanism to distribute malicious DLLs or executables " +
                                         "through legitimate-looking Workshop subscriptions.",
                                Detail = $"Workshop item: {Path.GetDirectoryName(file)} | File: {file}"
                            });
                            continue;
                        }

                        if (ext == ".exe" || ext == ".dll" || ext == ".sys")
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Executable in CS2 Workshop Item: {fn}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = fn,
                                Reason = $"Executable/DLL file '{fn}' ({ext}) found inside a CS2 Steam Workshop " +
                                         "content folder. CS2 Workshop items should only contain map, model, and " +
                                         "script files. Executable files in Workshop content are unusual and " +
                                         "may indicate a weaponized Workshop item.",
                                Detail = $"Workshop path: {workshopItem} | File: {file}"
                            });
                        }
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckCS2AppDataAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var appDataPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Counter-Strike 2"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Counter-Strike Global Offensive"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Counter-Strike Global Offensive"),
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

                    // Flag known cheat files
                    var cheatMatch = KnownCheatFileNames.FirstOrDefault(c =>
                        fn.Equals(c, StringComparison.OrdinalIgnoreCase));
                    if (cheatMatch is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"CS2 Cheat in AppData: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known CS2 cheat file '{fn}' found in CS2 AppData directory. " +
                                     $"Matched pattern: '{cheatMatch}'. Cheat tools store configuration, " +
                                     "logs, and sometimes their own binaries in game AppData folders.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    // Flag suspicious executables/DLLs in AppData
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
                                Title = $"Suspicious Executable in CS2 AppData: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Executable/DLL '{fn}' with cheat-related keyword '{heuristicHit}' " +
                                         "found in CS2 AppData directory. Cheat loaders frequently place " +
                                         "payloads inside game AppData paths to blend in with legitimate " +
                                         "game data and avoid detection.",
                                Detail = $"Path: {file} | Pattern: {heuristicHit}"
                            });
                        }
                    }

                    // Check for cheat config files stored in AppData
                    if (ext is ".json" or ".cfg" or ".ini" or ".toml" or ".yaml")
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
                                Title = $"CS2 Cheat Config in AppData: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Configuration file '{fn}' in CS2 AppData contains cheat-specific " +
                                         $"keyword '{cheatConfigHit}'. Cheat tools store their settings in " +
                                         "config files alongside game data. This config file was likely " +
                                         "created by a CS2 cheat tool.",
                                Detail = $"Path: {file} | Config keyword: {cheatConfigHit}"
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckCheatConfigFilesAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            // Scan common cheat config storage locations
            var configSearchPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "cs2cheats"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "skeet"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "fatality"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "neverlose"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "onetap"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "aimware"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "gamesense"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "nixware"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "interwebz"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "lumina"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "cs2cheats"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "skeet"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "fatality"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "neverlose"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "onetap"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "aimware"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "gamesense"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "nixware"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "interiumhvh"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "hvhcs2"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".cs2cheats"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".skeet"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".fatality"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".neverlose"),
            };

            foreach (var configPath in configSearchPaths)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(configPath)) continue;

                var dirName = Path.GetFileName(configPath);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"CS2 Cheat Config Folder Found: {dirName}",
                    Risk = RiskLevel.Critical,
                    Location = configPath,
                    FileName = dirName,
                    Reason = $"Folder '{configPath}' is a known configuration directory for CS2 cheat " +
                             $"tool '{dirName}'. The presence of this directory confirms that this cheat " +
                             "was installed and ran on this system, as these directories are only created " +
                             "by the cheat software itself.",
                    Detail = $"Cheat config dir: {configPath}"
                });

                // Also scan files inside
                string[] configFiles;
                try { configFiles = Directory.GetFiles(configPath, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var configFile in configFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(configFile);
                    var ext = Path.GetExtension(fn).ToLowerInvariant();

                    if (ext is ".json" or ".cfg" or ".ini" or ".toml" or ".txt")
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
                                Title = $"CS2 Cheat Config File Content: {fn}",
                                Risk = RiskLevel.High,
                                Location = configFile,
                                FileName = fn,
                                Reason = $"Config file '{fn}' in cheat directory contains cheat-specific " +
                                         $"setting '{cheatConfigHit}'. This config was written by a CS2 " +
                                         "cheat tool and contains settings for cheating features.",
                                Detail = $"Path: {configFile} | Config key: {cheatConfigHit}"
                            });
                        }
                    }
                }
            }
        }, ct);

    private static List<string> BuildCS2ScanPaths()
    {
        var paths = new List<string>();

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        paths.Add(Path.Combine(appData, "Counter-Strike 2"));
        paths.Add(Path.Combine(localAppData, "Counter-Strike Global Offensive"));
        paths.Add(Path.Combine(appData, "Counter-Strike Global Offensive"));
        paths.Add(Path.Combine(userProfile, "Downloads"));

        // Get Steam path from registry
        var steamPath = Registry.GetValue(
            @"HKEY_CURRENT_USER\Software\Valve\Steam", "SteamPath", null) as string;
        if (steamPath is not null)
        {
            paths.Add(Path.Combine(steamPath, "steamapps", "common",
                "Counter-Strike Global Offensive"));
        }

        // Check common Steam install locations across drives
        foreach (var drive in new[] { @"C:\", @"D:\", @"E:\", @"F:\" })
        {
            paths.Add(Path.Combine(drive, "Program Files (x86)", "Steam",
                "steamapps", "common", "Counter-Strike Global Offensive"));
            paths.Add(Path.Combine(drive, "Program Files", "Steam",
                "steamapps", "common", "Counter-Strike Global Offensive"));
            paths.Add(Path.Combine(drive, "SteamLibrary", "steamapps",
                "common", "Counter-Strike Global Offensive"));
            paths.Add(Path.Combine(drive, "Steam", "steamapps",
                "common", "Counter-Strike Global Offensive"));
        }

        return paths;
    }
}
