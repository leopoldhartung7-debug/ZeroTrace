using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class OverwatchCheatForensicDeepScanModule : IScanModule
{
    public string Name => "Overwatch 2 Deep Cheat Forensic Scan";
    public double Weight => 3.7;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string TempPath =
        Path.GetTempPath();
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string Documents =
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static readonly string Downloads =
        Path.Combine(UserProfile, "Downloads");

    private static readonly string[] CheatExecutableNames =
    {
        "ow2_cheat.exe",
        "ow_aimbot.exe",
        "ow2_esp.dll",
        "ow_wh.exe",
        "owcheat.exe",
        "overwatch_hack.exe",
        "ow2_trigger.exe",
        "ow2_wallhack.dll",
        "ow2_aim.exe",
        "ow2_esp.exe",
        "ow2_tracker.exe",
        "ow2_killbot.exe",
        "ow_maphack.dll",
        "ow_radar.exe",
        "ana_sleep_bot.exe",
        "dva_matrix_bot.exe",
        "mercy_boost_bot.exe",
        "ow2_aimassist.exe",
        "ow2_spinbot.exe",
        "ow2_bhop.exe",
        "ow2_noclip.exe",
        "overwatch_injector.exe",
        "ow2_loader.exe",
        "ow2_bypass.exe",
        "ow_silent_aim.exe",
        "ow2_silent_aim.exe",
        "ow2_fov_aimbot.exe",
        "ow2_bone_aimbot.exe",
        "ow2_prediction.exe",
        "ow_prediction.exe",
        "ow2_recoil.dll",
        "ow2_triggerbot.exe",
        "ow2_cheats.dll",
        "overwatch2_hack.exe",
        "ow2_player_esp.exe",
        "ow_internal.dll",
        "ow2_internal.dll",
        "ow2_external.exe",
        "ow_external.exe",
        "ow2_driver_cheat.sys",
        "ow2_kernel_cheat.sys",
        "ow2_hvh.exe",
        "ow_hvh.exe",
        "ow2_rage.exe",
        "ow2_legit.exe",
        "ow_boost.exe",
        "ow2_boost.exe",
        "ow2_rankboost.exe",
        "ow_rankboost.exe",
        "owcheat64.exe",
        "ow2cheat64.exe",
    };

    private static readonly string[] WardenBypassNames =
    {
        "ow2_warden_bypass.dll",
        "ow2_anticheat_bypass.dll",
        "ow2_vanguard_bypass.dll",
        "ow_warden_bypass.dll",
        "ow_anticheat_bypass.dll",
        "ow2_warden_spoofer.dll",
        "ow2_warden_killer.dll",
        "warden_bypass_ow2.dll",
        "anticheat_bypass_ow2.exe",
        "ow2_ricochet_bypass.dll",
        "ricochet_bypass.dll",
        "ow_ricochet_bypass.dll",
        "ow2_kernel_bypass.sys",
        "ow2_eac_bypass.dll",
        "ow2_be_bypass.dll",
    };

    private static readonly string[] BnetBypassNames =
    {
        "bnet_bypass.dll",
        "battle_net_bypass.exe",
        "battlenet_bypass.dll",
        "bnet_patcher.exe",
        "battlenet_patcher.exe",
        "bnet_hook.dll",
        "battle_net_hook.dll",
        "bnet_injector.exe",
        "battle_net_injector.dll",
        "bnet_launcher_bypass.dll",
        "ow2_launcher_bypass.dll",
        "ow_launcher_bypass.exe",
    };

    private static readonly string[] MacroScriptNames =
    {
        "ow2_macro.ahk",
        "ow2_rapidfire.ahk",
        "ow2_triggerbot.ahk",
        "ow2_aim_macro.py",
        "ow_macro.ahk",
        "ow_triggerbot.ahk",
        "ow2_aim.ahk",
        "ow_aim.ahk",
        "ow2_norecoil.ahk",
        "ow_norecoil.ahk",
        "ow2_bhop.ahk",
        "ow_bhop.ahk",
        "ow2_triggerbot.py",
        "ow2_aimbot.py",
        "ow_aimbot.py",
        "ow2_pixel_aim.py",
        "ow_pixel_aim.py",
        "ow2_bot.ahk",
        "ow2_bot.py",
        "ow_bot.py",
        "overwatch_macro.ahk",
        "overwatch_bot.py",
    };

    private static readonly string[] PixelAimBotKeywords =
    {
        "pyautogui",
        "autopy",
        "mss.mss",
        "ImageGrab",
        "screen_grab",
        "win32api.mouse_event",
        "ctypes.windll.user32.mouse_event",
        "SendInput",
        "overwatch",
        "ow2",
        "enemy_color",
        "pixel_color",
        "screen_color",
        "aimbot",
        "triggerbot",
        "trigger_bot",
        "aim_bot",
        "find_enemy",
        "detect_enemy",
        "color_detect",
        "team_color",
        "hp_bar",
        "kill_confirm",
        "opencv",
        "cv2.inRange",
        "np.where",
    };

    private static readonly string[] SoftAimbotConfigKeywords =
    {
        "fov=",
        "fov =",
        "smoothing=",
        "smooth=",
        "smooth =",
        "bone=head",
        "bone = head",
        "bone=nearest",
        "bone = nearest",
        "target_bone",
        "aim_fov",
        "aimfov",
        "aim_smooth",
        "aimsmooth",
        "triggerkey",
        "trigger_key",
        "aimkey",
        "aim_key",
        "prediction=",
        "prediction =",
        "auto_fire",
        "autofire",
        "no_recoil",
        "norecoil",
        "recoil_control",
        "recoil=",
        "esp_enabled",
        "wallhack=",
        "wallhack =",
        "radar_hack",
        "radarhack",
        "chams=",
        "chams =",
        "glow=",
        "glow =",
    };

    private static readonly string[] Ow2ConfigCheatKeywords =
    {
        "aimbot",
        "triggerbot",
        "wallhack",
        "esp",
        "noclip",
        "godmode",
        "speedhack",
        "bypass",
        "cheat",
        "hack",
        "inject",
        "aimassist",
        "aim_assist",
        "fov_override",
        "smooth_aim",
    };

    private static readonly string[] AccountBoostBotKeywords =
    {
        "boost_bot",
        "boostbot",
        "rank_bot",
        "rankbot",
        "sr_bot",
        "account_boost",
        "accountboost",
        "ow_boost",
        "ow2_boost",
        "auto_queue",
        "autoqueue",
        "afk_bot",
        "afkbot",
        "grind_bot",
        "grindbot",
        "competitive_bot",
        "ladder_bot",
    };

    private static readonly string[] BnetLogCheatKeywords =
    {
        "bypass",
        "inject",
        "patch",
        "cheat",
        "hack",
        "spoof",
        "tamper",
        "anticheat",
        "warden",
        "ricochet",
        "aimbot",
        "wallhack",
        "triggerbot",
        "loader",
    };

    private static readonly string[] UserAssistCheatNames =
    {
        "ow2_cheat",
        "ow_aimbot",
        "owcheat",
        "overwatch_hack",
        "ow2_trigger",
        "ow2_wallhack",
        "ow2_esp",
        "ow2_aim",
        "ow2_loader",
        "ow2_bypass",
        "ow_wh",
        "ow_radar",
        "ow2_tracker",
        "ow2_killbot",
        "ana_sleep_bot",
        "dva_matrix_bot",
        "mercy_boost_bot",
        "ow2_warden_bypass",
        "ow2_anticheat_bypass",
        "bnet_bypass",
        "battle_net_bypass",
        "ow2_macro",
        "ow2_rapidfire",
        "ow2_triggerbot",
        "ow2_aimassist",
        "ow2_spinbot",
        "ow2_bhop",
        "overwatch_injector",
        "ow2_boost",
        "ow_boost",
        "ow2_rankboost",
        "ricochet_bypass",
        "ow2_pixel_aim",
        "overwatch_bot",
        "ow2_bot",
    };

    private static readonly string[] MuiCacheCheatKeywords =
    {
        "ow2_cheat",
        "ow_aimbot",
        "ow2_aimbot",
        "owcheat",
        "overwatch_hack",
        "ow2_trigger",
        "ow2_wallhack",
        "ow2_esp",
        "ow2_loader",
        "ow2_bypass",
        "ow_wh",
        "ow_radar",
        "ow2_tracker",
        "ow2_boost",
        "ow2_rankboost",
        "ow2_warden_bypass",
        "ow2_anticheat_bypass",
        "bnet_bypass",
        "ow2_macro",
        "ow2_triggerbot",
        "ow2_aimassist",
        "ricochet_bypass",
        "ow2_pixel_aim",
        "mercy_boost_bot",
        "dva_matrix_bot",
        "ana_sleep_bot",
        "ow2_silent_aim",
        "ow2_spinbot",
        "ow2_bhop",
    };

    private static readonly string[] RunKeyCheatNames =
    {
        "ow2_cheat",
        "ow_aimbot",
        "ow2_aimbot",
        "owcheat",
        "overwatch_hack",
        "ow2_loader",
        "ow2_bypass",
        "ow2_trigger",
        "ow2_warden_bypass",
        "ow2_anticheat_bypass",
        "bnet_bypass",
        "ow2_triggerbot",
        "ow2_aimassist",
        "ow2_boost",
        "ow2_rankboost",
        "ricochet_bypass",
        "ow2_pixel_aim",
        "overwatch_bot",
        "ow2_bot",
        "ow2_spinbot",
    };

    private static readonly string[] TempCheatKeywords =
    {
        "ow2",
        "ow_",
        "overwatch",
        "aimbot",
        "triggerbot",
        "wallhack",
        "esp_",
        "_esp",
        "bypass",
        "cheat",
        "hack",
        "inject",
        "loader",
        "bnet_bypass",
        "warden_bypass",
        "ricochet",
        "ow2_warden",
        "ow2_anticheat",
        "ow2_loader",
        "ow2_driver",
        "ow2_kernel",
        "mercy_boost",
        "dva_matrix",
        "ana_sleep",
    };

    private static readonly string[] AimTrainingBypassKeywords =
    {
        "training_bypass",
        "practice_mode_bypass",
        "practice_range_aim",
        "ow2_aim_trainer",
        "training_mode_cheat",
        "aimhero_bypass",
        "aim_lab_bypass",
        "training_aimbot",
        "mechanical_aimbot",
        "aim_override",
        "practice_range_hack",
        "workshop_bypass",
        "workshop_cheat",
        "ow2_workshop_hack",
    };

    private const string UserAssistBase =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
    private const string MuiCacheKey =
        @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
    private const string UninstallKeyLm =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string UninstallKeyWow =
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string RunKeyLm =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string RunKeyHkcu =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOnceLm =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";

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

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Overwatch 2 deep forensic scan...");

        return Task.WhenAll(
            CheckCheatExecutables(ctx, ct),
            CheckWardenBypassArtifacts(ctx, ct),
            CheckBattleNetBypassArtifacts(ctx, ct),
            CheckMacroScriptArtifacts(ctx, ct),
            CheckOw2ConfigFile(ctx, ct),
            CheckAimTrainingBypassArtifacts(ctx, ct),
            CheckAccountBoostBotArtifacts(ctx, ct),
            CheckSoftAimbotConfigFiles(ctx, ct),
            CheckUserAssistRegistry(ctx, ct),
            CheckMuiCacheRegistry(ctx, ct),
            CheckRunKeyRegistry(ctx, ct),
            CheckUninstallRegistry(ctx, ct),
            CheckTempFolderArtifacts(ctx, ct),
            CheckBattleNetLogs(ctx, ct),
            CheckPixelAimbotScripts(ctx, ct),
            CheckCheatDirectoryArtifacts(ctx, ct),
            CheckOw2DriverArtifacts(ctx, ct),
            CheckOw2PrefetchArtifacts(ctx, ct)
        );
    }

    private Task CheckCheatExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.05, Name, "Scanning for OW2 cheat executables...");

            var searchRoots = new[]
            {
                UserProfile,
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(AppData, "Battle.net"),
                Path.Combine(LocalAppData, "Battle.net"),
                Path.Combine(LocalAppData, "Blizzard Entertainment"),
                Path.Combine(AppData, "Blizzard Entertainment"),
                Path.Combine(LocalAppData, "Overwatch"),
                "C:\\",
            };

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var match = CheatExecutableNames.FirstOrDefault(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"OW2 Cheat Executable Found: {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Known Overwatch 2 cheat executable '{fileName}' was found at '{file}'. " +
                                       "This binary is a well-known cheat tool targeting Overwatch 2 and " +
                                       "constitutes a direct forensic artifact of cheat software installation " +
                                       "or use. The file matches the known artifact list for OW2 cheats " +
                                       "including aimbots, ESPs, wallhacks, triggerbots, and similar tools.",
                            Detail   = $"Matched artifact: {match} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            var deepRoots = new[]
            {
                Desktop,
                Downloads,
                Documents,
                Path.Combine(UserProfile, "Games"),
                Path.Combine(UserProfile, "Cheats"),
                Path.Combine(UserProfile, "Hacks"),
                Path.Combine(UserProfile, "OW2"),
                Path.Combine(UserProfile, "Overwatch"),
            };

            foreach (var root in deepRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var match = CheatExecutableNames.FirstOrDefault(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"OW2 Cheat Executable (Deep): {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Known Overwatch 2 cheat executable '{fileName}' found during deep scan " +
                                       $"at '{file}'. This is a direct forensic artifact indicating cheat tool " +
                                       "installation or use against Overwatch 2.",
                            Detail   = $"Matched artifact: {match} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            ctx.Report(0.1, Name, "OW2 cheat executable check complete.");
        }, ct);

    private Task CheckWardenBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.1, Name, "Checking for Warden/anti-cheat bypass artifacts...");

            var searchDirs = new[]
            {
                UserProfile,
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(AppData, "Battle.net"),
                Path.Combine(LocalAppData, "Battle.net"),
                Path.Combine(LocalAppData, "Blizzard Entertainment"),
                Path.Combine(AppData, "Blizzard Entertainment"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var match = WardenBypassNames.FirstOrDefault(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"OW2 Anti-Cheat Bypass Artifact: {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Overwatch 2 anti-cheat bypass artifact '{fileName}' found at '{file}'. " +
                                       "This file is specifically designed to disable, circumvent, or neutralize " +
                                       "Blizzard's Warden anti-cheat system or other anti-cheat components " +
                                       "active in Overwatch 2. Discovery of this artifact constitutes strong " +
                                       "forensic evidence of deliberate anti-cheat evasion.",
                            Detail   = $"Matched bypass artifact: {match} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            ctx.Report(0.15, Name, "Warden bypass check complete.");
        }, ct);

    private Task CheckBattleNetBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.15, Name, "Checking for Battle.net launcher bypass artifacts...");

            var searchDirs = new[]
            {
                UserProfile,
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(AppData, "Battle.net"),
                Path.Combine(LocalAppData, "Battle.net"),
                Path.Combine(LocalAppData, "Blizzard Entertainment"),
                Path.Combine(ProgramFilesDir(), "Battle.net"),
                Path.Combine(ProgramFilesDir(), "Blizzard Entertainment"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var match = BnetBypassNames.FirstOrDefault(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Battle.net Launcher Bypass Artifact: {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Battle.net launcher bypass artifact '{fileName}' found at '{file}'. " +
                                       "This file is designed to intercept, patch, or bypass the Battle.net " +
                                       "launcher's integrity checks before or during Overwatch 2 launch, " +
                                       "enabling unauthorized modifications or cheat tools to load undetected. " +
                                       "This constitutes a critical forensic indicator of cheat infrastructure.",
                            Detail   = $"Matched artifact: {match} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            ctx.Report(0.2, Name, "Battle.net bypass check complete.");
        }, ct);

    private Task CheckMacroScriptArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.2, Name, "Scanning for OW2 macro/script artifacts...");

            var searchDirs = new[]
            {
                UserProfile,
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(AppData, "AutoHotkey"),
                Path.Combine(Documents, "AutoHotkey"),
                Path.Combine(AppData, "Logitech", "GHUB", "profiles"),
                Path.Combine(AppData, "Logitech Gaming Software", "profiles"),
                Path.Combine(UserProfile, "Scripts"),
                Path.Combine(UserProfile, "Macros"),
                Path.Combine(UserProfile, "OW2"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var match = MacroScriptNames.FirstOrDefault(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"OW2 Macro Script Found: {fileName}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason   = $"Overwatch 2 macro/automation script '{fileName}' found at '{file}'. " +
                                           "This script file is a known artifact of OW2 macro cheating " +
                                           "including rapid-fire, triggerbot, aim macros, or no-recoil scripts " +
                                           "that automate gameplay actions to gain an unfair competitive advantage.",
                                Detail   = $"Matched script: {match} | Path: {file}"
                            });
                            continue;
                        }

                        var ext = Path.GetExtension(fileName);
                        if (!ext.Equals(".ahk", StringComparison.OrdinalIgnoreCase) &&
                            !ext.Equals(".py", StringComparison.OrdinalIgnoreCase) &&
                            !ext.Equals(".au3", StringComparison.OrdinalIgnoreCase)) continue;

                        if (!fileName.Contains("ow", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("overwatch", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("aimbot", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("triggerbot", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("wallhack", StringComparison.OrdinalIgnoreCase)) continue;

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = sr.ReadToEnd();

                            var keyword = SoftAimbotConfigKeywords.FirstOrDefault(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (keyword is null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"OW2 Macro Script with Cheat Keywords: {fileName}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason   = $"Script file '{fileName}' has Overwatch-related name and contains " +
                                           $"cheat configuration keyword '{keyword}'. This script appears to " +
                                           "implement or configure automated cheating functionality for OW2.",
                                Detail   = $"Keyword: {keyword} | Path: {file}"
                            });
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            ctx.Report(0.25, Name, "OW2 macro script check complete.");
        }, ct);

    private Task CheckOw2ConfigFile(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.25, Name, "Scanning OW2 settings64.ini for cheat indicators...");

            var configPaths = new[]
            {
                Path.Combine(Documents, "Overwatch", "Settings", "Settings_v0.ini"),
                Path.Combine(Documents, "Overwatch", "Settings", "Settings_v1.ini"),
                Path.Combine(Documents, "Overwatch", "Settings", "Settings64.ini"),
                Path.Combine(Documents, "Overwatch", "Settings", "settings64.ini"),
                Path.Combine(Documents, "Overwatch", "Settings", "Settings.ini"),
                Path.Combine(AppData, "Blizzard Entertainment", "Overwatch", "Settings", "Settings_v0.ini"),
                Path.Combine(AppData, "Blizzard Entertainment", "Overwatch", "Settings", "settings64.ini"),
                Path.Combine(LocalAppData, "Blizzard Entertainment", "Overwatch", "Settings", "Settings_v0.ini"),
                Path.Combine(LocalAppData, "Overwatch", "Settings", "Settings_v0.ini"),
                Path.Combine(LocalAppData, "Overwatch", "Settings", "settings64.ini"),
            };

            foreach (var configPath in configPaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!File.Exists(configPath)) continue;

                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = sr.ReadToEnd();

                    var keyword = Ow2ConfigCheatKeywords.FirstOrDefault(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (keyword is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"OW2 Config File Contains Cheat Keyword: {keyword}",
                            Risk     = RiskLevel.High,
                            Location = configPath,
                            FileName = Path.GetFileName(configPath),
                            Reason   = $"Overwatch 2 configuration file '{Path.GetFileName(configPath)}' contains " +
                                       $"suspicious keyword '{keyword}' that is not part of any legitimate OW2 " +
                                       "configuration parameter. This indicates the config file has been tampered " +
                                       "with or was generated by cheat software that appends its own configuration " +
                                       "values to the game's settings file.",
                            Detail   = $"Keyword: {keyword} | Config: {configPath}"
                        });
                    }

                    if (AnalyzeOw2ConfigForSuspiciousValues(content, out string suspiciousDetail))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "OW2 Config: Suspicious Parameter Values Detected",
                            Risk     = RiskLevel.Medium,
                            Location = configPath,
                            FileName = Path.GetFileName(configPath),
                            Reason   = $"Overwatch 2 configuration file contains parameter values " +
                                       "outside of normal game-set ranges, which may indicate " +
                                       "manipulation by external tools. " + suspiciousDetail,
                            Detail   = $"Detail: {suspiciousDetail} | Config: {configPath}"
                        });
                    }
                }
                catch (IOException) { }
            }

            ctx.Report(0.3, Name, "OW2 config scan complete.");
        }, ct);

    private static bool AnalyzeOw2ConfigForSuspiciousValues(string content, out string detail)
    {
        detail = string.Empty;
        var sb = new StringBuilder();

        if (content.Contains("MouseSensitivity = 0.000", StringComparison.OrdinalIgnoreCase) ||
            content.Contains("MouseSensitivity=0.000", StringComparison.OrdinalIgnoreCase))
            sb.Append("MouseSensitivity near zero (possible aim assist override). ");

        if (content.Contains("AimEase = ", StringComparison.OrdinalIgnoreCase) &&
            content.Contains("AimEase = 100", StringComparison.OrdinalIgnoreCase))
            sb.Append("AimEase at maximum (100). ");

        if (sb.Length > 0)
        {
            detail = sb.ToString().Trim();
            return true;
        }
        return false;
    }

    private Task CheckAimTrainingBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.3, Name, "Checking for aim training bypass / mechanical aimbot artifacts...");

            var searchDirs = new[]
            {
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(UserProfile, "Scripts"),
                Path.Combine(UserProfile, "Tools"),
                Path.Combine(UserProfile, "Hacks"),
                Path.Combine(AppData, "OW2"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file).ToLowerInvariant();

                        var keyword = AimTrainingBypassKeywords.FirstOrDefault(k =>
                            fileName.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (keyword is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"OW2 Aim Training Bypass Artifact: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"File '{Path.GetFileName(file)}' matches known aim training bypass " +
                                       $"keyword '{keyword}'. These tools exploit Overwatch 2's practice range " +
                                       "and Workshop mode to run mechanical aimbots that manipulate mouse input " +
                                       "under the cover of training, bypassing anti-cheat scrutiny.",
                            Detail   = $"Keyword: {keyword} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            ctx.Report(0.35, Name, "Aim training bypass check complete.");
        }, ct);

    private Task CheckAccountBoostBotArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.35, Name, "Checking for OW2 account boost bot artifacts...");

            var searchDirs = new[]
            {
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(UserProfile, "Bots"),
                Path.Combine(UserProfile, "Boost"),
                Path.Combine(UserProfile, "OW2"),
                Path.Combine(AppData, "OW2Boost"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var keyword = AccountBoostBotKeywords.FirstOrDefault(k =>
                            fileName.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (keyword is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"OW2 Account Boost Bot Artifact: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"File '{fileName}' matches known Overwatch 2 account boost bot " +
                                       $"keyword '{keyword}'. Boost bots automate competitive play to " +
                                       "artificially inflate a player's skill rating (SR/rank), constituting " +
                                       "a direct violation of Overwatch 2 terms of service and competitive " +
                                       "integrity rules.",
                            Detail   = $"Keyword: {keyword} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            ctx.Report(0.4, Name, "Account boost bot check complete.");
        }, ct);

    private Task CheckSoftAimbotConfigFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.4, Name, "Scanning for soft aimbot configuration files...");

            var configExtensions = new[] { ".cfg", ".ini", ".json", ".yaml", ".yml", ".txt", ".xml", ".conf" };

            var searchDirs = new[]
            {
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(UserProfile, "Cheats"),
                Path.Combine(UserProfile, "Hacks"),
                Path.Combine(UserProfile, "OW2"),
                Path.Combine(UserProfile, "Overwatch"),
                Path.Combine(AppData, "OW2"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var ext = Path.GetExtension(file);
                        if (!configExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase)))
                            continue;

                        var fileName = Path.GetFileName(file);
                        if (!fileName.Contains("ow", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("overwatch", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("aim", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("cheat", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("hack", StringComparison.OrdinalIgnoreCase) &&
                            !fileName.Contains("config", StringComparison.OrdinalIgnoreCase)) continue;

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = sr.ReadToEnd();

                            int keywordHits = SoftAimbotConfigKeywords.Count(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (keywordHits < 3) continue;

                            var matchedKeywords = SoftAimbotConfigKeywords
                                .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                                .Take(5)
                                .ToList();

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Soft Aimbot Config File Detected: {fileName}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason   = $"Configuration file '{fileName}' contains {keywordHits} soft aimbot " +
                                           "configuration keywords associated with low-FOV, high-smoothing " +
                                           "aim assistance, bone targeting (head/nearest), and trigger " +
                                           "configuration. This pattern is characteristic of 'soft' or " +
                                           "'legit-looking' aimbots designed to evade manual review.",
                                Detail   = $"Matched keywords: {string.Join(", ", matchedKeywords)} | Path: {file}"
                            });
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            ctx.Report(0.45, Name, "Soft aimbot config check complete.");
        }, ct);

    private Task CheckUserAssistRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.45, Name, "Scanning UserAssist registry for OW2 cheat execution history...");

            try
            {
                using var baseKey = Registry.CurrentUser.OpenSubKey(UserAssistBase, writable: false);
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

                            var match = UserAssistCheatNames.FirstOrDefault(n =>
                                decoded.Contains(n, StringComparison.OrdinalIgnoreCase));
                            if (match is null) continue;

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
                                Title    = $"UserAssist: OW2 Cheat Executed — {match}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKCU\{UserAssistBase}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason   = $"Windows UserAssist entry records execution of OW2 cheat tool " +
                                           $"matching '{match}'. Decoded path: '{decoded}'. " +
                                           $"Execution count: {runCount}. " +
                                           (lastRun.HasValue ? $"Last executed: {lastRun.Value:yyyy-MM-dd HH:mm} UTC. " : "") +
                                           "UserAssist records are ROT13-encoded and persist even after " +
                                           "the cheat executable has been deleted, providing a reliable " +
                                           "forensic record of program execution.",
                                Detail   = $"Decoded: {decoded} | Runs: {runCount} | " +
                                           $"Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }

            ctx.Report(0.5, Name, "UserAssist registry check complete.");
        }, ct);

    private Task CheckMuiCacheRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.5, Name, "Scanning MuiCache for OW2 cheat execution evidence...");

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(MuiCacheKey, writable: false);
                if (key is null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    var path = valueName;
                    var dotIdx = valueName.LastIndexOf('.');
                    if (dotIdx > 0 && !valueName[dotIdx..].Contains('\\'))
                        path = valueName[..dotIdx];

                    var friendlyName = key.GetValue(valueName) as string ?? "";
                    var combined = path + " " + friendlyName;

                    var keyword = MuiCacheCheatKeywords.FirstOrDefault(k =>
                        combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (keyword is null) continue;

                    bool fileExists = File.Exists(path);
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"MuiCache: OW2 Cheat Tool Executed: {Path.GetFileName(path)}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKCU\{MuiCacheKey}",
                        FileName = Path.GetFileName(path),
                        Reason   = $"MuiCache registry entry confirms execution of Overwatch 2 cheat tool " +
                                   $"matching keyword '{keyword}'. Path recorded: '{path}'. " +
                                   (fileExists
                                       ? "The cheat file still exists on disk."
                                       : "The cheat file has been deleted, but MuiCache preserves the execution record.") +
                                   " MuiCache is populated whenever Windows displays a binary's friendly " +
                                   "name (e.g. in Explorer, taskbar) and survives file deletion.",
                        Detail   = $"Path: {path} | FriendlyName: {friendlyName} | Keyword: {keyword} | Exists: {fileExists}"
                    });
                }
            }
            catch { }

            ctx.Report(0.55, Name, "MuiCache check complete.");
        }, ct);

    private Task CheckRunKeyRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.55, Name, "Scanning Run/RunOnce keys for OW2 cheat persistence...");

            var runKeys = new[]
            {
                (Registry.LocalMachine, RunKeyLm),
                (Registry.CurrentUser,  RunKeyHkcu),
                (Registry.LocalMachine, RunOnceLm),
                (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            };

            foreach (var (hive, subKeyPath) in runKeys)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var key = hive.OpenSubKey(subKeyPath, writable: false);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        var value = key.GetValue(valueName) as string ?? "";
                        var combined = valueName + " " + value;

                        var keyword = RunKeyCheatNames.FirstOrDefault(k =>
                            combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (keyword is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Run Key: OW2 Cheat Autostart — {valueName}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"{(hive == Registry.LocalMachine ? "HKLM" : "HKCU")}\{subKeyPath}",
                            Reason   = $"Registry Run key entry '{valueName}' references known OW2 cheat " +
                                       $"keyword '{keyword}'. Value: '{value}'. " +
                                       "This indicates the cheat tool was configured for automatic startup, " +
                                       "meaning it was set to launch with Windows — a persistence pattern " +
                                       "commonly used by loader-based cheat tools and boost bots.",
                            Detail   = $"ValueName: {valueName} | Value: {value} | Keyword: {keyword}"
                        });
                    }
                }
                catch { }
            }

            ctx.Report(0.6, Name, "Run key check complete.");
        }, ct);

    private Task CheckUninstallRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.6, Name, "Scanning Uninstall registry for OW2 cheat software entries...");

            var uninstallRoots = new[]
            {
                (Registry.LocalMachine, UninstallKeyLm),
                (Registry.LocalMachine, UninstallKeyWow),
                (Registry.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            };

            foreach (var (hive, subKeyPath) in uninstallRoots)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var key = hive.OpenSubKey(subKeyPath, writable: false);
                    if (key is null) continue;

                    foreach (var subName in key.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();
                        try
                        {
                            using var entry = key.OpenSubKey(subName, writable: false);
                            if (entry is null) continue;

                            var displayName = entry.GetValue("DisplayName") as string ?? "";
                            var installLocation = entry.GetValue("InstallLocation") as string ?? "";
                            var uninstallString = entry.GetValue("UninstallString") as string ?? "";
                            var combined = displayName + " " + installLocation + " " + uninstallString;

                            var keyword = UserAssistCheatNames.FirstOrDefault(k =>
                                combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (keyword is null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Uninstall Entry: OW2 Cheat Software — {displayName}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"{(hive == Registry.LocalMachine ? "HKLM" : "HKCU")}\{subKeyPath}\{subName}",
                                Reason   = $"Windows Uninstall registry entry '{displayName}' matches " +
                                           $"known OW2 cheat keyword '{keyword}'. " +
                                           "This indicates that Overwatch 2 cheat software was installed " +
                                           "via a formal installer on this system, creating a persistent " +
                                           "uninstall record even after the software is removed.",
                                Detail   = $"DisplayName: {displayName} | InstallLocation: {installLocation} | Keyword: {keyword}"
                            });
                        }
                        catch { }
                    }
                }
                catch { }
            }

            ctx.Report(0.65, Name, "Uninstall registry check complete.");
        }, ct);

    private Task CheckTempFolderArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.65, Name, "Scanning temp folders for OW2 cheat artifacts...");

            var tempDirs = new[]
            {
                TempPath,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(UserProfile, "AppData", "LocalLow", "Temp"),
                Path.Combine(LocalAppData, "Microsoft", "Windows", "INetCache"),
            };

            foreach (var tempDir in tempDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tempDir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(tempDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var keyword = TempCheatKeywords.FirstOrDefault(k =>
                            fileName.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (keyword is null) continue;

                        var ext = Path.GetExtension(fileName).ToLowerInvariant();
                        if (ext != ".exe" && ext != ".dll" && ext != ".sys" &&
                            ext != ".zip" && ext != ".rar" && ext != ".7z" &&
                            ext != ".cfg" && ext != ".ini" && ext != ".log" &&
                            ext != ".ahk" && ext != ".py" && ext != ".bat" &&
                            ext != ".ps1" && ext != ".tmp") continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"OW2 Cheat Artifact in Temp: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"File '{fileName}' in temporary folder matches OW2 cheat keyword " +
                                       $"'{keyword}'. Cheat tools frequently extract components to temp " +
                                       "directories during installation or execution, then attempt to " +
                                       "delete them after use. Finding such artifacts in temp indicates " +
                                       "recent or ongoing cheat tool activity.",
                            Detail   = $"Keyword: {keyword} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            ctx.Report(0.7, Name, "Temp folder scan complete.");
        }, ct);

    private Task CheckBattleNetLogs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.7, Name, "Scanning Battle.net logs for cheat-related entries...");

            var bnetLogDirs = new[]
            {
                Path.Combine(AppData, "Battle.net"),
                Path.Combine(AppData, "Battle.net", "Logs"),
                Path.Combine(AppData, "Battle.net", "Updates"),
                Path.Combine(LocalAppData, "Battle.net"),
                Path.Combine(LocalAppData, "Battle.net", "Logs"),
                Path.Combine(LocalAppData, "Blizzard Entertainment", "Battle.net"),
                Path.Combine(LocalAppData, "Blizzard Entertainment", "Battle.net", "Logs"),
                Path.Combine(AppData, "Blizzard Entertainment"),
                Path.Combine(AppData, "Blizzard Entertainment", "Battle.net"),
                Path.Combine(AppData, "Blizzard Entertainment", "Overwatch"),
            };

            foreach (var logDir in bnetLogDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(logDir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = sr.ReadToEnd();

                            var keyword = BnetLogCheatKeywords.FirstOrDefault(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (keyword is null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Battle.net Log Contains Cheat Keyword: {Path.GetFileName(file)}",
                                Risk     = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason   = $"Battle.net log file '{Path.GetFileName(file)}' contains keyword " +
                                           $"'{keyword}' that is not expected in normal Battle.net client " +
                                           "log output. This may indicate that cheat tools have injected " +
                                           "code into the Battle.net process or that bypass tools have " +
                                           "modified launcher behavior, leaving traces in the log output.",
                                Detail   = $"Keyword: {keyword} | Log: {file}"
                            });
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            ctx.Report(0.75, Name, "Battle.net log scan complete.");
        }, ct);

    private Task CheckPixelAimbotScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.75, Name, "Scanning for pixel aimbot / screen-reading bot scripts...");

            var searchDirs = new[]
            {
                Desktop,
                Downloads,
                Documents,
                TempPath,
                Path.Combine(UserProfile, "Scripts"),
                Path.Combine(UserProfile, "Bots"),
                Path.Combine(UserProfile, "Tools"),
                Path.Combine(UserProfile, "OW2"),
                Path.Combine(UserProfile, "Overwatch"),
                Path.Combine(AppData, "OW2"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.py", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = sr.ReadToEnd();

                            int matchCount = PixelAimBotKeywords.Count(k =>
                                content.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (matchCount < 3) continue;

                            bool hasGameRef = content.Contains("overwatch", StringComparison.OrdinalIgnoreCase) ||
                                             content.Contains("ow2", StringComparison.OrdinalIgnoreCase) ||
                                             content.Contains("aimbot", StringComparison.OrdinalIgnoreCase) ||
                                             content.Contains("triggerbot", StringComparison.OrdinalIgnoreCase) ||
                                             content.Contains("enemy", StringComparison.OrdinalIgnoreCase);

                            if (!hasGameRef) continue;

                            var matched = PixelAimBotKeywords
                                .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                                .Take(5)
                                .ToList();

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Pixel Aimbot Script Detected: {Path.GetFileName(file)}",
                                Risk     = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason   = $"Python script '{Path.GetFileName(file)}' contains {matchCount} " +
                                           "pixel aimbot indicators including screen capture, color detection, " +
                                           "and mouse input automation APIs. Pixel aimbots use OpenCV, " +
                                           "PyAutoGUI, or Win32 APIs to capture the screen, detect enemy " +
                                           "models or health bars by color, and send synthetic mouse input " +
                                           "to aim/shoot — operating entirely outside the game process to " +
                                           "evade kernel-level anti-cheat detection.",
                                Detail   = $"Matched APIs: {string.Join(", ", matched)} | Hits: {matchCount} | Path: {file}"
                            });
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            ctx.Report(0.8, Name, "Pixel aimbot script check complete.");
        }, ct);

    private Task CheckCheatDirectoryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.8, Name, "Checking for known cheat tool directories...");

            var suspiciousDirectoryNames = new[]
            {
                "ow2_cheat",
                "ow2cheat",
                "overwatch_cheat",
                "overwatch_hack",
                "ow2_hack",
                "ow2hack",
                "ow2_aimbot",
                "ow2aimbot",
                "ow2_esp",
                "ow2esp",
                "ow2_wallhack",
                "ow2wallhack",
                "ow2_loader",
                "ow2loader",
                "ow2_bypass",
                "ow2bypass",
                "ow2_trigger",
                "ow2trigger",
                "ow2_boost",
                "ow2boost",
                "bnet_bypass",
                "bnetbypass",
                "warden_bypass",
                "wardenbypass",
                "ricochet_bypass",
                "ricochetbypass",
                "ow2_warden",
                "ow2warden",
                "ow2_anticheat",
                "ow2anticheat",
            };

            var searchRoots = new[]
            {
                UserProfile,
                "C:\\",
                "D:\\",
            };

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        var dirName = Path.GetFileName(dir);

                        var match = suspiciousDirectoryNames.FirstOrDefault(n =>
                            dirName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"OW2 Cheat Directory Found: {dirName}",
                            Risk     = RiskLevel.Critical,
                            Location = dir,
                            FileName = dirName,
                            Reason   = $"Directory '{dirName}' at '{dir}' matches a known Overwatch 2 " +
                                       $"cheat tool installation directory name '{match}'. " +
                                       "Cheat tools typically create named directories for their components, " +
                                       "configuration files, and logs. The presence of this directory " +
                                       "constitutes forensic evidence of cheat tool installation.",
                            Detail   = $"Directory: {dir} | Matched: {match}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            ctx.Report(0.85, Name, "Cheat directory check complete.");
        }, ct);

    private Task CheckOw2DriverArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.85, Name, "Checking for OW2 kernel driver cheat artifacts...");

            var driverCheatNames = new[]
            {
                "ow2_driver_cheat.sys",
                "ow2_kernel_cheat.sys",
                "ow2_kernel_bypass.sys",
                "ow2_cheat_driver.sys",
                "ow2_aimbot_driver.sys",
                "ow_cheat_driver.sys",
                "overwatch_driver.sys",
                "ow2_km.sys",
                "ow_km.sys",
                "ow2_kmode.sys",
            };

            var driverDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers"),
                TempPath,
                Desktop,
                Downloads,
            };

            foreach (var dir in driverDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.sys", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);

                        var match = driverCheatNames.FirstOrDefault(n =>
                            fileName.Equals(n, StringComparison.OrdinalIgnoreCase));
                        if (match is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"OW2 Kernel Driver Cheat Artifact: {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Known Overwatch 2 kernel-mode cheat driver '{fileName}' found at '{file}'. " +
                                       "Kernel-mode cheat drivers operate at Ring 0 privilege level, " +
                                       "allowing them to read/write game memory, hide processes, and " +
                                       "bypass user-mode anti-cheat protections. This is among the most " +
                                       "severe cheat indicators and indicates sophisticated cheat infrastructure.",
                            Detail   = $"Matched driver: {match} | Path: {file}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            try
            {
                using var servicesKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services", writable: false);
                if (servicesKey is not null)
                {
                    foreach (var serviceName in servicesKey.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        var isOw2CheatDriver = driverCheatNames.Any(n =>
                            serviceName.Contains(Path.GetFileNameWithoutExtension(n),
                                StringComparison.OrdinalIgnoreCase));
                        if (!isOw2CheatDriver) continue;

                        try
                        {
                            using var svc = servicesKey.OpenSubKey(serviceName, writable: false);
                            var imagePath = svc?.GetValue("ImagePath") as string ?? "";
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"OW2 Cheat Driver Service Entry: {serviceName}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{serviceName}",
                                Reason   = $"Windows service registry entry '{serviceName}' matches known " +
                                           "Overwatch 2 kernel cheat driver pattern. Even if the driver " +
                                           "file has been deleted, the service entry in the registry " +
                                           "constitutes forensic evidence of prior installation.",
                                Detail   = $"Service: {serviceName} | ImagePath: {imagePath}"
                            });
                        }
                        catch { }
                    }
                }
            }
            catch { }

            ctx.Report(0.9, Name, "OW2 driver artifact check complete.");
        }, ct);

    private Task CheckOw2PrefetchArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.9, Name, "Scanning Windows Prefetch for OW2 cheat execution traces...");

            var prefetchDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

            if (!Directory.Exists(prefetchDir)) return;

            var cheatPrefetchPatterns = new[]
            {
                "OW2_CHEAT",
                "OW_AIMBOT",
                "OWCHEAT",
                "OVERWATCH_HACK",
                "OW2_TRIGGER",
                "OW2_WALLHACK",
                "OW2_ESP",
                "OW2_AIM",
                "OW2_LOADER",
                "OW2_BYPASS",
                "OW_WH",
                "OW_RADAR",
                "OW2_TRACKER",
                "ANA_SLEEP_BOT",
                "DVA_MATRIX_BOT",
                "MERCY_BOOST_BOT",
                "OW2_WARDEN_BYPASS",
                "OW2_ANTICHEAT_BYPASS",
                "BNET_BYPASS",
                "BATTLE_NET_BYPASS",
                "OW2_TRIGGERBOT",
                "OW2_AIMASSIST",
                "OW2_SPINBOT",
                "OW2_BOOST",
                "OW2_RANKBOOST",
                "RICOCHET_BYPASS",
                "OW2_BOT",
                "OVERWATCH_BOT",
                "OW2_PIXEL_AIM",
                "OW2_SILENT_AIM",
            };

            try
            {
                foreach (var file in Directory.EnumerateFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file).ToUpperInvariant();

                    var match = cheatPrefetchPatterns.FirstOrDefault(p =>
                        fileName.Contains(p, StringComparison.OrdinalIgnoreCase));
                    if (match is null) continue;

                    DateTime? lastRun = null;
                    try { lastRun = File.GetLastWriteTimeUtc(file); } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Prefetch: OW2 Cheat Execution Trace — {Path.GetFileNameWithoutExtension(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Windows Prefetch file '{Path.GetFileName(file)}' confirms prior execution " +
                                   $"of Overwatch 2 cheat tool matching pattern '{match}'. " +
                                   (lastRun.HasValue ? $"Last prefetch update: {lastRun.Value:yyyy-MM-dd HH:mm} UTC. " : "") +
                                   "Windows Prefetch files record program execution to speed up subsequent " +
                                   "launches and persist on disk even after the cheat executable is deleted, " +
                                   "providing a reliable forensic timestamp of cheat tool execution.",
                        Detail   = $"Prefetch: {file} | Pattern: {match} | LastWrite: {lastRun?.ToString("O") ?? "unknown"}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            ctx.Report(1.0, Name, "Overwatch 2 deep forensic scan complete.");
        }, ct);

    private static string ProgramFilesDir() =>
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
}
