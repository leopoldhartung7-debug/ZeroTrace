using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class RustCheatDetectionScanModule : IScanModule
{
    private static readonly string _name = "Rust Game Cheat Detection";
    public string Name => _name;
    public double Weight => 4.3;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Known Rust cheat EXE names (80+ variants)
    // -------------------------------------------------------------------------
    private static readonly HashSet<string> KnownRustCheatExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Generic Rust hack executables
        "rust_hack.exe", "rustcheat.exe", "rust_cheat.exe",
        "rust_aimbot.exe", "rustaimbot.exe",
        "rust_esp.exe", "rustesp.exe",
        "rust_wallhack.exe", "rustwallhack.exe",
        "rust_radar.exe", "rustradar.exe",
        "rust_god.exe", "rustgod.exe", "rust_godmode.exe",
        "rust_speedhack.exe", "rustspeedhack.exe",
        "rust_nofall.exe", "rustnofall.exe",
        "rust_nocool.exe", "rustnocool.exe",
        "rust_autofarm.exe", "rustautofarm.exe",
        "rust_ore.exe", "rustore.exe",
        "rust_loot.exe", "rustloot.exe",
        "rust_silent_aim.exe", "rustsilentaim.exe",
        "rust_recoil.exe", "rustrecoil.exe",
        "rust_no_recoil.exe", "rustnorecoil.exe",
        "rust_fov_hack.exe", "rustfovhack.exe",
        "rustexploit.exe", "rust_exploit.exe",
        "rustmod.exe", "rust_mod.exe",
        "rusttrainer.exe", "rust_trainer.exe",
        "rust_loader.exe", "rustloader.exe",
        "rust_injector.exe", "rustinjector.exe",
        // Named Rust cheats and commercial products
        "midnight_rust.exe", "midnightrust.exe",
        "novoline_rust.exe", "novolinerust.exe",
        "skycheats_rust.exe", "skycheatsrust.exe", "skycheats.exe",
        "aimware_rust.exe", "aimwarerust.exe", "aimware.exe",
        "gamesense_rust.exe", "gamesenserust.exe", "gamesense.exe",
        "interwebz.exe", "interwebz_rust.exe",
        "streamline.exe", "streamline_rust.exe",
        "streamline_cheats.exe",
        "rustmagic.exe", "rust_magic.exe",
        "rustyhack.exe", "rusty_hack.exe",
        "corehacks_rust.exe", "corehacksrust.exe",
        "oxide_exploit.exe", "oxideexploit.exe",
        "umod_exploit.exe", "umodexploit.exe",
        "harmony_exploit.exe", "harmonyexploit.exe",
        "carbon_exploit.exe", "carbonexploit.exe",
        "eac_bypass.exe", "eacbypass.exe",
        "easyanticheat_bypass.exe",
        "rust_eac_bypass.exe", "rusteacbypass.exe",
        "rust_bypass.exe", "rustbypass.exe",
        "rust_spoofer.exe", "rustspoofer.exe",
        "hwid_spoofer_rust.exe", "hwidspooferrust.exe",
        "rust_hwid.exe", "rusthwid.exe",
        "rust_external.exe", "rustexternal.exe",
        "rust_internal.exe", "rustinternal.exe",
        "rust_chams.exe", "rustchams.exe",
        "rust_triggerbot.exe", "rusttriggerbot.exe",
        "rust_bunnyhop.exe", "rustbunnyhop.exe",
        "rust_bhop.exe", "rustbhop.exe",
        "rust_antiaim.exe", "rustantiaim.exe",
        "rust_spinbot.exe", "rustspinbot.exe",
        "rust_fakeang.exe", "rustfakeang.exe",
        "rust_flicker.exe", "rustflicker.exe",
        "rust_nospread.exe", "rustnospread.exe",
        "rust_norecoil.exe",
        "rusthax.exe", "rust_hax.exe",
        "rustesp_v2.exe", "rust_esp_v2.exe",
        "rustcheatpublic.exe", "rust_cheat_public.exe",
        "rustfreecheat.exe", "rust_free_cheat.exe",
        "rustcracked.exe", "rust_cracked.exe",
        "rustpublic.exe", "rust_public.exe",
        "rustprivate.exe", "rust_private.exe",
        // Additional variants
        "rust_menu.exe", "rustmenu.exe",
        "rust_overlay.exe", "rustoverlay.exe",
        "rust_radar_hack.exe",
        "rust_item_esp.exe",
        "rust_player_esp.exe",
        "rust_node_esp.exe",
        "rust_animal_esp.exe",
        "rust_stash_esp.exe",
    };

    // DLL equivalents
    private static readonly HashSet<string> KnownRustCheatDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "rust_hack.dll", "rustcheat.dll", "rust_aimbot.dll", "rust_esp.dll",
        "rust_wallhack.dll", "rust_radar.dll", "rust_silent_aim.dll",
        "rust_recoil.dll", "rust_no_recoil.dll", "rust_norecoil.dll",
        "rust_injected.dll", "rust_internal.dll", "rust_external.dll",
        "rust_loader.dll", "rust_bypass.dll", "eac_bypass.dll",
        "easyanticheat_bypass.dll", "rust_eac.dll",
        "rustcheat_internal.dll", "rustcheat_external.dll",
        "novoline_rust.dll", "aimware_rust.dll",
        "gamesense_rust.dll", "midnight_rust.dll",
        "skycheats_rust.dll", "interwebz.dll",
        "oxide_exploit.dll", "harmony_inject.dll",
        "carbon_inject.dll", "umod_exploit.dll",
        "rust_spoofer.dll", "hwid_spoof_rust.dll",
        "rust_chams.dll", "rust_esp_overlay.dll",
        "rustmagic.dll", "rustyhack.dll",
        "rust_triggerbot.dll", "rust_bhop.dll",
        "corehacks_rust.dll", "rust_menu.dll",
        "rust_overlay.dll",
    };

    // Known Rust cheat config file names
    private static readonly HashSet<string> KnownRustCheatConfigFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "rust_hack_config.json", "rustcheat_config.json", "rust_cheat_config.json",
        "esp_config.json", "aimbot_config.json", "recoil_settings.json",
        "rust_esp_config.json", "rust_aimbot_config.json",
        "rust_recoil_config.json", "rust_no_recoil_config.json",
        "rust_radar_config.json", "rust_silent_aim_config.json",
        "rust_loader_config.json", "rust_bypass_config.json",
        "novoline_config.json", "novoline_settings.json",
        "aimware_config.json", "aimware_settings.json",
        "gamesense_config.json", "gamesense_settings.json",
        "midnight_config.json", "midnight_settings.json",
        "skycheats_config.json", "skycheats_settings.json",
        "interwebz_config.json", "streamline_config.json",
        "corehacks_config.json", "rustmagic_config.json",
        "eac_bypass_config.json", "spoofer_config.json",
        "hwid_spoofer_config.json", "rust_spoofer_config.json",
        "rust_hack_settings.ini", "rust_cheat_settings.ini",
        "rust_esp_settings.ini", "rust_aimbot_settings.ini",
        "recoil_settings.ini", "norecoil_settings.ini",
        "esp_settings.json", "wallhack_settings.json",
        "chams_settings.json", "triggerbot_settings.json",
        "bhop_settings.json", "bunnyhop_settings.json",
        "radar_config.json", "item_esp_config.json",
        "player_esp_config.json",
    };

    // Known Rust cheat AutoHotKey and Lua recoil macro filenames
    private static readonly HashSet<string> KnownRecoilScriptFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        // AutoHotKey recoil scripts
        "no_recoil.ahk", "norecoil.ahk", "recoil.ahk", "rust_recoil.ahk",
        "rust_no_recoil.ahk", "rust_norecoil.ahk", "rust_macro.ahk",
        "rust_ak47_recoil.ahk", "rust_ak_recoil.ahk", "rust_lr300_recoil.ahk",
        "rust_mp5_recoil.ahk", "rust_m249_recoil.ahk", "rust_python_recoil.ahk",
        "rust_semi_recoil.ahk", "rust_custom_smg_recoil.ahk",
        "recoil_script.ahk", "recoil_helper.ahk", "recoil_control.ahk",
        "noreciol.ahk", "no-recoil.ahk", "anti_recoil.ahk", "antirecoil.ahk",
        "spray_control.ahk", "spraycontrol.ahk",
        "rust_spray.ahk", "rust_hipfire.ahk",
        // Lua recoil scripts
        "recoil_script.lua", "norecoil.lua", "no_recoil.lua",
        "rust_recoil.lua", "rust_no_recoil.lua", "rust_macro.lua",
        "recoil.lua", "recoil_helper.lua", "recoil_control.lua",
        "spray_control.lua", "logitech_norecoil.lua",
        "rust_ak47.lua", "rust_lr300.lua", "rust_mp5.lua",
        // Python/other scripts
        "recoil_script.py", "rust_recoil.py", "no_recoil.py",
        "rust_macro.py", "spray_control.py",
    };

    // Folder name keywords associated with Rust cheats
    private static readonly string[] KnownRustCheatFolderKeywords = new[]
    {
        "rust_hack", "rustcheat", "rust_cheat", "rust_esp",
        "rust_aimbot", "rust_wallhack", "rust_radar", "rust_silent",
        "rust_recoil", "rust_norecoil", "rust_bypass", "rust_eac",
        "rust_spoofer", "rusthwid", "rust_loader", "rust_injector",
        "rustmod", "rust_mod", "rusttrainer", "rust_trainer",
        "novoline_rust", "novolinerust",
        "skycheats", "skycheats_rust",
        "aimware", "aimware_rust",
        "gamesense", "gamesense_rust",
        "midnight_rust", "midnightrust",
        "interwebz", "interwebz_rust",
        "streamline_cheat", "streamlinecheat",
        "rustmagic", "rusty_hack", "rustyhack",
        "corehacks", "corehacks_rust",
        "eac_bypass", "eacbypass",
        "harmony_exploit", "harmonyexploit",
        "carbon_exploit", "carbonexploit",
        "oxide_exploit", "oxideexploit",
        "umod_exploit", "umodexploit",
        "rust_overlay_cheat",
        "rust_free_cheat", "rustfreecheat",
        "rust_public_cheat", "rustpublicheat",
        "rust_cracked", "rustcracked",
    };

    // Keywords found inside Rust cheat config files
    private static readonly string[] RustCheatConfigKeywords = new[]
    {
        "aimbot", "aim_bot", "silent_aim", "silentaim",
        "esp_players", "player_esp", "item_esp", "stash_esp",
        "wallhack", "wall_hack", "chams", "glow_esp",
        "no_recoil", "norecoil", "recoil_control", "recoil_script",
        "bunnyhop", "bhop", "bunny_hop", "speed_hack", "speedhack",
        "no_fall", "nofall", "no_fall_damage",
        "eac_bypass", "eacbypass", "anticheat_bypass",
        "triggerbot", "trigger_bot",
        "radar_hack", "radarhack", "minimap_hack",
        "node_esp", "ore_esp", "animal_esp",
        "loot_esp", "crate_esp", "barrel_esp",
        "fov_circle", "fov_hack",
        "spinbot", "spin_bot", "antiaim", "anti_aim",
        "autofire", "auto_fire", "rapidfire",
        "teleport", "noclip", "no_clip",
        "rust_hack", "rust_cheat", "cheat_enabled",
        "inject_dll", "injected", "bypass_enabled",
        "hwid_spoof", "hwidspoof", "spoofer_enabled",
    };

    // EAC bypass artifact files and folder names inside Rust game directory
    private static readonly string[] EacBypassArtifacts = new[]
    {
        "EasyAntiCheat_bypass.dll",
        "EasyAntiCheat_stub.dll",
        "EasyAntiCheat_fake.dll",
        "EasyAntiCheat_disabled.dll",
        "EasyAntiCheat_patched.dll",
        "EAC_bypass.dll",
        "eac_bypass.dll",
        "eac_stub.dll",
        "eac_disabled.dll",
        "anticheat_bypass.dll",
        "bypass_eac.dll",
    };

    // Oxide/uMod plugin directories and suspicious plugin names
    private static readonly string[] SuspiciousOxidePluginKeywords = new[]
    {
        "aimbot", "esp", "wallhack", "norecoil", "no_recoil",
        "speedhack", "nofall", "godmode", "god_mode",
        "eacbypass", "eac_bypass", "anticheat_bypass",
        "teleport_all", "kill_all", "instant_kill",
        "infinite_ammo", "infinite_health",
        "spawn_items", "spawn_all", "give_all",
        "admin_exploit", "admin_hack", "rcon_exploit",
        "crash_server", "server_crash", "lag_exploit",
        "item_dupe", "duplication_exploit",
        "raid_esp", "base_esp",
        "chat_bypass", "bypass_auth",
    };

    // Registry paths for MUICache and UserAssist
    private static readonly string MUICacheKeyPath =
        @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

    private static readonly string UserAssistKeyPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

    // ROT13 decoder for UserAssist
    private static string Rot13(string s)
    {
        var arr = s.ToCharArray();
        for (int i = 0; i < arr.Length; i++)
        {
            char c = arr[i];
            if (c >= 'a' && c <= 'z') arr[i] = (char)('a' + (c - 'a' + 13) % 26);
            else if (c >= 'A' && c <= 'Z') arr[i] = (char)('A' + (c - 'A' + 13) % 26);
        }
        return new string(arr);
    }

    // Directories to scan
    private static string[] GetScanDirectories()
    {
        var localApp    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var temp        = Path.GetTempPath();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var desktop     = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads   = Path.Combine(userProfile, "Downloads");
        var documents   = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        var dirs = new List<string>
        {
            localApp,
            appData,
            temp,
            desktop,
            downloads,
            documents,
            Path.Combine(localApp, "Temp"),
            Path.Combine(appData,  "Rust"),
            Path.Combine(localApp, "Rust"),
            Path.Combine(userProfile, "Rust"),
        };

        // Add Steam library paths where Rust might be installed
        try
        {
            using var steamKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Valve\Steam", writable: false);
            var steamPath = steamKey?.GetValue("SteamPath") as string;
            if (!string.IsNullOrEmpty(steamPath))
            {
                dirs.Add(Path.Combine(steamPath, "steamapps", "common", "Rust"));
                dirs.Add(Path.Combine(steamPath, "steamapps", "common", "Rust", "EasyAntiCheat"));
            }
        }
        catch { }

        return dirs.ToArray();
    }

    // -------------------------------------------------------------------------
    // Entry point
    // -------------------------------------------------------------------------
    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Rust cheat detection...");

        await Task.WhenAll(
            CheckFilesystem(ctx, ct),
            CheckRecoilScripts(ctx, ct),
            CheckCheatProcesses(ctx, ct),
            CheckEacBypassArtifacts(ctx, ct),
            CheckOxidePluginAbuse(ctx, ct),
            CheckRegistryMuiCache(ctx, ct),
            CheckRegistryUserAssist(ctx, ct),
            CheckRegistryUninstall(ctx, ct),
            CheckHarmonyAndCarbonInjection(ctx, ct)
        );

        ctx.Report(1.0, Name, "Rust cheat detection complete.");
    }

    // -------------------------------------------------------------------------
    // Sub-check: filesystem scan
    // -------------------------------------------------------------------------
    private Task CheckFilesystem(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            ctx.Report(0.05, Name, "Scanning filesystem for Rust cheat artifacts...");

            var dirs = GetScanDirectories();
            var tasks = dirs.Select(d => ScanDirectoryForRustCheats(d, ctx, ct)).ToArray();
            await Task.WhenAll(tasks);

            ctx.Report(0.35, Name, "Filesystem scan complete.");
        }, ct);
    }

    private Task ScanDirectoryForRustCheats(string rootDir, ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            if (!Directory.Exists(rootDir)) return;

            var stack = new Stack<string>();
            stack.Push(rootDir);

            while (stack.Count > 0)
            {
                if (ct.IsCancellationRequested) return;
                var dir = stack.Pop();

                // Check directory name for Rust cheat keywords
                var dirName = Path.GetFileName(dir) ?? string.Empty;
                foreach (var kw in KnownRustCheatFolderKeywords)
                {
                    if (dirName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = $"Rust Cheat Directory: {dirName}",
                            Risk     = RiskLevel.Critical,
                            Location = dir,
                            FileName = dirName,
                            Reason   = $"Directory name '{dirName}' matches known Rust cheat tool folder pattern '{kw}'. " +
                                       "This directory is associated with cheating tools targeting the game Rust.",
                            Detail   = $"Matched keyword: {kw} | Path: {dir}"
                        });
                        break;
                    }
                }

                string[] files = Array.Empty<string>();
                try { files = Directory.GetFiles(dir); }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    InspectRustFile(file, ctx);
                }

                string[] subs = Array.Empty<string>();
                try { subs = Directory.GetDirectories(dir); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var sub in subs) stack.Push(sub);
            }
        }, ct);
    }

    private void InspectRustFile(string file, ScanContext ctx)
    {
        var fileName = Path.GetFileName(file);
        var ext = Path.GetExtension(file);

        // Check known cheat EXE names
        if (KnownRustCheatExeNames.Contains(fileName))
        {
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = _name,
                Title    = $"Known Rust Cheat Executable: {fileName}",
                Risk     = RiskLevel.Critical,
                Location = file,
                FileName = fileName,
                Reason   = $"File '{fileName}' is a known Rust game cheat tool executable. " +
                           "This executable provides unauthorized cheating capabilities in Rust including " +
                           "aimbot, ESP, wallhack, recoil scripts, and EAC bypass.",
                Detail   = $"Full path: {file}"
            });
            return;
        }

        // Check known cheat DLL names
        if (KnownRustCheatDllNames.Contains(fileName))
        {
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = _name,
                Title    = $"Known Rust Cheat DLL: {fileName}",
                Risk     = RiskLevel.Critical,
                Location = file,
                FileName = fileName,
                Reason   = $"DLL '{fileName}' is associated with known Rust cheat tools. " +
                           "These libraries are injected into the Rust game process to enable cheating " +
                           "including aimbot, ESP, wallhack, and EAC bypass functionality.",
                Detail   = $"Full path: {file}"
            });
            return;
        }

        // Check known cheat config files
        if (KnownRustCheatConfigFiles.Contains(fileName))
        {
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = _name,
                Title    = $"Rust Cheat Configuration File: {fileName}",
                Risk     = RiskLevel.High,
                Location = file,
                FileName = fileName,
                Reason   = $"Configuration file '{fileName}' belongs to a known Rust cheat tool. " +
                           "The presence of this file indicates a Rust cheat was previously installed and configured.",
                Detail   = $"Full path: {file}"
            });
            TryScanRustConfigContent(file, fileName, ctx);
            return;
        }

        // Check known recoil script files
        if (KnownRecoilScriptFiles.Contains(fileName))
        {
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = _name,
                Title    = $"Rust Recoil Script: {fileName}",
                Risk     = RiskLevel.High,
                Location = file,
                FileName = fileName,
                Reason   = $"Recoil control macro script '{fileName}' found. " +
                           "AutoHotKey and Lua recoil scripts provide unfair no-recoil advantages in Rust " +
                           "by automatically countering weapon recoil patterns during shooting.",
                Detail   = $"Full path: {file}"
            });
            TryScanRecoilScriptContent(file, fileName, ctx);
            return;
        }

        // Scan config content for cheat keywords
        if (ext.Equals(".json", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".ini",  StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".cfg",  StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".xml",  StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".txt",  StringComparison.OrdinalIgnoreCase))
        {
            TryScanRustConfigContent(file, fileName, ctx);
            return;
        }

        // Scan AHK/Lua scripts for recoil keywords
        if (ext.Equals(".ahk", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".lua", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".au3", StringComparison.OrdinalIgnoreCase))
        {
            TryScanRecoilScriptContent(file, fileName, ctx);
        }
    }

    private void TryScanRustConfigContent(string file, string fileName, ScanContext ctx)
    {
        try
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            string content = sr.ReadToEnd();

            foreach (var kw in RustCheatConfigKeywords)
            {
                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Rust Cheat Keyword in Config: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Configuration file '{fileName}' contains keyword '{kw}' which is " +
                                   "strongly associated with Rust cheat tools including aimbot, ESP, wallhack, " +
                                   "recoil control, EAC bypass, and other cheating features.",
                        Detail   = $"Matched keyword: {kw} | File: {file}"
                    });
                    return;
                }
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static readonly string[] RecoilScriptKeywords = new[]
    {
        "no_recoil", "norecoil", "recoil_control", "recoil_script",
        "spray_control", "spraycontrol", "ak47_recoil", "lr300_recoil",
        "mp5_recoil", "m249_recoil", "python_recoil", "semi_auto_recoil",
        "GetKeyState", "MouseMove", "PixelGetColor",
        "MouseClick", "Send", "Sleep",
        "rust", "ak", "lr300", "mp5", "m249",
        "hipfire", "ads_recoil", "noscope_recoil",
        "anti_recoil", "antirecoil", "recoil_compensate",
        "weapon_recoil", "gun_recoil",
    };

    private static void TryScanRecoilScriptContent(string file, string fileName, ScanContext ctx)
    {
        try
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            string content = sr.ReadToEnd();

            // Need at least 2 keywords to confirm it's a recoil script (reduce false positives)
            var hits = RecoilScriptKeywords.Where(kw =>
                content.Contains(kw, StringComparison.OrdinalIgnoreCase)).Take(3).ToList();

            if (hits.Count >= 2)
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = _name,
                    Title    = $"Rust Recoil Macro Script Content: {fileName}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Script file '{fileName}' contains multiple recoil control keywords ({string.Join(", ", hits.Select(h => $"'{h}'"))}). " +
                               "This script appears to be an AutoHotKey or Lua recoil macro that automates " +
                               "weapon recoil compensation in Rust, providing an unfair advantage.",
                    Detail   = $"Matched keywords: {string.Join(", ", hits)} | File: {file}"
                });
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    // -------------------------------------------------------------------------
    // Sub-check: recoil scripts in common macro tool locations
    // -------------------------------------------------------------------------
    private Task CheckRecoilScripts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.12, Name, "Scanning for Rust recoil scripts in macro tool directories...");

            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var appData     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var documents   = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var desktop     = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            var downloads   = Path.Combine(userProfile, "Downloads");

            var scriptSearchDirs = new[]
            {
                desktop,
                downloads,
                documents,
                Path.Combine(documents, "AutoHotkey"),
                Path.Combine(documents, "AutoHotKey"),
                Path.Combine(appData, "Logitech", "GHUB", "profiles"),
                Path.Combine(appData, "Logitech Gaming Software", "profiles"),
                Path.Combine(userProfile, "AutoHotKey"),
                Path.Combine(userProfile, "AHK"),
                Path.Combine(userProfile, "Macros"),
                Path.Combine(userProfile, "Scripts"),
            };

            foreach (var dir in scriptSearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] files = Array.Empty<string>();
                try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    // Check against known recoil script names
                    if (KnownRecoilScriptFiles.Contains(fn))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = $"Rust Recoil Script Found: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Known Rust recoil macro script '{fn}' found at '{dir}'. " +
                                       "These scripts automate weapon recoil compensation in Rust, " +
                                       "giving the user an unfair accuracy advantage over other players.",
                            Detail   = $"Script directory: {dir}"
                        });
                        continue;
                    }

                    // For AHK/Lua files: scan content
                    if (ext.Equals(".ahk", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".lua", StringComparison.OrdinalIgnoreCase))
                    {
                        // Only check files with "rust" or "recoil" in name for performance
                        var fnLower = fn.ToLowerInvariant();
                        if (fnLower.Contains("rust") || fnLower.Contains("recoil") ||
                            fnLower.Contains("norecoil") || fnLower.Contains("spray") ||
                            fnLower.Contains("macro"))
                        {
                            TryScanRecoilScriptContent(file, fn, ctx);
                        }
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Sub-check: running processes
    // -------------------------------------------------------------------------
    private Task CheckCheatProcesses(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.18, Name, "Checking running processes for Rust cheat tools...");

            try
            {
                foreach (var proc in ctx.GetProcessSnapshot())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementProcesses();

                    try
                    {
                        var procExeName = proc.ProcessName + ".exe";

                        if (KnownRustCheatExeNames.Contains(procExeName))
                        {
                            string? exePath = null;
                            try { exePath = proc.MainModule?.FileName; } catch { }

                            ctx.AddFinding(new Finding
                            {
                                Module = _name,
                                Title    = $"Rust Cheat Process Running: {proc.ProcessName}",
                                Risk     = RiskLevel.Critical,
                                Location = exePath ?? $"PID {proc.Id}",
                                FileName = proc.ProcessName,
                                Reason   = $"Known Rust cheat tool '{proc.ProcessName}' is currently running. " +
                                           "This process is a cheat tool for the game Rust that provides " +
                                           "unauthorized advantages such as aimbot, ESP, wallhack, or EAC bypass.",
                                Detail   = $"PID: {proc.Id} | Name: {proc.ProcessName} | Path: {exePath ?? "unknown"}"
                            });
                            continue;
                        }

                        // Fuzzy match against cheat folder keywords
                        var lowerName = proc.ProcessName.ToLowerInvariant();
                        foreach (var kw in KnownRustCheatFolderKeywords)
                        {
                            if (lowerName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                string? exePath = null;
                                try { exePath = proc.MainModule?.FileName; } catch { }

                                ctx.AddFinding(new Finding
                                {
                                    Module = _name,
                                    Title    = $"Suspicious Rust-Related Process: {proc.ProcessName}",
                                    Risk     = RiskLevel.High,
                                    Location = exePath ?? $"PID {proc.Id}",
                                    FileName = proc.ProcessName,
                                    Reason   = $"Process '{proc.ProcessName}' contains keyword '{kw}' " +
                                               "associated with Rust cheat tools or cheating communities.",
                                    Detail   = $"PID: {proc.Id} | Matched keyword: {kw}"
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
    // Sub-check: EAC bypass artifacts in Rust game directory
    // -------------------------------------------------------------------------
    private Task CheckEacBypassArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.25, Name, "Checking for EAC bypass artifacts in Rust directories...");

            var rustPaths = GetRustInstallPaths();

            foreach (var rustRoot in rustPaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(rustRoot)) continue;

                var eacDir = Path.Combine(rustRoot, "EasyAntiCheat");

                // Check for bypass DLLs in the Rust root
                foreach (var bypassFile in EacBypassArtifacts)
                {
                    var targetPath = Path.Combine(rustRoot, bypassFile);
                    if (File.Exists(targetPath))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = $"EAC Bypass DLL in Rust Directory: {bypassFile}",
                            Risk     = RiskLevel.Critical,
                            Location = targetPath,
                            FileName = bypassFile,
                            Reason   = $"EasyAntiCheat bypass artifact '{bypassFile}' found in Rust installation directory '{rustRoot}'. " +
                                       "This file is designed to disable or circumvent EasyAntiCheat protection, " +
                                       "allowing other cheat tools to operate undetected in Rust.",
                            Detail   = $"Rust root: {rustRoot}"
                        });
                    }
                }

                // Check EasyAntiCheat subdirectory for modified/stub files
                if (Directory.Exists(eacDir))
                {
                    CheckEacDirectoryIntegrity(eacDir, ctx, ct);
                }

                // Check Rust.exe size anomaly (very rough heuristic)
                CheckRustExeIntegrity(rustRoot, ctx, ct);

                // Check for disabled EAC service indication
                CheckEacServiceDisabled(ctx, ct);
            }
        }, ct);
    }

    private static void CheckEacDirectoryIntegrity(string eacDir, ScanContext ctx, CancellationToken ct)
    {
        string[] eacFiles = Array.Empty<string>();
        try { eacFiles = Directory.GetFiles(eacDir, "*.dll"); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in eacFiles)
        {
            if (ct.IsCancellationRequested) return;
            var fn = Path.GetFileName(file);

            // Suspiciously small EAC DLLs are likely stubs
            try
            {
                var info = new FileInfo(file);
                if (info.Length < 10240) // Less than 10KB is suspicious for EAC DLLs
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Suspiciously Small EAC DLL (Possible Stub): {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"EasyAntiCheat DLL '{fn}' in Rust EAC directory is suspiciously small ({info.Length} bytes). " +
                                   "Legitimate EAC DLLs are much larger. This file may be a stub replacement " +
                                   "designed to bypass anti-cheat protection in Rust.",
                        Detail   = $"File size: {info.Length} bytes | EAC dir: {eacDir}"
                    });
                }
            }
            catch { }
        }
    }

    private static void CheckRustExeIntegrity(string rustRoot, ScanContext ctx, CancellationToken ct)
    {
        var rustExe = Path.Combine(rustRoot, "Rust.exe");
        if (!File.Exists(rustExe)) return;

        try
        {
            var info = new FileInfo(rustExe);
            // Rust.exe is typically over 50MB; very small files are suspicious
            if (info.Length < 1024 * 1024) // Less than 1MB
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = _name,
                    Title    = "Rust.exe Size Anomaly (Possible Modification)",
                    Risk     = RiskLevel.High,
                    Location = rustExe,
                    FileName = "Rust.exe",
                    Reason   = $"Rust.exe at '{rustRoot}' is suspiciously small ({info.Length} bytes). " +
                               "The legitimate Rust executable is much larger. " +
                               "This may indicate the executable has been replaced with a modified version.",
                    Detail   = $"File size: {info.Length} bytes | Expected: >50MB"
                });
            }
        }
        catch { }
    }

    private static void CheckEacServiceDisabled(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        // Check if EAC service has been disabled or set to manual start
        var eacServiceNames = new[]
        {
            "EasyAntiCheat", "EasyAntiCheat_EOS", "EAC",
        };

        foreach (var serviceName in eacServiceNames)
        {
            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Services\{serviceName}", writable: false);
                if (key is null) continue;

                var startType = key.GetValue("Start") as int?;
                var imagePath = key.GetValue("ImagePath") as string ?? "";

                // StartType 4 = Disabled, suspicious for EAC
                if (startType == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"EasyAntiCheat Service Disabled: {serviceName}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{serviceName}",
                        Reason   = $"EasyAntiCheat service '{serviceName}' has been disabled (StartType=4). " +
                                   "Disabling the EAC service prevents anti-cheat from running during Rust gameplay, " +
                                   "allowing cheat tools to operate without detection.",
                        Detail   = $"StartType: {startType} | ImagePath: {imagePath}"
                    });
                }
                else if (imagePath.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                         imagePath.Contains("fake", StringComparison.OrdinalIgnoreCase) ||
                         imagePath.Contains("stub", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Suspicious EAC Service ImagePath: {serviceName}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{serviceName}",
                        Reason   = $"EasyAntiCheat service '{serviceName}' has a suspicious ImagePath '{imagePath}' " +
                                   "containing bypass-related keywords. This may indicate a stub EAC service " +
                                   "installed to neutralize anti-cheat protection in Rust.",
                        Detail   = $"ImagePath: {imagePath} | StartType: {startType}"
                    });
                }
            }
            catch { }
        }
    }

    // -------------------------------------------------------------------------
    // Sub-check: Oxide/uMod plugin abuse
    // -------------------------------------------------------------------------
    private Task CheckOxidePluginAbuse(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.55, Name, "Checking for abusive Oxide/uMod plugins...");

            var rustPaths = GetRustInstallPaths();

            foreach (var rustRoot in rustPaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(rustRoot)) continue;

                // Check Oxide and uMod plugin directories for suspicious plugins
                var oxideDirs = new[]
                {
                    Path.Combine(rustRoot, "oxide", "plugins"),
                    Path.Combine(rustRoot, "oxide", "config"),
                    Path.Combine(rustRoot, "umod", "plugins"),
                    Path.Combine(rustRoot, "umod", "config"),
                    Path.Combine(rustRoot, "RustDedicated_Data", "Managed", "oxide"),
                };

                foreach (var oxideDir in oxideDirs)
                {
                    if (ct.IsCancellationRequested) break;
                    if (!Directory.Exists(oxideDir)) continue;

                    string[] pluginFiles = Array.Empty<string>();
                    try { pluginFiles = Directory.GetFiles(oxideDir, "*.cs", SearchOption.TopDirectoryOnly); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var plugin in pluginFiles)
                    {
                        if (ct.IsCancellationRequested) break;
                        var pluginName = Path.GetFileNameWithoutExtension(plugin).ToLowerInvariant();

                        foreach (var kw in SuspiciousOxidePluginKeywords)
                        {
                            if (pluginName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.IncrementFiles();
                                ctx.AddFinding(new Finding
                                {
                                    Module = _name,
                                    Title    = $"Suspicious Oxide/uMod Plugin: {Path.GetFileName(plugin)}",
                                    Risk     = RiskLevel.High,
                                    Location = plugin,
                                    FileName = Path.GetFileName(plugin),
                                    Reason   = $"Oxide/uMod plugin '{Path.GetFileName(plugin)}' contains keyword '{kw}' " +
                                               "associated with cheating, exploitation, or server manipulation in Rust. " +
                                               "This plugin may provide unauthorized advantages or exploit server vulnerabilities.",
                                    Detail   = $"Plugin directory: {oxideDir} | Matched keyword: {kw}"
                                });
                                break;
                            }
                        }

                        // Also scan plugin source for cheat keywords
                        TryScanOxidePluginContent(plugin, ctx);
                    }
                }
            }
        }, ct);
    }

    private static readonly string[] OxideCheatCodePatterns = new[]
    {
        "BasePlayer.IsAdmin", "permission.UserHasPermission",
        "player.IsGod()", "player.SetPlayerFlag",
        "KillMessage.Suicide", "entity.Kill()",
        "player.Hurt(", "player.Die(",
        "player.MovePosition(", "player.ClientRPCPlayer(",
        "SendNetworkUpdate", "inventory.GiveItem",
        "item.info.shortname", "ItemManager.CreateByName",
        "BaseNpc", "patrol_helicopter",
        "ConVar.Server.hostname",
        "auth.level", "authlevel",
        "rcon.", "AdminKick", "AdminBan",
        "CanUseUI", "DestroyUI",
        "Physics.OverlapSphere", "raycast",
        "hack", "cheat", "exploit", "bypass",
    };

    private static void TryScanOxidePluginContent(string file, ScanContext ctx)
    {
        try
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            string content = sr.ReadToEnd();

            // Look for abuse patterns — need combination of suspicious patterns
            var suspiciousHits = OxideCheatCodePatterns
                .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                .Take(5)
                .ToList();

            // Only flag if clearly cheat-related
            bool hasExplicitCheatKeyword = content.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                                           content.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                           content.Contains("exploit", StringComparison.OrdinalIgnoreCase) ||
                                           content.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                           content.Contains("aimbot", StringComparison.OrdinalIgnoreCase) ||
                                           content.Contains("esp", StringComparison.OrdinalIgnoreCase);

            if (hasExplicitCheatKeyword && suspiciousHits.Count >= 2)
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = _name,
                    Title    = $"Oxide Plugin With Cheat Code Patterns: {Path.GetFileName(file)}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason   = $"Oxide plugin '{Path.GetFileName(file)}' contains code patterns ({string.Join(", ", suspiciousHits.Take(3).Select(h => $"'{h}'"))}) " +
                               "combined with explicit cheat-related keywords. This plugin may be implementing " +
                               "cheating functionality within the server-side Oxide/uMod framework.",
                    Detail   = $"Suspicious patterns: {string.Join(", ", suspiciousHits)}"
                });
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    // -------------------------------------------------------------------------
    // Sub-check: Harmony and Carbon injection framework abuse
    // -------------------------------------------------------------------------
    private Task CheckHarmonyAndCarbonInjection(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.62, Name, "Checking for Harmony/Carbon injection abuse...");

            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var appData     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var localApp    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            // Look for Harmony patches outside legitimate game directories
            var harmonySearchDirs = new[]
            {
                appData,
                localApp,
                Path.Combine(userProfile, "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            };

            var suspiciousHarmonyFiles = new[]
            {
                "0Harmony.dll", "HarmonyX.dll", "HarmonyLib.dll",
                "0Harmony_rust.dll", "harmony_rust.dll",
                "carbon_exploit.dll", "carbon_cheat.dll",
                "carbon_hack.dll", "carbon_inject.dll",
                "harmony_inject.dll", "harmony_exploit.dll",
                "harmony_cheat.dll", "harmony_hack.dll",
            };

            foreach (var searchDir in harmonySearchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(searchDir)) continue;

                foreach (var harmonyFile in suspiciousHarmonyFiles)
                {
                    var fullPath = Path.Combine(searchDir, harmonyFile);
                    if (!File.Exists(fullPath)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"Suspicious Harmony/Carbon File Outside Game: {harmonyFile}",
                        Risk     = RiskLevel.High,
                        Location = fullPath,
                        FileName = harmonyFile,
                        Reason   = $"Harmony or Carbon injection framework file '{harmonyFile}' found outside " +
                                   $"a legitimate game directory at '{searchDir}'. " +
                                   "Harmony patching and Carbon framework can be abused to inject cheat code " +
                                   "into Rust at runtime by patching game methods in memory.",
                        Detail   = $"Found at: {fullPath}"
                    });
                }

                // Also recursively scan for carbon/harmony exploit directories
                string[] subdirs = Array.Empty<string>();
                try { subdirs = Directory.GetDirectories(searchDir); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var sub in subdirs)
                {
                    if (ct.IsCancellationRequested) break;
                    var subName = Path.GetFileName(sub).ToLowerInvariant();

                    if (subName.Contains("harmony", StringComparison.OrdinalIgnoreCase) &&
                        (subName.Contains("exploit", StringComparison.OrdinalIgnoreCase) ||
                         subName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                         subName.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                         subName.Contains("rust", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = $"Suspicious Harmony Directory: {Path.GetFileName(sub)}",
                            Risk     = RiskLevel.High,
                            Location = sub,
                            FileName = Path.GetFileName(sub),
                            Reason   = $"Directory '{Path.GetFileName(sub)}' in '{searchDir}' has a name " +
                                       "combining 'harmony' with cheat-related keywords. " +
                                       "This may indicate a Harmony-based Rust cheat injection framework.",
                            Detail   = $"Directory: {sub}"
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Sub-check: MUICache registry
    // -------------------------------------------------------------------------
    private Task CheckRegistryMuiCache(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.70, Name, "Checking MUICache for Rust cheat execution history...");

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(MUICacheKeyPath, writable: false);
                if (key is null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    var fileNamePart = Path.GetFileName(valueName);
                    var lowerValue   = valueName.ToLowerInvariant();

                    // Check known cheat EXE names
                    if (KnownRustCheatExeNames.Contains(fileNamePart))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = $"Rust Cheat Execution Record (MUICache): {fileNamePart}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKCU\{MUICacheKeyPath}",
                            FileName = fileNamePart,
                            Reason   = $"MUICache registry record shows Rust cheat tool '{fileNamePart}' was previously " +
                                       "executed on this system. MUICache persists execution records even after the file is deleted.",
                            Detail   = $"Registry value: {valueName}"
                        });
                        continue;
                    }

                    // Fuzzy match with cheat folder keywords
                    foreach (var kw in KnownRustCheatFolderKeywords)
                    {
                        if (lowerValue.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = _name,
                                Title    = $"Rust Cheat Execution Record (MUICache): {kw}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKCU\{MUICacheKeyPath}",
                                FileName = fileNamePart,
                                Reason   = $"MUICache record '{valueName}' contains keyword '{kw}' associated " +
                                           "with Rust cheat tools. This indicates a cheat tool was previously " +
                                           "launched from this path.",
                                Detail   = $"Registry value: {valueName} | Matched keyword: {kw}"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Sub-check: UserAssist registry (ROT13-decoded shell execution records)
    // -------------------------------------------------------------------------
    private Task CheckRegistryUserAssist(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.78, Name, "Checking UserAssist records for Rust cheat history...");

            try
            {
                using var uaRoot = Registry.CurrentUser.OpenSubKey(UserAssistKeyPath, writable: false);
                if (uaRoot is null) return;

                foreach (var guidName in uaRoot.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;

                    try
                    {
                        using var guidKey = uaRoot.OpenSubKey(guidName + @"\Count", writable: false);
                        if (guidKey is null) continue;

                        foreach (var valueName in guidKey.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementRegistryKeys();

                            var decoded      = Rot13(valueName);
                            var decodedLower = decoded.ToLowerInvariant();
                            var fileNamePart = Path.GetFileName(decoded);

                            // Check known cheat EXE names
                            if (KnownRustCheatExeNames.Contains(fileNamePart))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = _name,
                                    Title    = $"Rust Cheat Execution Record (UserAssist): {fileNamePart}",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKCU\{UserAssistKeyPath}\{guidName}\Count",
                                    FileName = fileNamePart,
                                    Reason   = $"UserAssist registry entry (ROT13 decoded: '{decoded}') shows " +
                                               $"Rust cheat executable '{fileNamePart}' was launched by the user. " +
                                               "UserAssist records persist even after the file and folder are deleted.",
                                    Detail   = $"Decoded path: {decoded} | GUID: {guidName}"
                                });
                                continue;
                            }

                            // Fuzzy match
                            foreach (var kw in KnownRustCheatFolderKeywords)
                            {
                                if (decodedLower.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = _name,
                                        Title    = $"Rust Cheat in UserAssist: {kw}",
                                        Risk     = RiskLevel.High,
                                        Location = $@"HKCU\{UserAssistKeyPath}\{guidName}\Count",
                                        FileName = fileNamePart,
                                        Reason   = $"UserAssist record (decoded: '{decoded}') contains keyword '{kw}' " +
                                                   "associated with Rust cheat tools or cheating communities.",
                                        Detail   = $"Decoded path: {decoded} | GUID: {guidName} | Keyword: {kw}"
                                    });
                                    break;
                                }
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
    // Sub-check: Programs/Uninstall registry entries for known Rust cheats
    // -------------------------------------------------------------------------
    private Task CheckRegistryUninstall(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.86, Name, "Checking Uninstall registry for Rust cheat software...");

            var uninstallPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };

            foreach (var path in uninstallPaths)
            {
                if (ct.IsCancellationRequested) return;

                try
                {
                    using var root = Registry.LocalMachine.OpenSubKey(path, writable: false)
                                  ?? Registry.CurrentUser.OpenSubKey(path, writable: false);
                    if (root is null) continue;

                    foreach (var subKeyName in root.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        try
                        {
                            using var sub = root.OpenSubKey(subKeyName, writable: false);
                            if (sub is null) continue;

                            var displayName     = (sub.GetValue("DisplayName")     as string ?? "").ToLowerInvariant();
                            var installLocation = (sub.GetValue("InstallLocation") as string ?? "").ToLowerInvariant();
                            var uninstallString = (sub.GetValue("UninstallString") as string ?? "").ToLowerInvariant();

                            var combined = $"{displayName} {installLocation} {uninstallString}";

                            foreach (var kw in KnownRustCheatFolderKeywords)
                            {
                                if (combined.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = _name,
                                        Title    = $"Rust Cheat Software in Uninstall Registry: {subKeyName}",
                                        Risk     = RiskLevel.Critical,
                                        Location = $@"HKLM\{path}\{subKeyName}",
                                        Reason   = $"Uninstall registry entry '{displayName}' contains keyword '{kw}' " +
                                                   "associated with Rust cheat software. " +
                                                   "This indicates a Rust cheat tool was or still is installed on the system.",
                                        Detail   = $"DisplayName: {displayName} | InstallLocation: {installLocation} | Key: {subKeyName}"
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Helper: find Rust installation paths
    // -------------------------------------------------------------------------
    private static List<string> GetRustInstallPaths()
    {
        var paths = new List<string>();

        var programFiles    = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        // Default Steam paths
        paths.Add(Path.Combine(programFiles,    "Steam", "steamapps", "common", "Rust"));
        paths.Add(Path.Combine(programFilesX86, "Steam", "steamapps", "common", "Rust"));
        paths.Add(Path.Combine("C:\\", "Program Files", "Steam", "steamapps", "common", "Rust"));
        paths.Add(Path.Combine("D:\\", "SteamLibrary", "steamapps", "common", "Rust"));
        paths.Add(Path.Combine("D:\\", "Games", "Rust"));
        paths.Add(Path.Combine("E:\\", "Games", "Rust"));

        // Try to find via Steam registry
        try
        {
            using var steamKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Valve\Steam", writable: false);
            var steamPath = steamKey?.GetValue("SteamPath") as string;
            if (!string.IsNullOrEmpty(steamPath))
            {
                paths.Add(Path.Combine(steamPath, "steamapps", "common", "Rust"));
            }
        }
        catch { }

        // Try additional Steam library folders from libraryfolders.vdf
        try
        {
            using var steamKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Valve\Steam", writable: false);
            var steamPath = steamKey?.GetValue("SteamPath") as string;
            if (!string.IsNullOrEmpty(steamPath))
            {
                var libraryFolders = Path.Combine(steamPath, "steamapps", "libraryfolders.vdf");
                if (File.Exists(libraryFolders))
                {
                    using var fs = new FileStream(libraryFolders, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string vdfContent = sr.ReadToEnd();

                    // Parse path entries from VDF format: "path"  "C:\\Games\\Steam"
                    var lines = vdfContent.Split('\n');
                    foreach (var line in lines)
                    {
                        if (!line.Contains("\"path\"", StringComparison.OrdinalIgnoreCase)) continue;
                        var parts = line.Split('"');
                        if (parts.Length >= 4)
                        {
                            var libPath = parts[3].Replace("\\\\", "\\");
                            if (Directory.Exists(libPath))
                            {
                                paths.Add(Path.Combine(libPath, "steamapps", "common", "Rust"));
                            }
                        }
                    }
                }
            }
        }
        catch { }

        return paths;
    }
}
