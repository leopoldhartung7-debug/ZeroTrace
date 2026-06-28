using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class GTA5OnlineCheatScanModule : IScanModule
{
    private static readonly string _name = "GTA V Online Cheat Detection";
    public string Name => _name;
    public double Weight => 4.5;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Known mod menu executable and DLL names (100+ variants)
    // -------------------------------------------------------------------------
    private static readonly HashSet<string> KnownCheatExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Kiddion's Modest Menu
        "kiddions_modest_menu.exe", "modest_menu.exe", "kiddions.exe", "kiddion.exe",
        // 2Take1
        "2take1.exe", "2t1.exe", "twotakeone.exe",
        // Eulen
        "eulen.exe", "eulen_menu.exe",
        // Cherax
        "cherax.exe", "cherax_menu.exe",
        // Impulse
        "impulse.exe", "impulse_menu.exe",
        // Stand
        "stand.exe", "stand_menu.exe",
        // Brutan
        "brutan.exe", "brutan_menu.exe",
        // Force
        "force_menu.exe", "forcemenu.exe",
        // Ketchup
        "ketchup_menu.exe", "ketchup.exe",
        // Gang
        "gang_menu.exe", "gangmenu.exe",
        // Luna
        "lunax.exe", "luna.exe", "luna_menu.exe",
        // Midnight
        "midnight.exe", "midnight_menu.exe",
        // Atone
        "atone.exe", "atone_menu.exe",
        // Gravity
        "gravity_menu.exe", "gravity.exe",
        // Night
        "night.exe", "night_menu.exe",
        // Shift
        "shift_menu.exe", "shiftmenu.exe",
        // Partial
        "partial.exe", "partial_menu.exe",
        // Big Base
        "big_base.exe", "bigbase.exe",
        // Phantom X
        "phantom_x.exe", "phantomx.exe",
        // Ozark
        "ozark.exe", "ozark_menu.exe",
        // Vanish
        "vanish.exe", "vanish_menu.exe",
        // Legion
        "legion.exe", "legion_menu.exe",
        // Paragon
        "paragon.exe", "paragon_menu.exe",
        // Lazer
        "lazer.exe", "lazer_menu.exe",
        // Void
        "void.exe", "void_menu.exe",
        // Astro
        "astro.exe", "astro_menu.exe",
        // Nova
        "nova.exe", "nova_menu.exe",
        // Celestia
        "celestia.exe", "celestia_menu.exe",
        // Aurora
        "aurora.exe", "aurora_menu.exe",
        // Revolution
        "revolution.exe", "revolution_menu.exe",
        // Phantom
        "phantom.exe", "phantom_menu.exe",
        // Crystal
        "crystal.exe", "crystal_menu.exe",
        // Diamond
        "diamond.exe", "diamond_menu.exe",
        // Sapphire
        "sapphire.exe", "sapphire_menu.exe",
        // Emerald
        "emerald.exe", "emerald_menu.exe",
        // Odin
        "odin.exe", "odin_menu.exe",
        // Zeus
        "zeus.exe", "zeus_menu.exe",
        // Thor
        "thor.exe", "thor_menu.exe",
        // Loki
        "loki.exe", "loki_menu.exe",
        // Simple Trainer
        "simple_trainer.exe", "simpletrainer.exe", "gta5_trainer.exe",
        // Menyoo
        "menyoo.exe", "menyoopc.exe", "menyoo_trainer.exe",
        // Native Trainer
        "native_trainer.exe", "nativetrainer.exe",
        // Lambda Menu
        "lambda_menu.exe", "lambdamenu.exe",
        // Absolute Menu
        "absolute_menu.exe", "absolutemenu.exe",
        // Susano
        "susano.exe", "susano_menu.exe",
        // Hyperion
        "hyperion.exe", "hyperion_menu.exe",
        // Scarlet
        "scarlet.exe", "scarlet_menu.exe",
        // Spectre
        "spectre.exe", "spectre_menu.exe",
        // Reaper
        "reaper.exe", "reaper_menu.exe",
        // Hammafia
        "hammafia.exe",
        // Desudo
        "desudo.exe",
        // Lynx
        "lynx.exe", "lynx_menu.exe",
        // Nexus
        "nexusmenu.exe", "nexus_menu.exe",
        // Rxce
        "rxce.exe",
        // Tsunami
        "tsunami.exe", "tsunami_menu.exe",
        // RedEngine
        "redengine.exe",
        // Yim Menu
        "yimmenu.exe", "yim_menu.exe",
        // Celestial
        "celestial.exe",
        // Generic cheat loaders
        "gta_loader.exe", "gta5_loader.exe", "gta_hack.exe", "gta5_hack.exe",
        "gta_cheat.exe", "gta5_cheat.exe", "gta_mod.exe", "gta5_mod.exe",
        "modmenu.exe", "mod_menu.exe", "cheatmenu.exe", "cheat_menu.exe",
        "moneymod.exe", "money_mod.exe", "moneyhack.exe", "money_hack.exe",
        "godmode.exe", "god_mode.exe", "gta_god.exe",
        "rockstar_bypass.exe", "sc_bypass.exe", "socialclub_bypass.exe",
    };

    // DLL equivalents — same names with .dll extension
    private static readonly HashSet<string> KnownCheatDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "kiddions_modest_menu.dll", "modest_menu.dll", "kiddions.dll",
        "2take1.dll", "2t1.dll", "eulen.dll", "eulen_menu.dll",
        "cherax.dll", "cherax_menu.dll", "impulse.dll", "impulse_menu.dll",
        "stand.dll", "stand_menu.dll", "brutan.dll", "force_menu.dll",
        "ketchup_menu.dll", "gang_menu.dll", "lunax.dll", "luna_menu.dll",
        "midnight.dll", "atone.dll", "gravity_menu.dll", "night.dll",
        "shift_menu.dll", "partial.dll", "big_base.dll", "phantom_x.dll",
        "ozark.dll", "vanish.dll", "legion.dll", "paragon.dll",
        "lazer.dll", "void.dll", "astro.dll", "nova.dll",
        "celestia.dll", "aurora.dll", "revolution.dll", "phantom.dll",
        "crystal.dll", "diamond.dll", "sapphire.dll", "emerald.dll",
        "odin.dll", "zeus.dll", "thor.dll", "loki.dll",
        "lambda_menu.dll", "absolute_menu.dll", "susano.dll",
        "hyperion.dll", "scarlet.dll", "spectre.dll", "reaper.dll",
        "yimmenu.dll", "yim_menu.dll", "nexusmenu.dll",
        "rxce.dll", "tsunami.dll", "redengine.dll", "celestial.dll",
        "hammafia.dll", "desudo.dll", "lynx.dll",
        // Script Hook V ecosystem
        "scripthookv.dll", "scripthookvdotnet.dll", "nativeui.dll",
        "scripthookvdotnet2.dll", "scripthookvdotnet3.dll",
        // ASI loaders in user directories (suspicious context)
        "dinput8.dll", "dsound.dll", "version.dll",
        // Money drop / exploit DLLs
        "money_drop.dll", "moneydrop.dll", "vehicle_spawn.dll",
        "godmode.dll", "god_mode.dll", "wanted_bypass.dll",
        // Injection helpers
        "inject_helper.dll", "injector_helper.dll", "gta_inject.dll",
    };

    // Known cheat config/settings file names
    private static readonly HashSet<string> KnownCheatConfigFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "modest_menu_settings.json", "kiddions_config.json", "kiddions_settings.json",
        "2take1_config.json", "2take1_settings.json", "eulen_config.json", "eulen_settings.json",
        "cherax_config.json", "cherax_settings.json", "impulse_config.json",
        "stand_config.json", "stand_settings.json", "ozark_config.json",
        "phantom_config.json", "luna_config.json", "luna_settings.json",
        "midnight_config.json", "celestia_config.json", "aurora_config.json",
        "brutan_config.json", "force_config.json", "vanish_config.json",
        "legion_config.json", "paragon_config.json", "nova_config.json",
        "void_config.json", "astro_config.json", "revolution_config.json",
        "crystal_config.json", "diamond_config.json", "sapphire_config.json",
        "odin_config.json", "zeus_config.json", "yimmenu_config.json",
        "modmenu_config.json", "mod_menu_config.json", "cheat_config.json",
        "gta_cheat_config.json", "gta5_settings.json", "trainer_settings.json",
        "menyoo_config.xml", "menyoo_settings.xml", "simple_trainer.ini",
        "nativetrainer.ini", "nativetrainer_settings.ini",
        "money_drop_config.json", "vehicle_spawn_config.json",
        "godmode_config.json", "teleport_config.json",
    };

    // Known .asi cheat file names
    private static readonly HashSet<string> KnownCheatAsiFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "kiddions.asi", "modest_menu.asi", "2take1.asi", "eulen.asi",
        "cherax.asi", "impulse.asi", "stand.asi", "ozark.asi",
        "phantom.asi", "luna.asi", "midnight.asi", "celestia.asi",
        "aurora.asi", "revolution.asi", "crystal.asi", "diamond.asi",
        "sapphire.asi", "odin.asi", "zeus.asi", "nova.asi", "void.asi",
        "astro.asi", "astro_menu.asi", "yimmenu.asi",
        "menyoo.asi", "trainerv.asi", "nativetrainer.asi",
        "simpletrainerv.asi", "simple_trainer.asi",
        "moneymod.asi", "money_mod.asi", "moneydrop.asi",
        "godmode.asi", "god_mode.asi", "teleport.asi",
        "weaponspawn.asi", "vehicle_spawn.asi", "vehiclespawn.asi",
        "wantedlevel.asi", "wantedmod.asi",
        "rockstareditor_bypass.asi", "bypass.asi", "inject.asi",
        "spoofer.asi", "hwid_spoof.asi",
        "blackout.asi", "blackout_v.asi",
        "reaper.asi", "scarlet.asi", "spectre.asi", "hyperion.asi",
        "susano.asi", "lynx.asi", "nexusmenu.asi",
    };

    // Folder name fragments that indicate GTA cheat mod directories
    private static readonly string[] KnownCheatFolderKeywords = new[]
    {
        "kiddions", "modest_menu", "modestmenu", "2take1", "twotakeone",
        "eulen", "cherax", "impulse_menu", "stand_menu", "ozark",
        "phantom_x", "phantomx", "luna_menu", "lunamenu", "midnight_menu",
        "celestia_menu", "aurora_menu", "revolution_menu", "nova_menu",
        "yimmenu", "yim_menu", "lambda_menu", "absolute_menu",
        "menyoopc", "menyoo", "simple_trainer", "simpletrainer",
        "modmenu", "mod_menu", "cheat_menu", "cheats_gta",
        "gta5_cheats", "gta_online_cheat", "gta_hack",
        "money_drop", "moneydrop", "vehicle_spawn", "weaponspawn",
        "godmode_gta", "gtav_trainer", "gta5trainer",
        "rockstar_bypass", "sc_bypass",
        "hammafia", "desudo", "lynx_menu", "nexus_menu",
        "tsunami_menu", "redengine", "rxce", "celestial_gta",
        "susano_menu", "hyperion_menu", "scarlet_menu", "spectre_menu",
        "reaper_menu",
    };

    // Keywords in config file content that strongly indicate cheat usage
    private static readonly string[] CheatConfigKeywords = new[]
    {
        "godmode", "god_mode", "money_drop", "moneydrop",
        "vehicle_spawn", "vehiclespawn", "teleport_menu", "teleportmenu",
        "player_blips", "weapon_spawn", "weaponspawn",
        "wanted_level", "wantedlevel", "police_ignore", "policeignore",
        "modmenu", "mod_menu", "kiddions", "2take1", "eulen", "cherax",
        "impulse_menu", "stand_menu", "ozark", "phantom_x",
        "no_clip", "noclip", "super_jump", "superjump",
        "never_wanted", "never wanted", "infinite_health", "infinite_ammo",
        "explosive_bullets", "fire_bullets", "ped_spawner",
        "blackout", "session_kick", "kick_all", "crash_menu",
        "session_options", "lobby_options", "protections_menu",
        "recovery_menu", "stat_editor", "rp_money", "cash_drop",
    };

    // Script Hook V and ASI Loader file names (suspicious outside game dir)
    private static readonly string[] ScriptHookFiles = new[]
    {
        "ScriptHookV.dll", "ScriptHookVDotNet.dll", "ScriptHookVDotNet2.dll",
        "ScriptHookVDotNet3.dll", "NativeUI.dll", "NativeUIReloaded.dll",
        "dinput8.dll", "dsound.dll", "version.dll",
        "asi_loader.log", "ScriptHookV.log",
    };

    // Directories to scan for cheat artifacts
    private static string[] GetScanDirectories()
    {
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var temp     = Path.GetTempPath();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var desktop  = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(userProfile, "Downloads");
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        return new[]
        {
            localApp,
            appData,
            temp,
            desktop,
            downloads,
            documents,
            Path.Combine(localApp, "Temp"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
            Path.Combine(documents, "Rockstar Games"),
            Path.Combine(documents, "GTA V"),
            Path.Combine(documents, "GTA5"),
            Path.Combine(documents, "GTAV"),
        };
    }

    // Registry paths to check for MUICache and UserAssist records
    private static readonly string MUICacheKeyPath =
        @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

    private static readonly string UserAssistKeyPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

    // ROT13 decoder for UserAssist GUID keys
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

    // -------------------------------------------------------------------------
    // Entry point
    // -------------------------------------------------------------------------
    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting GTA V Online cheat detection...");

        await Task.WhenAll(
            CheckFilesystem(ctx, ct),
            CheckCheatProcesses(ctx, ct),
            CheckRegistryMuiCache(ctx, ct),
            CheckRegistryUserAssist(ctx, ct),
            CheckRegistryUninstall(ctx, ct),
            CheckScriptHookOutsideGame(ctx, ct),
            CheckRockstarEditorBypass(ctx, ct)
        );

        ctx.Report(1.0, Name, "GTA V Online cheat detection complete.");
    }

    // -------------------------------------------------------------------------
    // Sub-check: filesystem scan across known directories
    // -------------------------------------------------------------------------
    private Task CheckFilesystem(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            ctx.Report(0.05, Name, "Scanning filesystem for GTA V cheat artifacts...");

            var dirs = GetScanDirectories();
            var tasks = dirs.Select(dir => ScanDirectoryForCheats(dir, ctx, ct)).ToArray();
            await Task.WhenAll(tasks);

            ctx.Report(0.45, Name, "Filesystem scan complete.");
        }, ct);
    }

    private Task ScanDirectoryForCheats(string rootDir, ScanContext ctx, CancellationToken ct)
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

                // Check folder name itself for cheat keywords
                var dirName = Path.GetFileName(dir) ?? string.Empty;
                foreach (var kw in KnownCheatFolderKeywords)
                {
                    if (dirName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = $"GTA V Cheat Directory: {dirName}",
                            Risk     = RiskLevel.Critical,
                            Location = dir,
                            FileName = dirName,
                            Reason   = $"Directory name '{dirName}' matches known GTA V Online cheat mod menu folder pattern '{kw}'. " +
                                       "This directory is associated with mod menus or cheat tools targeting GTA V Online.",
                            Detail   = $"Matched keyword: {kw} | Path: {dir}"
                        });
                        break;
                    }
                }

                // Enumerate files in this directory
                string[] files = Array.Empty<string>();
                try { files = Directory.GetFiles(dir); }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    InspectFile(file, ctx);
                }

                // Enumerate subdirectories (max depth 6)
                string[] subs = Array.Empty<string>();
                try { subs = Directory.GetDirectories(dir); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var sub in subs) stack.Push(sub);
            }
        }, ct);
    }

    private void InspectFile(string file, ScanContext ctx)
    {
        var fileName = Path.GetFileName(file);
        var ext = Path.GetExtension(file);

        // Check known cheat EXE names
        if (KnownCheatExeNames.Contains(fileName))
        {
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = _name,
                Title    = $"Known GTA V Cheat Executable: {fileName}",
                Risk     = RiskLevel.Critical,
                Location = file,
                FileName = fileName,
                Reason   = $"File '{fileName}' is a known GTA V Online mod menu or cheat tool executable. " +
                           "This executable is associated with unauthorized game modifications that provide " +
                           "unfair advantages in GTA V Online including god mode, money drops, and vehicle spawning.",
                Detail   = $"Full path: {file}"
            });
            return;
        }

        // Check known cheat DLL names
        if (KnownCheatDllNames.Contains(fileName))
        {
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = _name,
                Title    = $"Known GTA V Cheat DLL: {fileName}",
                Risk     = RiskLevel.Critical,
                Location = file,
                FileName = fileName,
                Reason   = $"DLL '{fileName}' is associated with known GTA V Online cheat tools or mod menus. " +
                           "These libraries are injected into the GTA V process to enable cheating functionality " +
                           "such as aimbot, ESP, money drops, god mode, and session manipulation.",
                Detail   = $"Full path: {file}"
            });
            return;
        }

        // Check known cheat ASI files
        if (KnownCheatAsiFiles.Contains(fileName))
        {
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = _name,
                Title    = $"Known GTA V Cheat ASI Plugin: {fileName}",
                Risk     = RiskLevel.Critical,
                Location = file,
                FileName = fileName,
                Reason   = $"ASI plugin file '{fileName}' is a known GTA V Online cheat or unauthorized trainer. " +
                           "ASI files are loaded via the ASI Loader and inject directly into the game process.",
                Detail   = $"Full path: {file}"
            });
            return;
        }

        // Check known cheat config files
        if (KnownCheatConfigFiles.Contains(fileName))
        {
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = _name,
                Title    = $"GTA V Cheat Configuration File: {fileName}",
                Risk     = RiskLevel.High,
                Location = file,
                FileName = fileName,
                Reason   = $"Configuration file '{fileName}' belongs to a known GTA V Online cheat tool or mod menu. " +
                           "The presence of this settings file indicates the associated cheat was previously installed and configured.",
                Detail   = $"Full path: {file}"
            });
            // Also scan config content for cheat keywords
            TryScanConfigContent(file, fileName, ctx);
            return;
        }

        // Scan JSON/INI/XML/CFG files for cheat keywords
        if (ext.Equals(".json", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".ini",  StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".xml",  StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".cfg",  StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".txt",  StringComparison.OrdinalIgnoreCase))
        {
            TryScanConfigContent(file, fileName, ctx);
        }
    }

    private void TryScanConfigContent(string file, string fileName, ScanContext ctx)
    {
        try
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            string content = sr.ReadToEnd();

            foreach (var kw in CheatConfigKeywords)
            {
                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"GTA V Cheat Keyword in Config: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"Configuration file '{fileName}' contains the keyword '{kw}' which is " +
                                   "strongly associated with GTA V Online cheat tools including god mode, " +
                                   "money drops, vehicle spawners, and session manipulation features.",
                        Detail   = $"Matched keyword: {kw} | File: {file}"
                    });
                    return;
                }
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    // -------------------------------------------------------------------------
    // Sub-check: running processes
    // -------------------------------------------------------------------------
    private Task CheckCheatProcesses(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.10, Name, "Checking running processes for GTA V cheat tools...");

            try
            {
                foreach (var proc in ctx.GetProcessSnapshot())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementProcesses();

                    try
                    {
                        var procName = proc.ProcessName + ".exe";

                        if (KnownCheatExeNames.Contains(procName))
                        {
                            string? exePath = null;
                            try { exePath = proc.MainModule?.FileName; } catch { }

                            ctx.AddFinding(new Finding
                            {
                                Module = _name,
                                Title    = $"GTA V Cheat Process Running: {proc.ProcessName}",
                                Risk     = RiskLevel.Critical,
                                Location = exePath ?? $"PID {proc.Id}",
                                FileName = proc.ProcessName,
                                Reason   = $"GTA V Online cheat tool '{proc.ProcessName}' is currently running. " +
                                           "This is a known mod menu or cheat executable that provides unauthorized " +
                                           "advantages in GTA V Online.",
                                Detail   = $"PID: {proc.Id} | Name: {proc.ProcessName} | Path: {exePath ?? "unknown"}"
                            });
                            continue;
                        }

                        // Check for cheat keywords in process name (fuzzy match)
                        var lowerName = proc.ProcessName.ToLowerInvariant();
                        foreach (var kw in KnownCheatFolderKeywords)
                        {
                            if (lowerName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                string? exePath = null;
                                try { exePath = proc.MainModule?.FileName; } catch { }

                                ctx.AddFinding(new Finding
                                {
                                    Module = _name,
                                    Title    = $"Suspicious GTA V Process: {proc.ProcessName}",
                                    Risk     = RiskLevel.High,
                                    Location = exePath ?? $"PID {proc.Id}",
                                    FileName = proc.ProcessName,
                                    Reason   = $"Process name '{proc.ProcessName}' contains keyword '{kw}' " +
                                               "associated with GTA V Online cheat tools or mod menus.",
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
    // Sub-check: MUICache registry (records last-executed app display names)
    // -------------------------------------------------------------------------
    private Task CheckRegistryMuiCache(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.50, Name, "Checking MUICache for GTA V cheat execution history...");

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(MUICacheKeyPath, writable: false);
                if (key is null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    var lowerValue = valueName.ToLowerInvariant();

                    // Check against known cheat exe names
                    var fileNamePart = Path.GetFileName(valueName);
                    if (KnownCheatExeNames.Contains(fileNamePart))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = $"GTA V Cheat Execution Record (MUICache): {fileNamePart}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKCU\{MUICacheKeyPath}",
                            FileName = fileNamePart,
                            Reason   = $"MUICache registry record indicates GTA V Online cheat tool '{fileNamePart}' " +
                                       "was previously executed on this system. MUICache stores display names of " +
                                       "recently launched executables.",
                            Detail   = $"Registry value: {valueName}"
                        });
                        continue;
                    }

                    // Check for cheat keywords in the path
                    foreach (var kw in KnownCheatFolderKeywords)
                    {
                        if (lowerValue.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = _name,
                                Title    = $"GTA V Cheat Execution Record (MUICache): {kw}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKCU\{MUICacheKeyPath}",
                                FileName = fileNamePart,
                                Reason   = $"MUICache record '{valueName}' contains keyword '{kw}' associated " +
                                           "with GTA V Online cheat tools. This indicates a cheat tool was " +
                                           "previously launched from this path.",
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
    // Sub-check: UserAssist registry (ROT13-encoded shell execution records)
    // -------------------------------------------------------------------------
    private Task CheckRegistryUserAssist(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.58, Name, "Checking UserAssist records for GTA V cheat history...");

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

                            var decoded = Rot13(valueName);
                            var decodedLower = decoded.ToLowerInvariant();
                            var fileNamePart = Path.GetFileName(decoded);

                            if (KnownCheatExeNames.Contains(fileNamePart))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = _name,
                                    Title    = $"GTA V Cheat Execution Record (UserAssist): {fileNamePart}",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKCU\{UserAssistKeyPath}\{guidName}\Count",
                                    FileName = fileNamePart,
                                    Reason   = $"UserAssist registry entry (ROT13 decoded: '{decoded}') shows " +
                                               $"GTA V cheat executable '{fileNamePart}' was launched by the user. " +
                                               "UserAssist records persist even after file deletion.",
                                    Detail   = $"Decoded path: {decoded} | GUID: {guidName}"
                                });
                                continue;
                            }

                            foreach (var kw in KnownCheatFolderKeywords)
                            {
                                if (decodedLower.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = _name,
                                        Title    = $"GTA V Cheat in UserAssist: {kw}",
                                        Risk     = RiskLevel.High,
                                        Location = $@"HKCU\{UserAssistKeyPath}\{guidName}\Count",
                                        FileName = fileNamePart,
                                        Reason   = $"UserAssist record (decoded: '{decoded}') contains keyword '{kw}' " +
                                                   "associated with GTA V Online cheat tools or mod menus.",
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
    // Sub-check: Programs/Uninstall registry entries for known cheats
    // -------------------------------------------------------------------------
    private Task CheckRegistryUninstall(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.65, Name, "Checking Uninstall registry for GTA V cheat software...");

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

                            var displayName    = (sub.GetValue("DisplayName")    as string ?? "").ToLowerInvariant();
                            var installLocation = (sub.GetValue("InstallLocation") as string ?? "").ToLowerInvariant();
                            var uninstallString = (sub.GetValue("UninstallString") as string ?? "").ToLowerInvariant();

                            var combined = $"{displayName} {installLocation} {uninstallString}";

                            foreach (var kw in KnownCheatFolderKeywords)
                            {
                                if (combined.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = _name,
                                        Title    = $"GTA V Cheat Software in Uninstall Registry: {subKeyName}",
                                        Risk     = RiskLevel.Critical,
                                        Location = $@"HKLM\{path}\{subKeyName}",
                                        Reason   = $"Uninstall registry entry '{displayName}' contains keyword '{kw}' " +
                                                   "associated with GTA V Online cheat software. " +
                                                   "This indicates the cheat tool was or still is installed on the system.",
                                        Detail   = $"DisplayName: {displayName} | InstallLocation: {installLocation}"
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
    // Sub-check: Script Hook V / ASI Loader files outside game directory
    // -------------------------------------------------------------------------
    private Task CheckScriptHookOutsideGame(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.72, Name, "Checking for Script Hook V files outside game directory...");

            // Known legitimate GTA V install paths
            var legitimateGamePaths = GetLegitimateGtaVPaths();

            var searchDirs = GetScanDirectories();

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                foreach (var hookFile in ScriptHookFiles)
                {
                    var fullPath = Path.Combine(dir, hookFile);
                    if (!File.Exists(fullPath)) continue;

                    // Check if this is inside a legitimate game directory
                    bool isInGameDir = legitimateGamePaths.Any(p =>
                        fullPath.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                    if (!isInGameDir)
                    {
                        ctx.IncrementFiles();
                        var isAsiLoader = hookFile.Equals("dinput8.dll", StringComparison.OrdinalIgnoreCase) ||
                                          hookFile.Equals("dsound.dll",  StringComparison.OrdinalIgnoreCase) ||
                                          hookFile.Equals("version.dll", StringComparison.OrdinalIgnoreCase);

                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = isAsiLoader
                                ? $"GTA ASI Loader DLL Outside Game Directory: {hookFile}"
                                : $"Script Hook V File Outside Game Directory: {hookFile}",
                            Risk     = isAsiLoader ? RiskLevel.High : RiskLevel.Critical,
                            Location = fullPath,
                            FileName = hookFile,
                            Reason   = isAsiLoader
                                ? $"ASI Loader file '{hookFile}' found outside the legitimate GTA V installation directory at '{dir}'. " +
                                  "ASI Loaders are used to load unauthorized .asi cheat plugins into GTA V."
                                : $"Script Hook V file '{hookFile}' found outside the legitimate GTA V installation directory at '{dir}'. " +
                                  "Script Hook V is a modding framework required by most GTA V mod menus and cheat tools.",
                            Detail   = $"Found at: {fullPath} | Expected in: {string.Join(", ", legitimateGamePaths)}"
                        });
                    }
                }
            }

            // Also check Scripts directory for known cheat .asi files
            CheckScriptsDirectoriesForCheats(ctx, ct);
        }, ct);
    }

    private void CheckScriptsDirectoriesForCheats(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            // Look for "scripts" subdirectory — a common cheat/mod folder
            var scriptsDir = Path.Combine(root, "scripts");
            if (!Directory.Exists(scriptsDir)) continue;

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(scriptsDir, "*.asi"); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                var fn = Path.GetFileName(file);

                if (KnownCheatAsiFiles.Contains(fn))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = $"GTA V Cheat ASI Plugin in Scripts Folder: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known GTA V cheat ASI file '{fn}' found in scripts directory '{scriptsDir}'. " +
                                   "ASI files in the scripts folder are loaded automatically by Script Hook V and " +
                                   "enable cheat functionality directly inside GTA V.",
                        Detail   = $"Scripts dir: {scriptsDir}"
                    });
                }
            }
        }
    }

    private static List<string> GetLegitimateGtaVPaths()
    {
        var paths = new List<string>();

        // Common Steam installation paths
        var programFiles   = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        paths.Add(Path.Combine(programFiles,    "Rockstar Games", "Grand Theft Auto V"));
        paths.Add(Path.Combine(programFilesX86, "Rockstar Games", "Grand Theft Auto V"));
        paths.Add(Path.Combine(programFiles,    "Steam", "steamapps", "common", "Grand Theft Auto V"));
        paths.Add(Path.Combine(programFilesX86, "Steam", "steamapps", "common", "Grand Theft Auto V"));
        paths.Add(Path.Combine("C:\\", "Program Files", "Rockstar Games", "Grand Theft Auto V"));
        paths.Add(Path.Combine("D:\\", "Rockstar Games", "Grand Theft Auto V"));
        paths.Add(Path.Combine("D:\\", "Games", "Grand Theft Auto V"));
        paths.Add(Path.Combine("E:\\", "Games", "Grand Theft Auto V"));

        // Try to find via registry (Rockstar Games Launcher)
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Rockstar Games\Grand Theft Auto V", writable: false)
                ?? Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Rockstar Games\Grand Theft Auto V", writable: false);
            if (key is not null)
            {
                var installFolder = key.GetValue("InstallFolder") as string;
                if (!string.IsNullOrEmpty(installFolder))
                    paths.Add(installFolder);
            }
        }
        catch { }

        // Try via Steam registry
        try
        {
            using var steamKey = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Valve\Steam", writable: false);
            var steamPath = steamKey?.GetValue("SteamPath") as string;
            if (!string.IsNullOrEmpty(steamPath))
            {
                paths.Add(Path.Combine(steamPath, "steamapps", "common", "Grand Theft Auto V"));
            }
        }
        catch { }

        return paths;
    }

    // -------------------------------------------------------------------------
    // Sub-check: Rockstar Editor bypass artifacts
    // -------------------------------------------------------------------------
    private Task CheckRockstarEditorBypass(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ctx.Report(0.82, Name, "Checking for Rockstar Editor bypass and Social Club bypass artifacts...");

            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var localApp    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var documents   = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            // Known Rockstar Editor bypass artifact locations
            var suspiciousPaths = new[]
            {
                Path.Combine(localApp, "Rockstar Games", "GTA V", "Profiles"),
                Path.Combine(localApp, "Rockstar Games", "Social Club"),
                Path.Combine(documents, "Rockstar Games", "GTA V", "Profiles"),
            };

            // Suspicious file names within those directories
            var bypassFileKeywords = new[]
            {
                "bypass", "spoof", "modded", "hacked", "injected",
                "editor_bypass", "socialclub_bypass", "sc_bypass",
                "ban_bypass", "anti_ban", "antidetect",
                "cheater_profile", "modded_profile",
            };

            foreach (var searchDir in suspiciousPaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(searchDir)) continue;

                string[] files = Array.Empty<string>();
                try { files = Directory.GetFiles(searchDir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file).ToLowerInvariant();

                    foreach (var kw in bypassFileKeywords)
                    {
                        if (fn.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = _name,
                                Title    = $"GTA V Bypass/Cheat Artifact: {Path.GetFileName(file)}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason   = $"File '{Path.GetFileName(file)}' in GTA V profile/Social Club directory " +
                                           $"contains keyword '{kw}' associated with bypass tools or cheating artifacts. " +
                                           "This may indicate Social Club bypass, Rockstar Editor manipulation, or ban evasion tools.",
                                Detail   = $"Matched keyword: {kw} | Path: {file}"
                            });
                            break;
                        }
                    }
                }
            }

            // Check registry for Rockstar Social Club bypass-related keys
            CheckSocialClubRegistryBypass(ctx, ct);
        }, ct);
    }

    private static void CheckSocialClubRegistryBypass(ScanContext ctx, CancellationToken ct)
    {
        var suspiciousRegPaths = new[]
        {
            @"SOFTWARE\Rockstar Games\Social Club",
            @"SOFTWARE\WOW6432Node\Rockstar Games\Social Club",
            @"SOFTWARE\Rockstar Games\Launcher",
        };

        var suspiciousValueKeywords = new[]
        {
            "bypass", "spoof", "offline", "cracked", "modded",
        };

        foreach (var regPath in suspiciousRegPaths)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false)
                             ?? Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    foreach (var kw in suspiciousValueKeywords)
                    {
                        if (valueName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = _name,
                                Title    = $"Suspicious Rockstar Registry Value: {valueName}",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{regPath}",
                                Reason   = $"Rockstar Games registry key contains suspicious value '{valueName}' " +
                                           $"matching keyword '{kw}'. This may indicate Social Club bypass or " +
                                           "cracked/modified Rockstar launcher configuration.",
                                Detail   = $"Registry path: {regPath} | Value: {valueName}"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }
    }
}
