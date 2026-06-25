using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class TeamFortress2CheatScanModule : IScanModule
{
    public string Name => "Team Fortress 2 Cheat Forensic Scan";
    public double Weight => 3.3;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    // -------------------------------------------------------------------------
    // Known TF2 cheat executable and DLL artifact names
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> KnownCheatExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        "tf2cheat.exe",
        "tf2_aimbot.exe",
        "tf2aim.dll",
        "catbot.dll",
        "lmaobox.dll",
        "lmaobox.exe",
        "mge_cheat.exe",
        "hvh_tf2.exe",
        "tbot.exe",
        "trixware.exe",
        "trixware.dll",
        "supremacy.dll",
        "supremacy_tf2.exe",
        "animtrigger.dll",
        "masterchief.dll",
        "aimware_tf2.dll",
        "sketchware.dll",
        "gamesense_tf2.dll",
        "opai.dll",
        "primordial.dll",
        "tf2_wh.exe",
        "tf2_esp.exe",
        "tf2_hack.exe",
        "tf2_loader.exe",
        "tf2_injector.exe",
        "tf2_bypass.exe",
        "tf2_trigger.exe",
        "tf2_spinbot.exe",
        "tf2_bhop.exe",
        "tf2_silentaim.exe",
        "tf2_crits.exe",
        "tf2_autobackstab.exe",
        "tf2_projectilehack.exe",
        "tf2_speedhack.exe",
        "tf2_noclip.exe",
        "tf2_radar.exe",
        "tf2_wallhack.exe",
        "tf2_godmode.exe",
        "tf2_fakeping.exe",
        "tf2_lagcomp.exe",
        "tf2_resolverbot.exe",
        "hvhbot_tf2.exe",
        "hvhloader_tf2.exe",
        "ragebot_tf2.exe",
        "legitbot_tf2.exe",
        "aimassist_tf2.exe",
        "hvh_loader.exe",
        "tf2_external.exe",
        "tf2_internal.exe",
        "tf2_menu.exe",
        "tf2_unlocker.exe",
        "lmaobox_loader.exe",
        "catbot_loader.exe",
        "trixware_loader.exe",
        "gamesense_loader.exe",
        "tf2_dma.exe",
        "dma_tf2.exe",
        "tf2_memory.exe",
        "tf2_cheat.dll",
        "tf2_hook.dll",
        "tf2_overlay.dll",
        "tf2_inject.dll",
        "tf2_proxy.dll",
        "tf2_module.dll",
        "aimware.dll",
        "skeet_tf2.dll",
        "neverlose_tf2.dll",
        "fatality_tf2.dll",
        "interium_tf2.dll",
        "tf2_aim.dll",
        "tf2_esp.dll",
        "tf2_wh.dll",
        "tf2_trigger.dll",
        "tf2_bhop.dll",
        "tf2_spinbot.dll",
        "tf2_crits.dll",
        "tf2_legit.dll",
    };

    // -------------------------------------------------------------------------
    // VAC bypass artifact names
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> VacBypassArtifacts = new(StringComparer.OrdinalIgnoreCase)
    {
        "vac_bypass_tf2.dll",
        "tf2_vac_bypass.exe",
        "steamvac_bypass.dll",
        "vac_bypass.dll",
        "vac_bypass.exe",
        "steam_bypass_tf2.dll",
        "vacbypass_tf2.dll",
        "vac_killer_tf2.exe",
        "vac_hook.dll",
        "steamapi_bypass.dll",
        "vac_disable_tf2.exe",
        "vac_patch_tf2.exe",
        "vac_unload.dll",
        "valve_bypass.dll",
        "valve_bypass.exe",
        "steamvac.dll",
        "vacnet_bypass.dll",
        "vacnet_killer.exe",
        "vacnet_disable.exe",
        "tf2_novac.exe",
        "tf2_bypass_vac.dll",
        "bypass_vac.exe",
    };

    // -------------------------------------------------------------------------
    // Suspicious overlay DLL names found in TF2 game directory
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> SuspiciousOverlayDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "discord-overlay.dll",
        "afterburner-overlay.dll",
        "rtss.dll",
        "rivatuner_overlay.dll",
        "fraps_overlay.dll",
        "bandicam_overlay.dll",
        "dxtory_overlay.dll",
        "xfire_overlay.dll",
        "gameoverlayrenderer.dll",
        "gameoverlayrenderer64.dll",
        "d3d9.dll",
        "d3d11.dll",
        "dxgi.dll",
        "opengl32.dll",
        "d3d8.dll",
        "ddraw.dll",
        "dinput8.dll",
        "xinput9_1_0.dll",
        "winmm.dll",
        "version.dll",
        "dbghelp.dll",
        "tier0.dll",
        "tier0_s.dll",
        "vstdlib.dll",
        "vstdlib_s.dll",
        "steam_api.dll",
        "steam_api64.dll",
        "steamclient.dll",
        "steamclient64.dll",
    };

    // -------------------------------------------------------------------------
    // TF2 cheat configuration file keywords
    // -------------------------------------------------------------------------

    private static readonly string[] CheatConfigKeywords =
    {
        "bind \"mouse5\" \"+aimbot\"",
        "bind \"mouse4\" \"+aimbot\"",
        "bind \"ins\" \"+aimbot\"",
        "exec cheat.cfg",
        "exec hack.cfg",
        "exec aimbot.cfg",
        "exec lmaobox",
        "exec catbot",
        "exec hvh",
        "exec tbot",
        "exec trixware",
        "exec supremacy",
        "exec aimware",
        "+bhop",
        "sv_cheats 1",
        "r_drawothermodels 2",
        "ent_fire !self",
        "tf_show_damage 1",
        "net_fakelag",
        "net_fakeloss",
        "bunnyhop",
        "aimbotkey",
        "triggerbot",
        "wallhack",
        "norecoil",
        "nospread",
        "silentaim",
        "aimlock",
        "tf_damage_disablespread 1",
        "tf_use_fixed_weapons_spread 1",
        "tf_weapon_criticals 0",
        "aimbot_enabled",
        "aimbot_key",
        "aimbot_smooth",
        "aimbot_fov",
        "esp_enabled",
        "wallhack_enabled",
        "bhop_enabled",
        "spinbot_enabled",
        "crithack",
        "autocrit",
        "fakeping",
        "lag_exploit",
        "backtrack",
        "resolver",
        "hvh_mode",
        "rage_mode",
        "autostab",
        "autobackstab",
    };

    // -------------------------------------------------------------------------
    // SourceMod plugin cheat keywords (for .smx file detection)
    // -------------------------------------------------------------------------

    private static readonly string[] SourceModCheatKeywords =
    {
        "aimbot", "esp", "wallhack", "cheat", "hack", "bhop",
        "trigger", "spinbot", "godmode", "noclip", "speedhack",
        "crits", "autocrit", "silentaim", "critbot", "autobackstab",
        "norecoil", "nospread", "hvh", "ragebot", "lagcomp",
        "backtrack", "resolver", "fakeping", "bypass", "inject",
        "cheater", "tbot", "lmaobox", "catbot", "trixware",
    };

    // -------------------------------------------------------------------------
    // Class config file names to check for cheat binds
    // -------------------------------------------------------------------------

    private static readonly string[] Tf2ClassConfigFiles =
    {
        "scout.cfg", "soldier.cfg", "pyro.cfg", "demoman.cfg",
        "heavyweapons.cfg", "engineer.cfg", "medic.cfg",
        "sniper.cfg", "spy.cfg", "autoexec.cfg",
        "config.cfg", "valve.rc",
        "scout_cfg.cfg", "soldier_cfg.cfg", "pyro_cfg.cfg",
        "demoman_cfg.cfg", "heavy_cfg.cfg", "engineer_cfg.cfg",
        "medic_cfg.cfg", "sniper_cfg.cfg", "spy_cfg.cfg",
        "cheat.cfg", "hack.cfg", "hvh.cfg", "rage.cfg",
        "legit.cfg", "aimbot.cfg", "esp.cfg", "bhop.cfg",
        "settings.cfg", "binds.cfg", "custom.cfg",
    };

    // -------------------------------------------------------------------------
    // Lua script cheat content keywords
    // -------------------------------------------------------------------------

    private static readonly string[] LuaCheatKeywords =
    {
        "tf2", "teamfortress", "lmaobox", "catbot", "tbot", "hvh",
        "aimbot", "esp", "wallhack", "bhop", "spinbot", "crithack",
        "autobackstab", "autocrit", "silentaim", "triggerbot",
        "norecoil", "fakeping", "lagcomp", "backtrack", "resolver",
        "inject_tf2", "tf2_hook", "tf2_bypass", "team_fortress",
        "tf_cheat", "vac_bypass", "steam_bypass",
    };

    // -------------------------------------------------------------------------
    // Registry run key keywords to flag for TF2 cheat loaders
    // -------------------------------------------------------------------------

    private static readonly string[] RegistryRunKeywords =
    {
        "lmaobox", "catbot", "tbot", "trixware", "supremacy",
        "aimware_tf2", "sketchware", "gamesense_tf2", "opai",
        "primordial", "tf2cheat", "tf2_aimbot", "tf2_loader",
        "tf2_bypass", "hvh_tf2", "tf2_hack", "tf2_esp",
        "tf2_wallhack", "tf2_injector", "vac_bypass_tf2",
        "vacnet_bypass", "masterchief", "animtrigger",
        "tf2_cheat", "tf2_unlocker", "tf2_spinbot", "tf2_crits",
    };

    // -------------------------------------------------------------------------
    // MUICache cheat keywords
    // -------------------------------------------------------------------------

    private static readonly string[] MuiCacheKeywords =
    {
        "lmaobox", "catbot", "tbot", "trixware", "supremacy",
        "aimware_tf2", "sketchware", "gamesense_tf2", "opai",
        "primordial", "tf2cheat", "tf2_aimbot", "tf2_loader",
        "tf2_bypass", "hvh_tf2", "tf2_hack", "tf2_esp",
        "tf2_wallhack", "tf2_injector", "vac_bypass_tf2",
        "vacnet_bypass", "masterchief", "animtrigger",
        "tf2_cheat", "tf2_unlocker", "tf2_spinbot",
        "hvhbot_tf2", "tf2_menu", "tf2_external",
    };

    // -------------------------------------------------------------------------
    // Temp folder cheat artifact file names
    // -------------------------------------------------------------------------

    private static readonly string[] TempCheatArtifactNames =
    {
        "tf2_cheat.log", "tf2_cheat.cfg", "tf2cheat.log",
        "lmaobox.log", "lmaobox.cfg", "lmaobox_config.json",
        "catbot.log", "catbot.cfg", "catbot_config.json",
        "tbot.log", "tbot.cfg", "tbot_config.json",
        "trixware.log", "trixware.cfg",
        "hvh_tf2.log", "hvh_config.json",
        "supremacy.log", "supremacy.cfg",
        "aimware_tf2.log", "aimware_tf2.cfg",
        "gamesense_tf2.log", "gamesense_tf2.cfg",
        "tf2_aimbot.log", "tf2_esp.log",
        "tf2_settings.json", "tf2_config.json",
        "tf2cheat_dump.txt", "tf2cheat_log.txt",
        "vac_bypass.log", "vac_bypass.cfg",
        "vacnet_bypass.log", "steamvac_bypass.log",
        "tf2_loader.log", "tf2_inject.log",
        "tf2_offsets.txt", "tf2_patterns.txt",
        "tf2_addresses.txt", "tf2_dump.txt",
    };

    // -------------------------------------------------------------------------
    // Known TF2 offset / pattern file names (used by external cheats)
    // -------------------------------------------------------------------------

    private static readonly string[] OffsetFileNames =
    {
        "tf2_offsets.json", "tf2_offsets.txt", "tf2_addresses.txt",
        "tf2_patterns.txt", "tf2_netvars.txt", "tf2_netvars.json",
        "tf2_offsets.cfg", "tf2_dump.txt", "tf2_signatures.txt",
        "offsets_tf2.json", "offsets_tf2.txt", "tf2_offset_dump.txt",
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

    private static IEnumerable<string> GetTf2InstallPaths()
    {
        var paths = new List<string>
        {
            @"C:\Program Files (x86)\Steam\steamapps\common\Team Fortress 2",
            @"C:\Program Files\Steam\steamapps\common\Team Fortress 2",
            @"D:\Steam\steamapps\common\Team Fortress 2",
            @"D:\SteamLibrary\steamapps\common\Team Fortress 2",
            @"E:\Steam\steamapps\common\Team Fortress 2",
            @"E:\SteamLibrary\steamapps\common\Team Fortress 2",
            @"F:\SteamLibrary\steamapps\common\Team Fortress 2",
            @"G:\SteamLibrary\steamapps\common\Team Fortress 2",
        };
        var steamPath = GetSteamInstallPath();
        if (!string.IsNullOrEmpty(steamPath))
            paths.Add(Path.Combine(steamPath, "steamapps", "common", "Team Fortress 2"));
        return paths.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    // -------------------------------------------------------------------------
    // IScanModule.RunAsync
    // -------------------------------------------------------------------------

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Team Fortress 2 cheat forensic scan");

        await Task.WhenAll(
            CheckKnownCheatExecutables(ctx, ct),
            CheckVacBypassArtifacts(ctx, ct),
            CheckTf2GameDirectoryOverlayDlls(ctx, ct),
            CheckSourceModPluginArtifacts(ctx, ct),
            CheckCustomHudEspArtifacts(ctx, ct),
            CheckClassConfigCheatBinds(ctx, ct),
            CheckAutoexecCheatContent(ctx, ct),
            CheckTempFolderArtifacts(ctx, ct),
            CheckOffsetPatternFiles(ctx, ct),
            CheckLuaScriptArtifacts(ctx, ct),
            CheckRegistryRunKeys(ctx, ct),
            CheckUserAssistArtifacts(ctx, ct),
            CheckMuiCacheArtifacts(ctx, ct),
            CheckDownloadsFolderArtifacts(ctx, ct),
            CheckAppDataArtifacts(ctx, ct)
        );

        ctx.Report(1.0, Name, "Team Fortress 2 cheat forensic scan complete");
    }

    // -------------------------------------------------------------------------
    // Check 1: Known cheat executables in Downloads, Desktop, AppData, TF2 dir
    // -------------------------------------------------------------------------

    private Task CheckKnownCheatExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.02, Name, "Scanning for known TF2 cheat executables");

            var searchBases = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow"),
            };

            foreach (var tf2Path in GetTf2InstallPaths())
                searchBases.Add(tf2Path);

            foreach (var baseDir in searchBases)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(baseDir)) continue;

                string[] entries;
                try
                {
                    entries = Directory.GetFiles(baseDir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in entries)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (!KnownCheatExecutables.Contains(fn)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"TF2 Cheat Executable Found: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"The file '{fn}' is a known Team Fortress 2 cheat executable or DLL artifact. " +
                                 "This binary is associated with aimbot, ESP, wallhack, or bypass functionality " +
                                 "for TF2. Its presence on disk is a direct forensic artifact of cheat tool usage.",
                        Detail = $"Path: {file}"
                    });
                }
            }

            // Also do a recursive search in TF2 install paths
            foreach (var tf2Root in GetTf2InstallPaths())
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tf2Root)) continue;

                IEnumerable<string> allFiles;
                try
                {
                    allFiles = Directory.EnumerateFiles(tf2Root, "*", SearchOption.AllDirectories);
                }
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
                        Title = $"TF2 Cheat DLL/EXE in Game Directory: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known TF2 cheat binary '{fn}' was found inside the Team Fortress 2 game " +
                                 "directory tree. Cheats placed in the game folder are loaded automatically " +
                                 "at launch or injected at runtime. This is a high-confidence cheat artifact.",
                        Detail = $"TF2 install: {tf2Root} | File: {file}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 2: VAC bypass DLLs and executables
    // -------------------------------------------------------------------------

    private Task CheckVacBypassArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.07, Name, "Scanning for VAC/VACnet bypass artifacts");

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

            foreach (var tf2Path in GetTf2InstallPaths())
                searchBases.Add(tf2Path);

            foreach (var baseDir in searchBases)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(baseDir)) continue;

                string[] files;
                try
                {
                    files = Directory.GetFiles(baseDir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (!VacBypassArtifacts.Contains(fn)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"VAC Bypass Artifact Found: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"The file '{fn}' is a known VAC (Valve Anti-Cheat) or VACnet bypass artifact " +
                                 "for Team Fortress 2. VAC bypass tools prevent the anti-cheat system from " +
                                 "detecting injected cheat DLLs or from scanning process memory. Their " +
                                 "presence is a direct forensic indicator of anti-cheat evasion.",
                        Detail = $"Path: {file}"
                    });
                }
            }

            // Also scan inside TF2 bin/ directory specifically — VAC bypass DLLs are commonly
            // placed there to intercept the game's DLL loading process.
            foreach (var tf2Root in GetTf2InstallPaths())
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tf2Root)) continue;

                var binDir = Path.Combine(tf2Root, "bin");
                if (!Directory.Exists(binDir)) continue;

                string[] binFiles;
                try { binFiles = Directory.GetFiles(binDir, "*.dll", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in binFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (!VacBypassArtifacts.Contains(fn)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"VAC Bypass DLL in TF2 bin Directory: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"A known VAC bypass DLL '{fn}' was found in the TF2 bin directory. " +
                                 "Placing bypass DLLs in the game's binary folder is a classic technique " +
                                 "for intercepting VAC scanning calls via DLL side-loading.",
                        Detail = $"Bin directory: {binDir} | File: {file}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 3: Suspicious overlay DLLs in TF2 game directory
    // -------------------------------------------------------------------------

    private Task CheckTf2GameDirectoryOverlayDlls(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.12, Name, "Scanning TF2 directory for suspicious overlay DLLs");

            foreach (var tf2Root in GetTf2InstallPaths())
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tf2Root)) continue;

                // Scan bin/ and tf/ directories for suspicious proxy/overlay DLLs
                var scanSubDirs = new[] { "bin", "tf", "hl2", "platform" };

                foreach (var subDir in scanSubDirs)
                {
                    if (ct.IsCancellationRequested) return;
                    var dir = Path.Combine(tf2Root, subDir);
                    if (!Directory.Exists(dir)) continue;

                    string[] dllFiles;
                    try { dllFiles = Directory.GetFiles(dir, "*.dll", SearchOption.TopDirectoryOnly); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in dllFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);

                        // Overlay DLLs that are normally NOT present in TF2 game subdirectories
                        // and may be used for hooking DirectX or Steam API calls
                        if (!SuspiciousOverlayDlls.Contains(fn)) continue;

                        // d3d9.dll inside tf2 bin/ is extremely suspicious — it is a classic
                        // DirectX hook placement for rendering ESP/wallhack overlays
                        var risk = fn.Equals("d3d9.dll", StringComparison.OrdinalIgnoreCase)
                                || fn.Equals("d3d11.dll", StringComparison.OrdinalIgnoreCase)
                                || fn.Equals("dxgi.dll", StringComparison.OrdinalIgnoreCase)
                                || fn.Equals("opengl32.dll", StringComparison.OrdinalIgnoreCase)
                                ? RiskLevel.High
                                : RiskLevel.Medium;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious Overlay DLL in TF2 Directory: {fn}",
                            Risk = risk,
                            Location = file,
                            FileName = fn,
                            Reason = $"The DLL '{fn}' is present in the TF2 game subdirectory '{subDir}'. " +
                                     "Cheat tools commonly place proxy/hook DLLs (d3d9.dll, opengl32.dll, " +
                                     "dinput8.dll, etc.) inside the game directory to intercept DirectX, " +
                                     "Steam API, or input calls for ESP rendering or aimbot functionality.",
                            Detail = $"Directory: {dir} | File: {file}"
                        });
                    }
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 4: SourceMod plugin cheat artifacts (.smx files)
    // -------------------------------------------------------------------------

    private Task CheckSourceModPluginArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.17, Name, "Scanning SourceMod plugin directories for cheat .smx files");

            foreach (var tf2Root in GetTf2InstallPaths())
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tf2Root)) continue;

                // SourceMod plugins live in tf/addons/sourcemod/plugins/
                var pluginsDir = Path.Combine(tf2Root, "tf", "addons", "sourcemod", "plugins");
                if (!Directory.Exists(pluginsDir)) continue;

                string[] smxFiles;
                try { smxFiles = Directory.GetFiles(pluginsDir, "*.smx", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var smxFile in smxFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(smxFile).ToLowerInvariant();

                    // Check the filename itself for cheat keywords
                    bool nameMatch = SourceModCheatKeywords.Any(kw =>
                        fn.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (nameMatch)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious SourceMod Plugin: {Path.GetFileName(smxFile)}",
                            Risk = RiskLevel.High,
                            Location = smxFile,
                            FileName = Path.GetFileName(smxFile),
                            Reason = $"A SourceMod plugin file '{Path.GetFileName(smxFile)}' with a cheat-related " +
                                     "name was found in the TF2 addons/sourcemod/plugins directory. " +
                                     "SourceMod plugins compiled as .smx files can implement server-side " +
                                     "cheat commands, auto-critical hits, gravity manipulation, or ESP features.",
                            Detail = $"Plugins directory: {pluginsDir} | File: {smxFile}"
                        });
                        continue;
                    }

                    // Read the compiled plugin binary for embedded cheat strings
                    // SMX files are bytecode containers and may contain readable string literals
                    string content;
                    try
                    {
                        using var fs = new FileStream(smxFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, System.Text.Encoding.Latin1);
                        content = sr.ReadToEnd();
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var kw in SourceModCheatKeywords)
                    {
                        if (!content.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"SourceMod Plugin Contains Cheat Content: {Path.GetFileName(smxFile)}",
                            Risk = RiskLevel.High,
                            Location = smxFile,
                            FileName = Path.GetFileName(smxFile),
                            Reason = $"The SourceMod plugin '{Path.GetFileName(smxFile)}' contains embedded " +
                                     $"string matching the cheat-related keyword '{kw}'. " +
                                     "Compiled .smx plugins may embed readable cheat function names, " +
                                     "command strings, or configuration identifiers in their bytecode.",
                            Detail = $"Keyword matched: {kw} | File: {smxFile}"
                        });
                        break;
                    }
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 5: Custom HUD/resource files modified with ESP overlays
    // -------------------------------------------------------------------------

    private Task CheckCustomHudEspArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.22, Name, "Scanning TF2 custom resource/HUD for ESP overlay artifacts");

            var espHudKeywords = new[]
            {
                "esp", "wallhack", "cheat", "aimbot", "hack", "bypass",
                "drawothermodels", "mat_fullbright", "r_drawothermodels",
                "overlay", "radar", "noclip",
                "healthbar_esp", "player_esp", "entity_esp",
                "box_esp", "skeleton_esp", "name_esp",
            };

            foreach (var tf2Root in GetTf2InstallPaths())
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tf2Root)) continue;

                // TF2 custom HUD and resource files live in tf/custom/ and tf/resource/
                var customDirs = new[]
                {
                    Path.Combine(tf2Root, "tf", "custom"),
                    Path.Combine(tf2Root, "tf", "resource"),
                    Path.Combine(tf2Root, "tf", "scripts"),
                    Path.Combine(tf2Root, "tf", "cfg"),
                };

                foreach (var dir in customDirs)
                {
                    if (ct.IsCancellationRequested) return;
                    if (!Directory.Exists(dir)) continue;

                    IEnumerable<string> hudFiles;
                    try
                    {
                        hudFiles = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in hudFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var ext = Path.GetExtension(file).ToLowerInvariant();
                        if (ext != ".res" && ext != ".txt" && ext != ".vmt"
                            && ext != ".cfg" && ext != ".json" && ext != ".vdf")
                            continue;

                        var fn = Path.GetFileName(file).ToLowerInvariant();

                        // Check file name first
                        bool nameHit = espHudKeywords.Any(kw =>
                            fn.Contains(kw, StringComparison.OrdinalIgnoreCase));

                        if (nameHit)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious TF2 Custom HUD File: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"A TF2 custom HUD or resource file '{Path.GetFileName(file)}' with a " +
                                         "cheat/ESP-related name was found in the TF2 custom or resource directory. " +
                                         "Custom HUD modifications can include ESP-style overlays, wallhack visual " +
                                         "elements, or modified models that highlight enemies.",
                                Detail = $"Directory: {dir} | File: {file}"
                            });
                            continue;
                        }

                        // Check file content
                        string content;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = sr.ReadToEnd();
                        }
                        catch (IOException) { continue; }
                        catch (UnauthorizedAccessException) { continue; }

                        foreach (var kw in espHudKeywords)
                        {
                            if (!content.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"TF2 Custom HUD/Resource File Contains ESP Content: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"The TF2 HUD/resource file '{Path.GetFileName(file)}' contains the " +
                                         $"keyword '{kw}', which is associated with ESP overlay or wallhack " +
                                         "visual modifications. Cheat-modified HUD files can render enemy " +
                                         "positions, health bars, or wallhack visuals through the game's " +
                                         "legitimate HUD rendering pipeline.",
                                Detail = $"Keyword: {kw} | Directory: {dir} | File: {file}"
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 6: TF2 class config files with cheat binds
    // -------------------------------------------------------------------------

    private Task CheckClassConfigCheatBinds(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.27, Name, "Scanning TF2 class config files for cheat binds");

            foreach (var tf2Root in GetTf2InstallPaths())
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tf2Root)) continue;

                var cfgDir = Path.Combine(tf2Root, "tf", "cfg");
                if (!Directory.Exists(cfgDir)) continue;

                foreach (var cfgName in Tf2ClassConfigFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    var cfgPath = Path.Combine(cfgDir, cfgName);
                    if (!File.Exists(cfgPath)) continue;

                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(cfgPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = sr.ReadToEnd();
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var keyword in CheatConfigKeywords)
                    {
                        if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"TF2 Class Config Contains Cheat Bind: {cfgName}",
                            Risk = RiskLevel.High,
                            Location = cfgPath,
                            FileName = cfgName,
                            Reason = $"The TF2 class configuration file '{cfgName}' contains the keyword " +
                                     $"'{keyword}', which is associated with cheat scripts. Common cheat cfg " +
                                     "patterns include binding aimbot toggles to mouse buttons, executing " +
                                     "external cheat config files, or setting bhop/wallhack/ESP CVars. " +
                                     "Class configs are executed automatically by TF2 when switching classes.",
                            Detail = $"Keyword: {keyword} | Config: {cfgPath}"
                        });
                        break;
                    }
                }

                // Also enumerate all .cfg files in the cfg directory for cheat exec patterns
                string[] allCfgs;
                try { allCfgs = Directory.GetFiles(cfgDir, "*.cfg", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var cfgPath in allCfgs)
                {
                    if (ct.IsCancellationRequested) return;
                    var cfgName = Path.GetFileName(cfgPath);

                    // Flag configs with cheat-related names
                    bool nameIsCheat = CheatConfigKeywords.Any(kw =>
                        cfgName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (nameIsCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"TF2 Cheat-Named Config File: {cfgName}",
                            Risk = RiskLevel.High,
                            Location = cfgPath,
                            FileName = cfgName,
                            Reason = $"A TF2 config file with the cheat-related name '{cfgName}' was found in " +
                                     "the TF2 cfg directory. Cheat-specific config files are a standard artifact " +
                                     "of cheat tools that load their settings via the TF2 config system.",
                            Detail = $"Config path: {cfgPath}"
                        });
                    }
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 7: autoexec.cfg scanning for cheat binds and execs
    // -------------------------------------------------------------------------

    private Task CheckAutoexecCheatContent(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.33, Name, "Scanning TF2 autoexec.cfg for cheat content");

            foreach (var tf2Root in GetTf2InstallPaths())
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tf2Root)) continue;

                var autoexecPath = Path.Combine(tf2Root, "tf", "cfg", "autoexec.cfg");
                if (!File.Exists(autoexecPath)) continue;

                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(autoexecPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = sr.ReadToEnd();
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                var foundKeywords = new List<string>();
                foreach (var keyword in CheatConfigKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        foundKeywords.Add(keyword);
                }

                if (foundKeywords.Count == 0) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "TF2 autoexec.cfg Contains Cheat Commands",
                    Risk = RiskLevel.High,
                    Location = autoexecPath,
                    FileName = "autoexec.cfg",
                    Reason = "The TF2 autoexec.cfg file contains commands associated with cheat functionality. " +
                             "autoexec.cfg is executed every time TF2 launches, making it a common location " +
                             "for cheat tool configuration loading, aimbot key bindings, bhop scripts, " +
                             "or VACnet evasion commands.",
                    Detail = $"Matched keywords: {string.Join(", ", foundKeywords)}"
                });

                // Additionally check for 'exec' lines pointing to cheat config files
                var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (!trimmed.StartsWith("exec", StringComparison.OrdinalIgnoreCase)) continue;

                    var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 2) continue;
                    var execTarget = parts[1].Trim('"', '\'');

                    bool targetIsCheat = CheatConfigKeywords.Any(kw =>
                        execTarget.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (!targetIsCheat) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"autoexec.cfg Executes Cheat Config: {execTarget}",
                        Risk = RiskLevel.Critical,
                        Location = autoexecPath,
                        FileName = "autoexec.cfg",
                        Reason = $"The TF2 autoexec.cfg contains 'exec {execTarget}', which loads a " +
                                 "cheat-named configuration file on every game launch. This pattern is " +
                                 "used by TF2 cheat tools including lmaobox, catbot, and HvH loaders " +
                                 "to automatically configure cheats via the TF2 console.",
                        Detail = $"Exec command: {trimmed} | autoexec: {autoexecPath}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 8: Temp folder TF2 cheat log and config artifacts
    // -------------------------------------------------------------------------

    private Task CheckTempFolderArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.40, Name, "Scanning temp folders for TF2 cheat logs and configs");

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
                        Title = $"TF2 Cheat Artifact in Temp Directory: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"A TF2 cheat-associated file '{fn}' was found in the system temp directory. " +
                                 "Cheat tools write log files, crash dumps, configuration caches, and " +
                                 "offset dumps to temp directories. These artifacts persist after the " +
                                 "cheat executable has been removed.",
                        Detail = $"Temp dir: {tempDir} | File: {file}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 9: Offset/pattern/address files for TF2 external cheats
    // -------------------------------------------------------------------------

    private Task CheckOffsetPatternFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.45, Name, "Scanning for TF2 external cheat offset and pattern files");

            var searchDirs = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.GetTempPath(),
            };

            foreach (var tf2Path in GetTf2InstallPaths())
                searchDirs.Add(tf2Path);

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

                    bool isOffsetFile = OffsetFileNames.Any(o =>
                        fn.Equals(o, StringComparison.OrdinalIgnoreCase));

                    if (!isOffsetFile) continue;

                    // Read the file to confirm it contains TF2 memory structure references
                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = sr.ReadToEnd();
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    var tf2OffsetKeywords = new[]
                    {
                        "client.dll", "engine.dll", "tf2", "team_fortress",
                        "CTFPlayer", "C_TFPlayer", "CTFWeaponBase", "CTFGameRules",
                        "m_iHealth", "m_lifeState", "m_vecOrigin", "m_angEyeAngles",
                        "m_iTeamNum", "m_iClass", "m_hActiveWeapon",
                        "GetClientMode", "CreateMove", "FrameStageNotify",
                        "LocalPlayer", "PlayerList", "EntityList",
                        "GlowObjectManager", "CHLClient",
                    };

                    bool hasTf2Content = tf2OffsetKeywords.Any(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (!hasTf2Content) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"TF2 External Cheat Offset File: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"The file '{fn}' appears to be a TF2 external cheat offset or memory " +
                                 "pattern file. These files contain memory addresses and structure offsets " +
                                 "for TF2 game objects (players, weapons, entities). External cheat tools " +
                                 "read these files to locate player health, position, team, and class " +
                                 "data in the game's memory for ESP and aimbot functionality.",
                        Detail = $"File: {file}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 10: Lua scripts with TF2 cheat content in user folders
    // -------------------------------------------------------------------------

    private Task CheckLuaScriptArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.52, Name, "Scanning for Lua scripts with TF2 cheat content");

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Scripts"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Lua"),
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                IEnumerable<string> luaFiles;
                try
                {
                    luaFiles = Directory.EnumerateFiles(dir, "*.lua", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in luaFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = sr.ReadToEnd();
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var kw in LuaCheatKeywords)
                    {
                        if (!content.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Lua Script Contains TF2 Cheat Content: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"The Lua script '{Path.GetFileName(file)}' contains the keyword '{kw}', " +
                                     "which is associated with TF2 cheat scripting. Some TF2 cheats use " +
                                     "embedded Lua scripting engines for configurable aimbot, trigger, " +
                                     "and ESP functionality. Lua scripts are also used by some HvH loaders " +
                                     "to define resolver and backtrack behavior.",
                            Detail = $"Keyword: {kw} | File: {file}"
                        });
                        break;
                    }
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 11: Registry Run keys for TF2 cheat loaders
    // -------------------------------------------------------------------------

    private Task CheckRegistryRunKeys(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.58, Name, "Scanning registry Run keys for TF2 cheat loaders");

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
                        ScanRunKeyForTf2Cheats(ctx, key, $@"HKCU\{keyPath}");
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
                        ScanRunKeyForTf2Cheats(ctx, key, $@"HKLM\{keyPath}");
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    private void ScanRunKeyForTf2Cheats(ScanContext ctx, RegistryKey key, string displayPath)
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
                    Title = $"TF2 Cheat Loader in Registry Run Key: {valueName}",
                    Risk = RiskLevel.Critical,
                    Location = displayPath,
                    FileName = Path.GetFileName(valueData.Trim('"')),
                    Reason = $"A registry Run key entry '{valueName}' with value '{valueData}' contains " +
                             $"the TF2 cheat-related keyword '{kw}'. Run keys execute programs automatically " +
                             "at Windows startup. TF2 cheat loaders use this mechanism to persist across " +
                             "reboots and auto-inject into TF2 when the game launches.",
                    Detail = $"Key: {displayPath} | Value name: {valueName} | Data: {valueData} | Keyword: {kw}"
                });
                break;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Check 12: UserAssist registry for TF2 cheat EXE execution history
    // -------------------------------------------------------------------------

    private Task CheckUserAssistArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.64, Name, "Scanning UserAssist registry for TF2 cheat execution history");

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
                                Title = $"UserAssist: TF2 Cheat Program Executed — {Path.GetFileName(decoded)}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{userAssistRoot}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"Windows UserAssist records that '{decoded}' was launched via the GUI. " +
                                         $"The decoded path matches the TF2 cheat keyword '{matchedKw}'. " +
                                         "UserAssist entries include a launch counter and last-run timestamp, " +
                                         "and persist in the registry after the executable is deleted.",
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
    // Check 13: MUICache registry for TF2 cheat program names
    // -------------------------------------------------------------------------

    private Task CheckMuiCacheArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.70, Name, "Scanning MUICache registry for TF2 cheat program history");

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

                        // MUICache stores "C:\path\to\app.exe.FriendlyAppName" as value name
                        // Strip the .FriendlyAppName suffix
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
                            Title = $"MUICache: TF2 Cheat Program Previously Run — {Path.GetFileName(exePath)}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{keyPath}",
                            FileName = Path.GetFileName(exePath),
                            Reason = $"The Windows MUICache registry contains an entry for '{exePath}', " +
                                     $"which matches the TF2 cheat keyword '{matchedKw}'. MUICache records " +
                                     "the display names of programs that were executed and is populated " +
                                     "when a GUI application is first run. This entry persists after the " +
                                     "program is deleted and is a reliable execution artifact.",
                            Detail = $"Key: {keyPath} | Entry: {valueName} | Friendly name: {friendlyName ?? "(none)"}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 14: Downloads folder for TF2 cheat artifacts
    // -------------------------------------------------------------------------

    private Task CheckDownloadsFolderArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.76, Name, "Scanning Downloads folder for TF2 cheat artifacts");

            var downloadsDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            if (!Directory.Exists(downloadsDir)) return;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(downloadsDir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);
                var fnLower = fn.ToLowerInvariant();

                // Check against known cheat executables
                if (KnownCheatExecutables.Contains(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"TF2 Cheat Executable in Downloads: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"The known TF2 cheat binary '{fn}' was found in the Downloads folder. " +
                                 "Downloaded cheat tools in this directory indicate active acquisition " +
                                 "of TF2 cheating software. Even without installation, the download " +
                                 "itself is a forensic indicator of intent to cheat.",
                        Detail = $"Downloads: {downloadsDir} | File: {file}"
                    });
                    continue;
                }

                if (VacBypassArtifacts.Contains(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"TF2 VAC Bypass Tool in Downloads: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"A known VAC bypass tool '{fn}' was found in the Downloads folder. " +
                                 "This tool is designed to circumvent Valve Anti-Cheat for Team Fortress 2.",
                        Detail = $"Downloads: {downloadsDir} | File: {file}"
                    });
                    continue;
                }

                // Check archives with TF2 cheat names (common download format)
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
                            Title = $"TF2 Cheat Archive in Downloads: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"A downloaded archive '{fn}' with a TF2 cheat-related name was found " +
                                     "in the Downloads folder. Cheat tools are commonly distributed as ZIP " +
                                     "or RAR archives containing the loader, DLL, and configuration files.",
                            Detail = $"Downloads: {downloadsDir} | File: {file}"
                        });
                    }
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 15: AppData for TF2 cheat configuration persistence
    // -------------------------------------------------------------------------

    private Task CheckAppDataArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            ctx.Report(0.84, Name, "Scanning AppData for TF2 cheat configuration artifacts");

            var appDataDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow"),
            };

            // Known TF2 cheat tool AppData subfolder names
            var cheatSubFolders = new[]
            {
                "lmaobox", "LmaoBox", "catbot", "CatBot",
                "tbot", "TBot", "trixware", "Trixware",
                "supremacy", "Supremacy", "aimware_tf2", "AimwareTF2",
                "sketchware", "Sketchware", "gamesense_tf2", "GameSenseTF2",
                "opai", "OPAI", "primordial", "Primordial",
                "hvh_tf2", "HvHTF2", "tf2cheat", "TF2Cheat",
                "masterchief", "MasterChief", "animtrigger", "AnimTrigger",
                "tf2_loader", "tf2_hack", "tf2_aimbot",
                "vacbypass_tf2", "vac_bypass_tf2",
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
                        Title = $"TF2 Cheat Tool AppData Directory Found: {subFolder}",
                        Risk = RiskLevel.High,
                        Location = cheatDir,
                        FileName = subFolder,
                        Reason = $"A directory named '{subFolder}' associated with the TF2 cheat tool of the " +
                                 "same name was found in AppData. Cheat tools create these directories to " +
                                 "store persistent configuration, license data, session logs, and offset " +
                                 "caches. The directory's existence persists after the main cheat executable " +
                                 "has been deleted.",
                        Detail = $"Cheat AppData directory: {cheatDir}"
                    });

                    // Enumerate files in the cheat's AppData folder for additional artifacts
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

                        // Log and config files inside the cheat's AppData directory
                        if (ext is ".log" or ".cfg" or ".json" or ".txt" or ".ini" or ".xml")
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"TF2 Cheat Configuration/Log File: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"A configuration or log file '{fn}' was found inside the TF2 cheat " +
                                         $"tool directory '{subFolder}'. This is a forensic artifact of " +
                                         "the cheat tool having been run and configured on this system.",
                                Detail = $"Cheat folder: {cheatDir} | File: {file}"
                            });
                        }
                    }
                }

                // Also scan directly in AppData for TF2 cheat files by name
                string[] directFiles;
                try { directFiles = Directory.GetFiles(appDataDir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in directFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (!TempCheatArtifactNames.Any(a => fn.Equals(a, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"TF2 Cheat Artifact in AppData: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"A TF2 cheat-associated file '{fn}' was found directly in AppData. " +
                                 "Some TF2 cheat tools write their logs and configuration to AppData " +
                                 "root rather than a named subdirectory.",
                        Detail = $"AppData directory: {appDataDir} | File: {file}"
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
