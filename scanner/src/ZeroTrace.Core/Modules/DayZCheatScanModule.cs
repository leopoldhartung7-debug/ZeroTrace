using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class DayZCheatScanModule : IScanModule
{
    public string Name => "DayZ Cheat Deep Scan";
    public double Weight => 3.5;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] KnownCheatExeNames =
    [
        // Primary cheat executables
        "dayz_cheat.exe", "dayz_cheats.exe", "dayz_hack.exe", "dayzhack.exe",
        "dayzcheater.exe", "dayz_internal.exe", "dayz_external.exe",
        "dayz_loader.exe", "dayz_injector.exe", "dayzinjector.exe",
        // Aimbot variants
        "dayz_aim.exe", "dayz_aimbot.exe", "dayzaimbot.exe", "dayz_aim_v2.exe",
        "dayz_silentaim.exe", "dayz_triggerbot.exe", "dayz_spinbot.exe",
        // ESP / wallhack variants
        "dayz_wh.exe", "dayz_wallhack.exe", "dayz_esp.exe", "dayzesp.exe",
        "dayz_esp_v2.exe", "dayz_player_esp.exe", "dayz_loot_esp.exe",
        "dayz_radar.exe", "dayz_radar_server.exe", "dayzradar.exe",
        // Speed / movement
        "dayz_speed.exe", "dayz_speedhack.exe", "dayz_fly.exe",
        "dayz_noclip.exe", "dayz_bhop.exe", "dayz_move.exe",
        // Teleport
        "dayz_tp.exe", "dayz_teleport.exe", "dayzteleport.exe",
        "dayz_goto.exe", "dayz_coord.exe",
        // Duplication
        "dayz_dupe.exe", "dayzdupe.exe", "dayz_item_dupe.exe",
        "dayz_duplication.exe", "item_dupe_dayz.exe",
        // BattlEye bypass
        "battleye_bypass_dayz.exe", "be_bypass_dayz.exe", "dayz_be_bypass.exe",
        "dayz_be.exe", "be_loader_dayz.exe", "dayz_bebypass.exe",
        "bebypass_dayz.exe", "bekill_dayz.exe", "be_unload_dayz.exe",
        // God mode / misc
        "dayz_godmode.exe", "dayz_nofall.exe", "dayz_infinite_stamina.exe",
        "dayz_unlimited_ammo.exe", "dayz_no_recoil.exe", "dayz_autoheal.exe",
        "dayz_kill_all.exe", "dayz_hvh.exe", "dayz_cheat_menu.exe",
        // DZSA / launcher bypass
        "dzsa_bypass.exe", "dzsa_launcher_bypass.exe", "dzsa_hack.exe",
        "dzsahack.exe", "dzsa_cheat.exe", "dayz_launcher_bypass.exe",
        // DMA / hardware cheats
        "dayz_dma.exe", "dma_dayz.exe", "dayz_memory.exe", "dayz_memhack.exe",
        // Spoofer
        "dayz_spoofer.exe", "spoofer_dayz.exe", "dayz_hwid_spoof.exe",
        // Misc trainer / menu
        "dayztrainer.exe", "dayz_trainer.exe", "dayz_menu.exe", "dayzmenu.exe",
        "dayz_mod_menu.exe", "dayz_modmenu.exe",
    ];

    private static readonly string[] KnownCheatDllNames =
    [
        // BattlEye bypass DLLs
        "dayz_be_bypass.dll", "battleye_bypass_dayz.dll", "be_bypass_dayz.dll",
        "dayz_beclient_bypass.dll", "dayz_beservice.dll", "beclient_dayz.dll",
        // Aimbot DLLs
        "dayz_aimbot.dll", "dayz_aim.dll", "dayzaimbot.dll", "dayz_aim_assist.dll",
        "dayz_silent_aim.dll", "dayz_triggerbot.dll",
        // ESP / wallhack DLLs
        "dayz_esp.dll", "dayz_wh.dll", "dayz_wallhack.dll", "dayzesp.dll",
        "dayz_player_esp.dll", "dayz_loot_esp.dll", "dayz_item_esp.dll",
        // Duplication DLLs
        "item_dupe_dayz.dll", "dayz_dupe.dll", "dayz_duplication.dll",
        // Speed / movement DLLs
        "speed_dayz.dll", "dayz_speed.dll", "dayz_speedhack.dll",
        "dayz_noclip.dll", "dayz_fly.dll", "dayz_bhop.dll",
        // Teleport DLLs
        "teleport_dayz.dll", "dayz_tp.dll", "dayz_teleport.dll",
        // General cheat DLLs
        "dayz_cheat.dll", "dayz_hack.dll", "dayz_internal.dll", "dayz_external.dll",
        // Steam API bypass
        "steam_api64_bypass_dayz.dll",
        // Injector DLLs
        "dayz_injector.dll", "dayz_inject.dll",
    ];

    private static readonly string[] CheatConfigKeywords =
    [
        "dayz_aimbot", "dayz_esp", "dayz_wallhack", "dayz_speedhack",
        "dayz_teleport", "dayz_dupe", "dayz_bypass", "dayz_noclip",
        "aimbot_smooth_dayz", "aimbot_fov_dayz", "esp_boxes_dayz",
        "esp_players_dayz", "esp_zombies_dayz", "esp_loot_dayz",
        "esp_vehicles_dayz", "loot_filter_dayz", "loot_esp_dayz",
        "player_esp_dayz", "zombie_esp_dayz", "item_esp_dayz",
        "vehicle_esp_dayz", "no_recoil_dayz", "no_spread_dayz",
        "silent_aim_dayz", "triggerbot_dayz", "spinbot_dayz",
        "bhop_dayz", "speed_multiplier_dayz", "dayz_god_mode",
        "dayz_infinite_health", "dayz_infinite_blood", "dayz_infinite_ammo",
        "dayz_infinite_stamina", "dayz_no_fall_damage", "dayz_auto_heal",
        "item_duplication_dayz", "dayz_dupe_mode", "dayz_item_copy",
        "teleport_coords_dayz", "dayz_tp_mode", "dayz_fly_mode",
        "dayz_noclip_mode", "battleye_bypass_config", "be_bypass_dayz_cfg",
        "radar_dayz", "dayz_radar_cfg", "dma_dayz_cfg",
    ];

    private static readonly string[] BattlEyeLogTamperKeywords =
    [
        "bypass", "patch", "hook", "inject", "detour", "tamper",
        "disable", "kill", "unload", "spoof", "fake", "dummy",
        "cheat detected", "cheat not detected", "bypass success",
        "be bypass", "battleye bypass", "be disabled", "anti-cheat bypassed",
        "injection successful", "hook installed", "driver loaded",
        "signature bypass", "integrity bypass",
    ];

    private static readonly string[] SuspiciousModNames =
    [
        "@cheat", "@hack", "@esp", "@aimbot", "@wallhack",
        "@bypass", "@injector", "@dupe", "@godmode", "@noclip",
        "@speedhack", "@teleport", "@cheatmod", "@hackmod",
        "@unfair", "@trainer", "@exploit",
    ];

    private static readonly string[] SteamApiBypassIndicators =
    [
        // Steam API replacement DLLs placed in DayZ folder
        "steam_api64.dll",
        "steam_api.dll",
        "steamclient.dll",
        "steamclient64.dll",
    ];

    private static readonly string[] DayZOffsetKeywords =
    [
        "DayZGame", "DayZPlayer", "PlayerBase", "DayZCreature",
        "ItemBase", "InventoryBase", "CarScript", "BaseBuildingBase",
        "ZombieBase", "AnimalBase", "SurvivorBase",
        "WorldObject", "EntityAI", "ActionBase",
        "DayZPhysics", "DayZPlayerImplement",
        "m_LocalPlayer", "g_Game", "m_pPlayer",
        "DayZWorld", "DayZServer",
    ];

    private static readonly string[] RegistryRunCheatKeywords =
    [
        "dayz_cheat", "dayz_hack", "dayzhack", "dayz_loader",
        "dayz_injector", "be_bypass_dayz", "dayz_be_bypass",
        "dzsa_bypass", "dayz_esp", "dayz_aimbot",
        "dayz_speed", "dayz_teleport", "dayz_dupe",
        "dayz_trainer", "dayz_menu", "dayz_spoofer",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "DayZ Cheat Deep Scan gestartet");

        var tasks = new List<Task>
        {
            CheckKnownCheatFilesAsync(ctx, ct),
            CheckProcessesAsync(ctx, ct),
            CheckBattlEyeBypassFilesAsync(ctx, ct),
            CheckDayZInstallFolderAsync(ctx, ct),
            CheckDayZLocalAppDataAsync(ctx, ct),
            CheckDocumentsFolderAsync(ctx, ct),
            CheckDownloadsFolderAsync(ctx, ct),
            CheckBattlEyeLogsAsync(ctx, ct),
            CheckCheatConfigFilesAsync(ctx, ct),
            CheckModFolderAsync(ctx, ct),
            CheckSteamApiReplacementAsync(ctx, ct),
            CheckRegistryRunKeysAsync(ctx, ct),
            CheckUserAssistAsync(ctx, ct),
            CheckMuiCacheAsync(ctx, ct),
            CheckOffsetFilesAsync(ctx, ct),
            CheckDzmaLauncherBypassAsync(ctx, ct),
            CheckVppProfileFilesAsync(ctx, ct),
        };

        await Task.WhenAll(tasks);
        ctx.Report(1.0, Name, "DayZ Cheat Deep Scan abgeschlossen");
    }

    private Task CheckKnownCheatFilesAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);

                    bool isExeHit = KnownCheatExeNames.Any(c =>
                        fn.Equals(c, StringComparison.OrdinalIgnoreCase));
                    bool isDllHit = !isExeHit && KnownCheatDllNames.Any(c =>
                        fn.Equals(c, StringComparison.OrdinalIgnoreCase));

                    if (isExeHit || isDllHit)
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DayZ Cheat Tool gefunden: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Bekanntes DayZ-Cheat-Tool '{fn}' in '{dir}' gefunden. " +
                                     "Dieser Dateiname stimmt exakt mit einer bekannten Cheat-Executable " +
                                     "oder -DLL fuer DayZ ueberein.",
                            Detail = $"Gefunden in: {dir}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckProcessesAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var processes = ctx.GetProcessSnapshot();
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementProcesses();
                var pname = proc.ProcessName + ".exe";

                bool isCheatExe = KnownCheatExeNames.Any(c =>
                    pname.Equals(c, StringComparison.OrdinalIgnoreCase));

                if (isCheatExe)
                {
                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"DayZ Cheat-Prozess aktiv: {pname}",
                        Risk = RiskLevel.Critical,
                        Location = procPath,
                        FileName = pname,
                        Reason = $"Bekannter DayZ-Cheat-Prozess '{pname}' ist aktuell aktiv. " +
                                 "Ein laufendes Cheat-Tool kann aktiv in DayZ injizieren oder " +
                                 "Spielinformationen abgreifen.",
                        Detail = $"PID: {proc.Id}"
                    });
                }

                // Check for Cheat Engine or memory editors targeting DayZ
                if (pname.Equals("cheatengine-x86_64.exe", StringComparison.OrdinalIgnoreCase) ||
                    pname.Equals("cheatengine-i386.exe", StringComparison.OrdinalIgnoreCase) ||
                    pname.Equals("cheatengine.exe", StringComparison.OrdinalIgnoreCase) ||
                    pname.Equals("ce.exe", StringComparison.OrdinalIgnoreCase))
                {
                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Engine laeuft (DayZ-Kontext)",
                        Risk = RiskLevel.High,
                        Location = procPath,
                        FileName = pname,
                        Reason = "Cheat Engine ist aktiv. Wird oft verwendet, um DayZ-Spielvariablen " +
                                 "(Gesundheit, Munition, Positionen) im Speicher zu manipulieren. " +
                                 "Legitime Verwendung waehrend DayZ unwahrscheinlich.",
                        Detail = $"PID: {proc.Id}"
                    });
                }

                // Check for known injector processes
                var procNameLower = proc.ProcessName.ToLowerInvariant();
                if ((procNameLower.Contains("inject") || procNameLower.Contains("loader")) &&
                    (procNameLower.Contains("dayz") || procNameLower.Contains("dz")))
                {
                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtiger DayZ-Injector-Prozess: {pname}",
                        Risk = RiskLevel.High,
                        Location = procPath,
                        FileName = pname,
                        Reason = $"Prozess '{pname}' enthaelt sowohl 'inject'/'loader' als auch " +
                                 "'dayz'/'dz' im Namen — starkes Indiz fuer einen DayZ-Cheat-Loader.",
                        Detail = $"PID: {proc.Id}"
                    });
                }
            }
        }, ct);

    private Task CheckBattlEyeBypassFilesAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var searchRoots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            };

            var bypassKeywords = new[]
            {
                "be_bypass", "battleye_bypass", "be_loader", "beloader",
                "be_hook", "be_spoofer", "be_disable", "be_patch",
                "be_inject", "dayz_be_bypass", "dayzbebypass",
                "beservice_bypass", "beclient_bypass", "battleeye_bypass",
                "battle_eye_bypass", "be_kill", "be_unload", "bebypass",
                "battleye_dayz", "dayz_battleye", "dayz_be_",
            };

            foreach (var dir in searchRoots)
            {
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file).ToLowerInvariant();

                    if (bypassKeywords.Any(k => fn.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"BattlEye-Bypass fuer DayZ: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Datei '{Path.GetFileName(file)}' enthaelt BattlEye-Bypass-Schluesselbegriffe. " +
                                     "BattlEye ist das offizielle Anti-Cheat-System von DayZ. " +
                                     "Bypass-Tools versuchen, diesen Schutz zu umgehen, um Cheats zu laden.",
                            Detail = $"Gefunden in: {dir}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckDayZInstallFolderAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var dayzPaths = new List<string>
            {
                @"C:\Program Files (x86)\Steam\steamapps\common\DayZ",
                @"C:\Program Files\Steam\steamapps\common\DayZ",
                @"D:\SteamLibrary\steamapps\common\DayZ",
                @"E:\SteamLibrary\steamapps\common\DayZ",
                @"F:\SteamLibrary\steamapps\common\DayZ",
                @"D:\Games\SteamLibrary\steamapps\common\DayZ",
                @"E:\Games\SteamLibrary\steamapps\common\DayZ",
                @"C:\Games\DayZ",
                @"D:\Games\DayZ",
            };

            try
            {
                using var steamKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\WOW6432Node\Valve\Steam");
                var steamPath = steamKey?.GetValue("InstallPath") as string;
                if (steamPath != null)
                    dayzPaths.Add(Path.Combine(steamPath, "steamapps", "common", "DayZ"));
            }
            catch { }

            try
            {
                using var steamKey = Registry.CurrentUser.OpenSubKey(
                    @"Software\Valve\Steam");
                var steamPath = steamKey?.GetValue("SteamPath") as string;
                if (steamPath != null)
                    dayzPaths.Add(Path.Combine(steamPath.Replace('/', '\\'), "steamapps", "common", "DayZ"));
            }
            catch { }

            foreach (var dayzRoot in dayzPaths)
            {
                if (!Directory.Exists(dayzRoot)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try { files = Directory.GetFiles(dayzRoot, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    // Check for cheat executables in game folder
                    if (KnownCheatExeNames.Any(c => fn.Equals(c, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DayZ Cheat im Installationsordner: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Cheat-Datei '{fn}' im DayZ-Spielordner gefunden. " +
                                     "Cheats im Spielverzeichnis koennen beim Spielstart automatisch " +
                                     "geladen oder injiziert werden.",
                            Detail = $"Spiel-Pfad: {dayzRoot}"
                        });
                        continue;
                    }

                    // Check for cheat DLLs
                    if (KnownCheatDllNames.Any(c => fn.Equals(c, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DayZ Cheat-DLL im Spielordner: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Cheat-DLL '{fn}' im DayZ-Spielordner gefunden. " +
                                     "DLLs in diesem Ordner koennen per DLL-Hijacking beim Spielstart " +
                                     "automatisch geladen werden.",
                            Detail = $"Spiel-Pfad: {dayzRoot}"
                        });
                        continue;
                    }

                    // Check BattlEye directory
                    if (file.Contains("BattlEye", StringComparison.OrdinalIgnoreCase))
                    {
                        var ext = Path.GetExtension(fn).ToLowerInvariant();
                        if (ext == ".dll" && (fn.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                              fn.Contains("patch", StringComparison.OrdinalIgnoreCase) ||
                                              fn.Contains("hook", StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"BattlEye-Bypass-DLL in DayZ: {fn}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fn,
                                Reason = $"Verdaechtige DLL '{fn}' im DayZ-BattlEye-Verzeichnis. " +
                                         "Manipulierte oder ersetzte BattlEye-Dateien sind ein " +
                                         "klassisches Bypass-Muster fuer DayZ-Cheats.",
                                Detail = "BattlEye-Verzeichnis-Manipulation erkannt"
                            });
                        }

                        // Check for unexpected executable in BattlEye folder
                        if (ext == ".exe" && !fn.Equals("BEService.exe", StringComparison.OrdinalIgnoreCase) &&
                            !fn.Equals("BEClient.exe", StringComparison.OrdinalIgnoreCase) &&
                            !fn.Equals("BELauncher.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Unerwartete EXE im BattlEye-Ordner: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Ausfuehrbare Datei '{fn}' im BattlEye-Verzeichnis von DayZ, " +
                                         "die keine bekannte BattlEye-Komponente ist. " +
                                         "Koennte ein Bypass-Tool oder ein manipuliertes Binary sein.",
                                Detail = $"Pfad: {file}"
                            });
                        }
                    }

                    // Check for Steam API replacement
                    if (fn.Equals("steam_api64.dll", StringComparison.OrdinalIgnoreCase) ||
                        fn.Equals("steam_api.dll", StringComparison.OrdinalIgnoreCase))
                    {
                        // Only flag if it's a direct replacement (not in valve/steam subfolder)
                        var parent = Path.GetDirectoryName(file) ?? string.Empty;
                        if (!parent.Contains("Steam", StringComparison.OrdinalIgnoreCase) ||
                            parent.Equals(dayzRoot, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Moegliche Steam-API-Umgehung in DayZ: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"'{fn}' im DayZ-Spielordner gefunden. " +
                                         "Eine ersetzte steam_api64.dll kann DRM-Schutz umgehen " +
                                         "und ist ein bekanntes Muster fuer DayZ-Cheat-Loader.",
                                Detail = $"Verzeichnis: {parent}"
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckDayZLocalAppDataAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var dayzLocalPath = Path.Combine(localAppData, "DayZ");

            if (!Directory.Exists(dayzLocalPath)) return;

            string[] files;
            try { files = Directory.GetFiles(dayzLocalPath, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { return; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);
                var ext = Path.GetExtension(fn).ToLowerInvariant();

                // Executables in the DayZ AppData folder are immediately suspicious
                if (ext == ".exe" || ext == ".sys")
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Ausfuehrbare Datei in DayZ-AppData: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Ausfuehrbare Datei '{fn}' in '%LOCALAPPDATA%\\DayZ' gefunden. " +
                                 "DayZ speichert hier keine eigenen Executables; " +
                                 "das Vorhandensein ist ein starkes Indiz fuer Cheat-Software.",
                        Detail = $"Pfad: {file}"
                    });
                    continue;
                }

                // Check for cheat config files
                if (ext == ".cfg" || ext == ".ini" || ext == ".json")
                {
                    var fnLower = fn.ToLowerInvariant();
                    if (CheatConfigKeywords.Any(k => fnLower.Contains(k.ToLowerInvariant())))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtige Cheat-Config in DayZ-AppData: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Konfigurationsdatei '{fn}' in '%LOCALAPPDATA%\\DayZ' " +
                                     "enthaelt einen Cheat-relevanten Dateinamen.",
                            Detail = $"Pfad: {file}"
                        });
                    }
                }

                // Check for known DLL names
                if (ext == ".dll" && KnownCheatDllNames.Any(c =>
                    fn.Equals(c, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Bekannte Cheat-DLL in DayZ-AppData: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Bekannte DayZ-Cheat-DLL '{fn}' in AppData-Verzeichnis gefunden.",
                        Detail = $"Pfad: {file}"
                    });
                }
            }
        }, ct);

    private Task CheckDocumentsFolderAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var dayzDocPaths = new[]
            {
                Path.Combine(documents, "DayZ"),
                Path.Combine(documents, "DayZ Standalone"),
            };

            foreach (var dayzDocPath in dayzDocPaths)
            {
                if (!Directory.Exists(dayzDocPath)) continue;

                string[] files;
                try { files = Directory.GetFiles(dayzDocPath, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(fn).ToLowerInvariant();

                    // Executables or DLLs in DayZ Documents folder
                    if (ext == ".exe" || ext == ".dll" || ext == ".sys")
                    {
                        bool isKnownCheat =
                            KnownCheatExeNames.Any(c => fn.Equals(c, StringComparison.OrdinalIgnoreCase)) ||
                            KnownCheatDllNames.Any(c => fn.Equals(c, StringComparison.OrdinalIgnoreCase));

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = isKnownCheat
                                ? $"Bekanntes Cheat-Tool im DayZ-Dokumentenordner: {fn}"
                                : $"Ausfuehrbare Datei im DayZ-Dokumentenordner: {fn}",
                            Risk = isKnownCheat ? RiskLevel.Critical : RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = isKnownCheat
                                ? $"Bekanntes DayZ-Cheat-Tool '{fn}' im Dokumentenordner gefunden."
                                : $"Ausfuehrbare Datei '{fn}' im DayZ-Dokumentenordner — " +
                                  "DayZ speichert hier normalerweise keine Executables.",
                            Detail = $"Pfad: {file}"
                        });
                        continue;
                    }

                    // Check for dayz_cheat_config.cfg and similar
                    if (fn.Equals("dayz_cheat_config.cfg", StringComparison.OrdinalIgnoreCase) ||
                        fn.Equals("dayz_hack_config.cfg", StringComparison.OrdinalIgnoreCase) ||
                        fn.Equals("cheat_config.cfg", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DayZ-Cheat-Konfigurationsdatei: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Bekannte Cheat-Konfigurationsdatei '{fn}' im DayZ-Dokumentenordner.",
                            Detail = $"Pfad: {file}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckDownloadsFolderAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var downloads = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            if (!Directory.Exists(downloads)) return;

            string[] files;
            try { files = Directory.GetFiles(downloads, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { return; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                bool isExeHit = KnownCheatExeNames.Any(c =>
                    fn.Equals(c, StringComparison.OrdinalIgnoreCase));
                bool isDllHit = KnownCheatDllNames.Any(c =>
                    fn.Equals(c, StringComparison.OrdinalIgnoreCase));

                if (isExeHit || isDllHit)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"DayZ Cheat-Download: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Bekanntes DayZ-Cheat-Tool '{fn}' im Downloads-Ordner gefunden. " +
                                 "Deutet auf kuerzlichen Download oder Verwendung hin.",
                        Detail = $"Downloads: {downloads}"
                    });
                    continue;
                }

                // Heuristic: DayZ + cheat/hack in filename
                var fnLower = fn.ToLowerInvariant();
                if ((fnLower.Contains("dayz") || fnLower.Contains("dz_")) &&
                    (fnLower.Contains("cheat") || fnLower.Contains("hack") ||
                     fnLower.Contains("aimbot") || fnLower.Contains("esp") ||
                     fnLower.Contains("bypass") || fnLower.Contains("dupe") ||
                     fnLower.Contains("trainer") || fnLower.Contains("inject")))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtiger DayZ-Dateiname im Downloads-Ordner: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Datei '{fn}' enthaelt sowohl 'dayz' als auch einen " +
                                 "cheat-relevanten Begriff. Koennte ein DayZ-Cheat-Tool sein.",
                        Detail = $"Downloads: {downloads}"
                    });
                }
            }
        }, ct);

    private Task CheckBattlEyeLogsAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var bePaths = new[]
            {
                Path.Combine(localAppData, "DayZ", "BattlEye"),
                @"C:\Program Files (x86)\Steam\steamapps\common\DayZ\BattlEye",
                @"C:\Program Files\Steam\steamapps\common\DayZ\BattlEye",
                @"D:\SteamLibrary\steamapps\common\DayZ\BattlEye",
                @"E:\SteamLibrary\steamapps\common\DayZ\BattlEye",
            };

            foreach (var bePath in bePaths)
            {
                if (!Directory.Exists(bePath)) continue;

                string[] logFiles;
                try { logFiles = Directory.GetFiles(bePath, "*.log", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var logFile in logFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hits = BattlEyeLogTamperKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"BattlEye-Log-Manipulation (DayZ): {Path.GetFileName(logFile)}",
                            Risk = RiskLevel.Critical,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"DayZ-BattlEye-Log enthaelt {hits.Count} verdaechtige Schluesselbegriffe " +
                                     "die auf Manipulation oder Bypass-Versuche hinweisen.",
                            Detail = "Schluesselbegriffe: " + string.Join(", ", hits.Take(6))
                        });
                    }
                    else if (hits.Count == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger Eintrag in DayZ-BattlEye-Log",
                            Risk = RiskLevel.High,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"DayZ-BattlEye-Log enthaelt verdaechtigen Begriff: '{hits[0]}'.",
                            Detail = $"Log: {logFile}"
                        });
                    }
                }

                // Check for unexpected executables in BattlEye folder
                string[] exeFiles;
                try { exeFiles = Directory.GetFiles(bePath, "*.exe", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                var legit = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                    { "BEService.exe", "BEClient.exe", "BELauncher.exe", "BEService_x64.exe" };

                foreach (var exeFile in exeFiles)
                {
                    var fn = Path.GetFileName(exeFile);
                    if (!legit.Contains(fn))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Unbekannte EXE im DayZ-BattlEye-Ordner: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = exeFile,
                            FileName = fn,
                            Reason = $"Unbekannte Executable '{fn}' im DayZ-BattlEye-Ordner. " +
                                     "Legitime BattlEye-Installationen enthalten nur BEService.exe, " +
                                     "BEClient.exe und BELauncher.exe.",
                            Detail = $"BattlEye-Pfad: {bePath}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckCheatConfigFilesAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DayZ"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "DayZ"),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext != ".cfg" && ext != ".ini" && ext != ".json" &&
                        ext != ".txt" && ext != ".xml" && ext != ".conf") continue;

                    var fn = Path.GetFileName(file);

                    // Direct config name match
                    if (fn.Equals("dayz_cheat_config.cfg", StringComparison.OrdinalIgnoreCase) ||
                        fn.Equals("cheat_config.cfg", StringComparison.OrdinalIgnoreCase) ||
                        fn.Equals("dayz_esp_config.cfg", StringComparison.OrdinalIgnoreCase) ||
                        fn.Equals("dayz_aimbot_config.cfg", StringComparison.OrdinalIgnoreCase) ||
                        fn.Equals("dayz_hack_config.cfg", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DayZ Cheat-Konfigurationsdatei: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Bekannte DayZ-Cheat-Konfigurationsdatei '{fn}' gefunden.",
                            Detail = $"Pfad: {file}"
                        });
                        continue;
                    }

                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    // Only scan files with DayZ context
                    if (!content.Contains("dayz", StringComparison.OrdinalIgnoreCase) &&
                        !fn.ToLowerInvariant().Contains("dayz")) continue;

                    var hits = CheatConfigKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DayZ Cheat-Konfiguration erkannt: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Datei enthaelt {hits.Count} DayZ-Cheat-Konfigurationsschluesselbegriffe.",
                            Detail = "Schluesselbegriffe: " + string.Join(", ", hits.Take(8))
                        });
                    }
                    else if (hits.Count >= 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DayZ Cheat-Config-Stichwort gefunden: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Datei enthaelt DayZ-Cheat-Begriff: '{hits[0]}'.",
                            Detail = $"Gefunden in: {file}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckModFolderAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var dayzPaths = new[]
            {
                @"C:\Program Files (x86)\Steam\steamapps\common\DayZ",
                @"C:\Program Files\Steam\steamapps\common\DayZ",
                @"D:\SteamLibrary\steamapps\common\DayZ",
                @"E:\SteamLibrary\steamapps\common\DayZ",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DayZ"),
            };

            foreach (var dayzRoot in dayzPaths)
            {
                if (!Directory.Exists(dayzRoot)) continue;

                // DayZ mods are in @ModName folders
                string[] modDirs;
                try { modDirs = Directory.GetDirectories(dayzRoot, "@*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var modDir in modDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    var modName = Path.GetFileName(modDir);

                    // Direct cheat mod name check
                    if (SuspiciousModNames.Any(m =>
                        modName.Equals(m, StringComparison.OrdinalIgnoreCase) ||
                        modName.StartsWith(m, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger DayZ-Mod-Ordner: {modName}",
                            Risk = RiskLevel.Critical,
                            Location = modDir,
                            FileName = modName,
                            Reason = $"Mod-Ordner '{modName}' stimmt mit bekanntem Cheat-Mod-Muster ueberein. " +
                                     "DayZ-Cheat-Mods tarnen sich oft als legitime Mods.",
                            Detail = $"Mod-Pfad: {modDir}"
                        });
                        continue;
                    }

                    // Heuristic: suspicious words in mod name
                    var modNameLower = modName.ToLowerInvariant();
                    if (modNameLower.Contains("cheat") || modNameLower.Contains("hack") ||
                        modNameLower.Contains("aimbot") || modNameLower.Contains("esp") ||
                        modNameLower.Contains("wallhack") || modNameLower.Contains("dupe") ||
                        modNameLower.Contains("bypass") || modNameLower.Contains("exploit") ||
                        modNameLower.Contains("godmod") || modNameLower.Contains("noclip") ||
                        modNameLower.Contains("teleport"))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DayZ-Mod mit verdaechtigem Namen: {modName}",
                            Risk = RiskLevel.High,
                            Location = modDir,
                            FileName = modName,
                            Reason = $"DayZ-Mod-Ordner '{modName}' enthaelt Cheat-relevante Begriffe im Namen.",
                            Detail = $"Mod-Pfad: {modDir}"
                        });
                        continue;
                    }

                    // Scan mod files for cheat DLLs
                    string[] modFiles;
                    try { modFiles = Directory.GetFiles(modDir, "*.dll", SearchOption.AllDirectories); }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var modFile in modFiles)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var mfn = Path.GetFileName(modFile);
                        if (KnownCheatDllNames.Any(c => mfn.Equals(c, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Bekannte Cheat-DLL in DayZ-Mod: {mfn}",
                                Risk = RiskLevel.Critical,
                                Location = modFile,
                                FileName = mfn,
                                Reason = $"Bekannte DayZ-Cheat-DLL '{mfn}' in Mod-Ordner '{modName}' gefunden. " +
                                         "Cheat-DLLs verstecken sich manchmal als Mod-Dateien.",
                                Detail = $"Mod: {modName}, Pfad: {modFile}"
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckSteamApiReplacementAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var dayzPaths = new[]
            {
                @"C:\Program Files (x86)\Steam\steamapps\common\DayZ",
                @"C:\Program Files\Steam\steamapps\common\DayZ",
                @"D:\SteamLibrary\steamapps\common\DayZ",
                @"E:\SteamLibrary\steamapps\common\DayZ",
            };

            foreach (var dayzRoot in dayzPaths)
            {
                if (!Directory.Exists(dayzRoot)) continue;

                foreach (var apiDll in SteamApiBypassIndicators)
                {
                    var apiPath = Path.Combine(dayzRoot, apiDll);
                    if (!File.Exists(apiPath)) continue;
                    ct.ThrowIfCancellationRequested();

                    ctx.IncrementFiles();

                    // Check file size: legitimate steam_api64.dll is typically 230-350 KB
                    long fileSize = 0;
                    try { fileSize = new FileInfo(apiPath).Length; } catch { }

                    // Check for low file size which may indicate a stub replacement
                    bool suspiciousSize = fileSize > 0 && fileSize < 50_000;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = suspiciousSize
                            ? $"Verdaechtig kleine Steam-API-DLL in DayZ: {apiDll}"
                            : $"Steam-API-DLL in DayZ-Ordner vorhanden: {apiDll}",
                        Risk = suspiciousSize ? RiskLevel.Critical : RiskLevel.Medium,
                        Location = apiPath,
                        FileName = apiDll,
                        Reason = suspiciousSize
                            ? $"'{apiDll}' in DayZ-Spielordner ist ungewoehnlich klein ({fileSize / 1024} KB). " +
                              "Stub-Replacements der Steam-API sind ein bekanntes Muster bei DayZ-Cheat-Loadern."
                            : $"'{apiDll}' im DayZ-Spielordner. " +
                              "Eine ersetzte Steam-API kann zur DRM-Umgehung oder Cheat-Injektion verwendet werden.",
                        Detail = $"Groesse: {fileSize / 1024} KB, Pfad: {apiPath}"
                    });
                }
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
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
            };

            foreach (var runPath in runKeyPaths)
            {
                // Check HKCU
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(runPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var value = key.GetValue(valueName) as string ?? string.Empty;

                        bool nameHit = RegistryRunCheatKeywords.Any(k =>
                            valueName.Contains(k, StringComparison.OrdinalIgnoreCase));
                        bool valueHit = RegistryRunCheatKeywords.Any(k =>
                            value.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (nameHit || valueHit)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"DayZ-Cheat-Autostart in Registry (HKCU): {valueName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKCU\{runPath}",
                                FileName = valueName,
                                Reason = $"Registry-Autostart-Eintrag '{valueName}' enthaelt DayZ-Cheat-Schluesselbegriffe. " +
                                         "Autostart-Eintraege werden bei jeder Windows-Anmeldung ausgefuehrt.",
                                Detail = $"Wert: {value}"
                            });
                        }
                    }
                }
                catch { }

                // Check HKLM
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(runPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var value = key.GetValue(valueName) as string ?? string.Empty;

                        bool nameHit = RegistryRunCheatKeywords.Any(k =>
                            valueName.Contains(k, StringComparison.OrdinalIgnoreCase));
                        bool valueHit = RegistryRunCheatKeywords.Any(k =>
                            value.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (nameHit || valueHit)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"DayZ-Cheat-Autostart in Registry (HKLM): {valueName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{runPath}",
                                FileName = valueName,
                                Reason = $"Registry-Autostart-Eintrag '{valueName}' (HKLM) enthaelt DayZ-Cheat-Schluesselbegriffe.",
                                Detail = $"Wert: {value}"
                            });
                        }
                    }
                }
                catch { }
            }

            // Check DayZ-specific registry keys for tampering
            var dayzRegKeys = new[]
            {
                @"SOFTWARE\Bohemia Interactive\DayZ",
                @"SOFTWARE\WOW6432Node\Bohemia Interactive\DayZ",
            };

            foreach (var dayzKey in dayzRegKeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(dayzKey);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        if (valueName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            valueName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                            valueName.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                            valueName.Contains("patch", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Verdaechtiger DayZ-Registry-Wert: {valueName}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{dayzKey}",
                                FileName = "Registry",
                                Reason = $"Verdaechtiger Wert '{valueName}' im DayZ-Registry-Schluessel.",
                                Detail = $"Schluessel: {dayzKey}"
                            });
                        }
                    }
                }
                catch { }
            }
        }, ct);

    private Task CheckUserAssistAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                using var ua = baseKey.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
                if (ua == null) return;

                foreach (var guid in ua.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    using var count = ua.OpenSubKey($@"{guid}\Count");
                    if (count == null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in count.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var decoded = Rot13Decode(valueName);
                        if (string.IsNullOrWhiteSpace(decoded)) continue;

                        var decodedLower = decoded.ToLowerInvariant();
                        bool isExeHit = KnownCheatExeNames.Any(c =>
                            decodedLower.Contains(c.ToLowerInvariant()));
                        bool isKeywordHit = !isExeHit && (
                            (decodedLower.Contains("dayz") || decodedLower.Contains("dz_")) &&
                            (decodedLower.Contains("cheat") || decodedLower.Contains("hack") ||
                             decodedLower.Contains("aimbot") || decodedLower.Contains("bypass") ||
                             decodedLower.Contains("esp") || decodedLower.Contains("inject") ||
                             decodedLower.Contains("trainer")));

                        if (isExeHit || isKeywordHit)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"DayZ-Cheat-Programmaufruf in UserAssist: {Path.GetFileName(decoded)}",
                                Risk = RiskLevel.Critical,
                                Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"UserAssist-Eintrag zeigt Ausfuehrung von '{decoded}'. " +
                                         "UserAssist protokolliert GUI-Programmstarts, auch wenn die Datei " +
                                         "inzwischen geloescht wurde.",
                                Detail = $"Dekodierter Pfad: {decoded}"
                            });
                        }
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckMuiCacheAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var muiCachePaths = new[]
            {
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                @"Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            };

            foreach (var muiPath in muiCachePaths)
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                    using var key = baseKey.OpenSubKey(muiPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var valueNameLower = valueName.ToLowerInvariant();

                        bool isCheatTool = KnownCheatExeNames.Any(c =>
                            valueNameLower.Contains(c.ToLowerInvariant().Replace(".exe", "")));
                        bool isKeywordHit = !isCheatTool && (
                            (valueNameLower.Contains("dayz") || valueNameLower.Contains("dz_")) &&
                            (valueNameLower.Contains("cheat") || valueNameLower.Contains("hack") ||
                             valueNameLower.Contains("bypass") || valueNameLower.Contains("esp") ||
                             valueNameLower.Contains("aimbot") || valueNameLower.Contains("inject")));

                        if (isCheatTool || isKeywordHit)
                        {
                            var displayName = key.GetValue(valueName) as string ?? string.Empty;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"DayZ-Cheat-Spur in MUICache: {Path.GetFileName(valueName)}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{muiPath}",
                                FileName = Path.GetFileName(valueName),
                                Reason = $"MUICache-Eintrag deutet auf ausgefuehrtes DayZ-Cheat-Tool hin: '{valueName}'. " +
                                         "MUICache protokolliert zuletzt gefundene Anwendungen.",
                                Detail = $"Name: {displayName}\nPfad: {valueName}"
                            });
                        }
                    }
                }
                catch { }
            }
        }, ct);

    private Task CheckOffsetFilesAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext != ".json" && ext != ".hpp" && ext != ".h" &&
                        ext != ".cpp" && ext != ".txt" && ext != ".ini") continue;

                    var fn = Path.GetFileName(file);
                    var fnLower = fn.ToLowerInvariant();
                    if (!fnLower.Contains("dayz") && !fnLower.Contains("dz_") &&
                        !fnLower.Contains("offset") && !fnLower.Contains("dump")) continue;

                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hits = DayZOffsetKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DayZ-Speicher-Offset-Datei: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Datei enthaelt {hits.Count} DayZ-Klassen-/Offset-Bezeichner. " +
                                     "Solche Dateien werden von Cheat-Entwicklern fuer Speichermanipulation verwendet.",
                            Detail = "Bezeichner: " + string.Join(", ", hits.Take(8))
                        });
                    }
                }
            }
        }, ct);

    private Task CheckDzmaLauncherBypassAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // DZSA Launcher bypass tools and fake DZSA installations
            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            };

            var dzsaBypassKeywords = new[]
            {
                "dzsa_bypass", "dzsa_hack", "dzsa_cheat", "dzsahack",
                "dzsa_loader", "dzsa_injector", "dayz_launcher_bypass",
                "dzsa_launcher_bypass", "fake_dzsa", "dzsa_patch",
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);

                    if (dzsaBypassKeywords.Any(k => fn.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DZSA-Launcher-Bypass-Tool: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Datei '{fn}' deutet auf ein DZSA Launcher-Bypass-Tool hin. " +
                                     "Solche Tools umgehen den offiziellen DayZ-SA-Launcher, um " +
                                     "Cheats unerkannt zu starten.",
                            Detail = $"Gefunden in: {dir}"
                        });
                    }
                }
            }

            // Check registry for DZSA bypass
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run");
                if (key != null)
                {
                    ctx.IncrementRegistryKeys();
                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var value = key.GetValue(valueName) as string ?? string.Empty;
                        if (dzsaBypassKeywords.Any(k =>
                            valueName.Contains(k, StringComparison.OrdinalIgnoreCase) ||
                            value.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"DZSA-Bypass-Autostart in Registry: {valueName}",
                                Risk = RiskLevel.Critical,
                                Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                                FileName = valueName,
                                Reason = $"Autostart-Eintrag '{valueName}' enthaelt DZSA-Launcher-Bypass-Bezeichner.",
                                Detail = $"Wert: {value}"
                            });
                        }
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckVppProfileFilesAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            // DayZ uses .VPP files for mod packing. Suspicious .VPP in profile folders
            // can indicate injected cheat content.
            var profilePaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "DayZ"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DayZ"),
            };

            foreach (var profilePath in profilePaths)
            {
                if (!Directory.Exists(profilePath)) continue;

                string[] vppFiles;
                try { vppFiles = Directory.GetFiles(profilePath, "*.vpp", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var vppFile in vppFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(vppFile);
                    var fnLower = fn.ToLowerInvariant();

                    // VPP files with cheat names are obviously suspicious
                    if (fnLower.Contains("cheat") || fnLower.Contains("hack") ||
                        fnLower.Contains("esp") || fnLower.Contains("aimbot") ||
                        fnLower.Contains("dupe") || fnLower.Contains("bypass") ||
                        fnLower.Contains("exploit") || fnLower.Contains("inject"))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtige DayZ-VPP-Datei: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = vppFile,
                            FileName = fn,
                            Reason = $"DayZ-VPP-Datei '{fn}' enthaelt cheat-relevante Begriffe. " +
                                     "VPP-Dateien sind DayZ-Mod-Archive — eine manipulierte VPP " +
                                     "kann Cheat-Code in das Spiel einschleusen.",
                            Detail = $"VPP-Pfad: {vppFile}"
                        });
                        continue;
                    }

                    // Check unexpected VPP files in profile folder (not standard mission/world VPPs)
                    string content;
                    try
                    {
                        using var fs = new FileStream(vppFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    // Scan VPP content for cheat-related strings
                    var cheatStrings = new[]
                    {
                        "aimbot", "wallhack", "esp_", "speedhack", "noclip",
                        "godmode", "teleport", "dupe_item", "bypass_be",
                        "inject_dll", "cheat_menu",
                    };

                    var contentHits = cheatStrings
                        .Where(s => content.Contains(s, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (contentHits.Count >= 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"DayZ-VPP-Datei mit Cheat-Inhalt: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = vppFile,
                            FileName = fn,
                            Reason = $"DayZ-VPP-Archiv '{fn}' enthaelt verdaechtige Zeichenketten: " +
                                     string.Join(", ", contentHits) + ". " +
                                     "Koennte injizierter Cheat-Code in einem Mod-Archiv sein.",
                            Detail = $"Gefundene Zeichenketten: {string.Join(", ", contentHits)}"
                        });
                    }
                }
            }
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
