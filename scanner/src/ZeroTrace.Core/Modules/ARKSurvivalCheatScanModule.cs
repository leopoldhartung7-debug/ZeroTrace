using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class ARKSurvivalCheatScanModule : IScanModule
{
    public string Name => "ARK Survival Cheat Deep Scan";
    public double Weight => 3.4;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] KnownCheatExeNames =
    [
        // Primary cheat executables
        "ark_cheat.exe", "ark_cheats.exe", "arkhack.exe", "ark_hack.exe",
        "ark_survival_cheats.exe", "ark_survival_hack.exe",
        "ark_external.exe", "ark_internal.exe", "ark_loader.exe",
        "ark_injector.exe", "arkinjector.exe", "ark_bypass.exe",
        // ARKTrainer and trainer variants
        "ARKTrainer.exe", "ark_trainer.exe", "arktrainer.exe",
        "ark_cheat_trainer.exe", "ark_survival_trainer.exe",
        // Aimbot
        "ark_aimbot.exe", "ark_aim.exe", "arkaimbot.exe",
        "ark_aim_v2.exe", "ark_silentaim.exe", "ark_triggerbot.exe",
        // ESP / x-ray
        "ark_esp.exe", "arkesp.exe", "ark_esp_v2.exe",
        "ark_xray.exe", "ark_wallhack.exe", "ark_wh.exe",
        "ark_player_esp.exe", "ark_dino_esp.exe", "ark_loot_esp.exe",
        "ark_radar.exe", "ark_radar_server.exe", "arkradar.exe",
        // Speed / fly hacks
        "ark_fly.exe", "ark_flymode.exe", "ark_noclip.exe",
        "ark_speed.exe", "ark_speedhack.exe", "ark_bhop.exe",
        "ark_superspeed.exe", "ark_fastmove.exe",
        // Dinosaur dupe
        "ark_dupe.exe", "arkdupe.exe", "ark_dino_dupe.exe",
        "ark_item_dupe.exe", "ark_duplication.exe", "dino_dupe_ark.exe",
        // Admin / server command injection
        "ark_admin.exe", "ark_admin_tool.exe", "ark_cmd.exe",
        "ark_console.exe", "ark_server_exploit.exe",
        "ark_admin_bypass.exe", "ark_godmode.exe",
        // Teleport
        "ark_teleport.exe", "arkteleport.exe", "ark_tp.exe",
        "ark_goto.exe", "ark_tribe_tp.exe", "ark_coord.exe",
        // BattlEye bypass for ARK (ASA uses EAC)
        "battleye_bypass_ark.exe", "be_bypass_ark.exe", "ark_be_bypass.exe",
        "eac_bypass_ark.exe", "ark_eac_bypass.exe", "ark_anticheat_bypass.exe",
        // DMA / hardware
        "ark_dma.exe", "dma_ark.exe", "ark_memory.exe", "ark_memhack.exe",
        // Spoofer
        "ark_spoofer.exe", "spoofer_ark.exe", "ark_hwid_spoof.exe",
        // Menu / misc
        "ark_menu.exe", "arkmenu.exe", "ark_mod_menu.exe",
        "ark_cheat_menu.exe", "ark_modmenu.exe",
        // Tribe exploit tools
        "ark_tribe_exploit.exe", "ark_tribe_hack.exe",
        "ark_alliance_hack.exe", "ark_pvp_cheat.exe",
        // Kibble / resource dupe
        "ark_resource_dupe.exe", "ark_kibble_dupe.exe",
        "ark_element_dupe.exe", "ark_crystal_dupe.exe",
    ];

    private static readonly string[] KnownCheatDllNames =
    [
        // ESP / x-ray DLLs
        "ark_esp.dll", "arkesp.dll", "ark_wallhack.dll", "ark_wh.dll",
        "ark_xray.dll", "ark_player_esp.dll", "ark_dino_esp.dll",
        "ark_loot_esp.dll", "ark_item_esp.dll",
        // Aimbot DLLs
        "ark_aimbot.dll", "ark_aim.dll", "ark_silentaim.dll",
        "ark_triggerbot.dll", "ark_aim_assist.dll",
        // Speed / fly DLLs
        "speed_ark.dll", "ark_speed.dll", "ark_fly.dll",
        "ark_noclip.dll", "ark_bhop.dll", "ark_speedhack.dll",
        // Duplication DLLs
        "ark_dupe.dll", "ark_duplication.dll", "dino_dupe_ark.dll",
        // General cheat DLLs
        "ark_cheat.dll", "ark_hack.dll", "ark_internal.dll",
        "ark_external.dll", "ark_loader.dll",
        // BattlEye / EAC bypass DLLs
        "ark_be_bypass.dll", "battleye_bypass_ark.dll",
        "ark_eac_bypass.dll", "eac_bypass_ark.dll",
        // Admin command DLLs
        "ark_admin.dll", "ark_console.dll", "ark_cmd.dll",
        // Teleport DLLs
        "ark_teleport.dll", "ark_tp.dll",
        // Steam API bypass
        "steam_api64_bypass_ark.dll",
        // Injector DLLs
        "ark_injector.dll", "ark_inject.dll",
    ];

    private static readonly string[] CheatConfigKeywords =
    [
        // Core cheat config entries
        "ark_aimbot", "ark_esp", "ark_wallhack", "ark_speedhack",
        "ark_fly", "ark_noclip", "ark_dupe", "ark_bypass",
        "ark_teleport", "ark_admin_cheat", "ark_godmode",
        // Aimbot settings
        "aimbot_smooth_ark", "aimbot_fov_ark", "aimbot_bone_ark",
        "silent_aim_ark", "triggerbot_ark", "aim_prediction_ark",
        // ESP settings
        "esp_boxes_ark", "esp_players_ark", "esp_dinos_ark",
        "esp_loot_ark", "esp_items_ark", "esp_structures_ark",
        "esp_tribe_ark", "esp_beacon_ark", "esp_cave_ark",
        "xray_ark", "wallhack_ark", "draw_esp_ark", "draw_fov_ark",
        // Dupe settings
        "dino_dupe_ark", "item_dupe_ark", "resource_dupe_ark",
        "stack_dupe_ark", "element_dupe_ark", "engram_dupe_ark",
        // Speed / movement
        "speed_multiplier_ark", "fly_speed_ark", "bhop_ark",
        "no_fall_damage_ark", "infinite_stamina_ark",
        // Admin / server
        "admin_command_ark", "server_inject_ark", "ark_admin_bypass",
        "spawn_dino_ark", "spawn_item_ark", "enable_cheats_ark",
        // Misc
        "no_recoil_ark", "no_spread_ark", "infinite_ammo_ark",
        "ark_radar_cfg", "dma_ark_cfg", "ark_hwid_bypass",
        // Tribe-related
        "tribe_teleport_ark", "member_tp_ark", "tribe_hack_ark",
    ];

    private static readonly string[] ArkIniCheatKeywords =
    [
        // bCheatMode — legitimate dev setting but red flag on public servers
        "bCheatMode=True", "bCheatMode = True", "bCheatMode=1",
        // Infinite stats exploits via ini overrides
        "InfiniteStats=True", "InfiniteStats = True",
        "GodMode=True", "GodMode = True",
        // Fly cheat indicators
        "EnableCheats=True", "EnableCheats = True",
        // Suspicious server-side settings that cheaters inject
        "AllowAnyoneBabyImprintCuddle=True",
        "PreventTribeAlliances=False",
        "bPassiveTameInfiniteFood=True",
        // Resource multiplier exploits
        "ResourceNoReplenishRadiusPlayers=0",
        // No-clip / fly indicators
        "bDisableStructurePlacementCollision=True",
        // Override engrams (cheat unlock all)
        "bOnlyAllowSpecifiedEngrams=False",
        "OverrideEngramEntries=",
        // Speed hack ini overrides
        "UnderwaterMaxSpeed=", "MaxFallSpeed=",
        "GroundMaxSpeed=", "SwimmingMaxSpeed=",
        // PvP speed manipulation
        "DinoCharacterFoodDrainMultiplier=0",
    ];

    private static readonly string[] EacBypassKeywords =
    [
        "eac_bypass", "easy_anticheat_bypass", "eac_loader", "eacloader",
        "eac_hook", "eac_spoofer", "eac_disable", "eac_patch",
        "eac_inject", "ark_eac_bypass", "arkeacbypass",
        "easyanticheat_bypass", "eac_kill", "eac_unload",
        "eac_disable_ark", "bypass_eac", "anti_eac",
    ];

    private static readonly string[] ArkOffsetKeywords =
    [
        "AShooterCharacter", "AShooterPlayerController",
        "UShooterCheatManager", "APrimalCharacter",
        "APrimalDinoCharacter", "APrimalStructure",
        "APrimalInventoryComponent", "UPrimalItem",
        "AShooterGameMode", "AShooterGameState",
        "GWorld", "GNames", "ULevel", "UWorld",
        "APlayerController", "AGameState",
        "m_LocalPlayer", "LocalPlayer", "LocalPlayerController",
        "PlayerArray", "ActorArray", "EntityList",
        "ViewMatrix", "WorldToScreen", "CameraManager",
        "BoneArray", "SkeletalMesh",
    ];

    private static readonly string[] RegistryRunCheatKeywords =
    [
        "ark_cheat", "ark_hack", "arkhack", "ark_loader",
        "ark_injector", "ark_bypass", "ark_trainer",
        "ark_esp", "ark_aimbot", "ark_speed", "ark_fly",
        "ark_teleport", "ark_dupe", "ark_menu", "ark_spoofer",
        "ark_survival_cheat", "ark_ascended_cheat",
        "eac_bypass_ark", "ark_eac", "ark_anticheat",
    ];

    private static readonly string[] ArkPluginCheatKeywords =
    [
        "aimbot", "wallhack", "esp_", "speedhack", "noclip",
        "godmode", "teleport", "dupe_", "bypass_", "inject_",
        "cheat_", "hack_", "admin_bypass", "no_recoil",
        "silent_aim", "triggerbot", "dino_spawn_hack",
        "item_spawn_hack", "resource_hack",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "ARK Survival Cheat Deep Scan gestartet");

        var tasks = new List<Task>
        {
            CheckKnownCheatFilesAsync(ctx, ct),
            CheckProcessesAsync(ctx, ct),
            CheckEacBypassFilesAsync(ctx, ct),
            CheckArkInstallFolderAsync(ctx, ct),
            CheckArkAppDataAsync(ctx, ct),
            CheckArkDocumentsFolderAsync(ctx, ct),
            CheckDownloadsFolderAsync(ctx, ct),
            CheckArkIniConfigsAsync(ctx, ct),
            CheckCheatConfigFilesAsync(ctx, ct),
            CheckArkPluginFolderAsync(ctx, ct),
            CheckSteamApiReplacementAsync(ctx, ct),
            CheckRegistryRunKeysAsync(ctx, ct),
            CheckUserAssistAsync(ctx, ct),
            CheckMuiCacheAsync(ctx, ct),
            CheckOffsetFilesAsync(ctx, ct),
            CheckArkSavedGamesAsync(ctx, ct),
            CheckServerLogExploitsAsync(ctx, ct),
        };

        await Task.WhenAll(tasks);
        ctx.Report(1.0, Name, "ARK Survival Cheat Deep Scan abgeschlossen");
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
                            Title = $"ARK Cheat Tool gefunden: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Bekanntes ARK-Survival-Cheat-Tool '{fn}' in '{dir}' gefunden. " +
                                     "Dieser Dateiname stimmt exakt mit einer bekannten Cheat-Executable " +
                                     "oder -DLL fuer ARK: Survival Evolved/Ascended ueberein.",
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
                        Title = $"ARK Cheat-Prozess aktiv: {pname}",
                        Risk = RiskLevel.Critical,
                        Location = procPath,
                        FileName = pname,
                        Reason = $"Bekannter ARK-Cheat-Prozess '{pname}' ist aktuell aktiv. " +
                                 "Ein laufendes Cheat-Tool kann aktiv in ARK injizieren, " +
                                 "Spielinformationen auslesen oder den Server manipulieren.",
                        Detail = $"PID: {proc.Id}"
                    });
                }

                // Check for Cheat Engine targeting ARK
                if (pname.Equals("cheatengine-x86_64.exe", StringComparison.OrdinalIgnoreCase) ||
                    pname.Equals("cheatengine-i386.exe", StringComparison.OrdinalIgnoreCase) ||
                    pname.Equals("cheatengine.exe", StringComparison.OrdinalIgnoreCase) ||
                    pname.Equals("ce.exe", StringComparison.OrdinalIgnoreCase))
                {
                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                    // Check if ARK is also running (targeting indicator)
                    bool arkRunning = processes.Any(p =>
                        p.ProcessName.Equals("ShooterGame", StringComparison.OrdinalIgnoreCase) ||
                        p.ProcessName.Equals("ArkAscended", StringComparison.OrdinalIgnoreCase));

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cheat Engine laeuft" + (arkRunning ? " waehrend ARK aktiv ist" : " (ARK-Kontext)"),
                        Risk = arkRunning ? RiskLevel.Critical : RiskLevel.High,
                        Location = procPath,
                        FileName = pname,
                        Reason = "Cheat Engine ist aktiv. Wird haeufig genutzt, um ARK-Spielvariablen " +
                                 "(Gesundheit, Resourcen, Dino-Stats, Positionen) im Speicher zu manipulieren. " +
                                 (arkRunning ? "ARK laeuft gleichzeitig — Manipulation wahrscheinlich." : ""),
                        Detail = $"PID: {proc.Id}" + (arkRunning ? " · ARK gleichzeitig aktiv" : "")
                    });
                }

                // Check for known ARK injector process names
                var procNameLower = proc.ProcessName.ToLowerInvariant();
                if ((procNameLower.Contains("inject") || procNameLower.Contains("loader")) &&
                    (procNameLower.Contains("ark") || procNameLower.Contains("shooter")))
                {
                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtiger ARK-Injector-Prozess: {pname}",
                        Risk = RiskLevel.High,
                        Location = procPath,
                        FileName = pname,
                        Reason = $"Prozess '{pname}' enthaelt 'inject'/'loader' und 'ark'/'shooter' im Namen — " +
                                 "starkes Indiz fuer einen ARK-Cheat-Loader.",
                        Detail = $"PID: {proc.Id}"
                    });
                }

                // Check for ARK-specific memory editor tools
                if (pname.Equals("artmoney.exe", StringComparison.OrdinalIgnoreCase) ||
                    pname.Equals("tsearch.exe", StringComparison.OrdinalIgnoreCase) ||
                    pname.Equals("scanmem.exe", StringComparison.OrdinalIgnoreCase) ||
                    pname.Equals("gameguardian.exe", StringComparison.OrdinalIgnoreCase))
                {
                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Speicher-Editor aktiv (ARK-Kontext): {pname}",
                        Risk = RiskLevel.High,
                        Location = procPath,
                        FileName = pname,
                        Reason = $"Speicher-Editiertool '{pname}' laeuft. Diese Programme werden genutzt, " +
                                 "um ARK-Spielwerte im Arbeitsspeicher direkt zu manipulieren.",
                        Detail = $"PID: {proc.Id}"
                    });
                }
            }
        }, ct);

    private Task CheckEacBypassFilesAsync(ScanContext ctx, CancellationToken ct) =>
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

            foreach (var dir in searchRoots)
            {
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);

                    if (EacBypassKeywords.Any(k => fn.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"EasyAntiCheat-Bypass fuer ARK: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Datei '{fn}' enthaelt EasyAntiCheat-Bypass-Schluesselbegriffe. " +
                                     "ARK: Survival Ascended verwendet EasyAntiCheat als Schutz. " +
                                     "Bypass-Tools versuchen, diesen Schutz zu umgehen.",
                            Detail = $"Gefunden in: {dir}"
                        });
                    }
                }
            }

            // Check EAC service status in registry
            try
            {
                using var eacKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat");
                if (eacKey != null)
                {
                    ctx.IncrementRegistryKeys();
                    var start = eacKey.GetValue("Start");
                    if (start is int s && s == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "EasyAntiCheat-Dienst deaktiviert (ARK)",
                            Risk = RiskLevel.High,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat",
                            FileName = "Registry",
                            Reason = "EasyAntiCheat-Dienst ist deaktiviert — ARK-Anti-Cheat-Bypass-Indikator. " +
                                     "Ein deaktivierter EAC-Dienst erlaubt das Starten von ARK ohne Anti-Cheat-Schutz.",
                            Detail = "EasyAntiCheat Start=4 (Disabled)"
                        });
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckArkInstallFolderAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var arkPaths = new List<string>
            {
                // ARK: Survival Evolved
                @"C:\Program Files (x86)\Steam\steamapps\common\ARK",
                @"C:\Program Files\Steam\steamapps\common\ARK",
                @"D:\SteamLibrary\steamapps\common\ARK",
                @"E:\SteamLibrary\steamapps\common\ARK",
                @"F:\SteamLibrary\steamapps\common\ARK",
                // ARK: Survival Ascended
                @"C:\Program Files (x86)\Steam\steamapps\common\ARK Survival Ascended",
                @"C:\Program Files\Steam\steamapps\common\ARK Survival Ascended",
                @"D:\SteamLibrary\steamapps\common\ARK Survival Ascended",
                @"E:\SteamLibrary\steamapps\common\ARK Survival Ascended",
                // Epic Games
                @"C:\Program Files\Epic Games\ARKSurvivalEvolved",
                @"C:\Program Files\Epic Games\ARKSurvivalAscended",
                // Common alternative paths
                @"C:\Games\ARK",
                @"D:\Games\ARK",
            };

            try
            {
                using var steamKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\WOW6432Node\Valve\Steam");
                var steamPath = steamKey?.GetValue("InstallPath") as string;
                if (steamPath != null)
                {
                    arkPaths.Add(Path.Combine(steamPath, "steamapps", "common", "ARK"));
                    arkPaths.Add(Path.Combine(steamPath, "steamapps", "common", "ARK Survival Ascended"));
                }
            }
            catch { }

            foreach (var arkRoot in arkPaths)
            {
                if (!Directory.Exists(arkRoot)) continue;
                ct.ThrowIfCancellationRequested();

                string[] files;
                try { files = Directory.GetFiles(arkRoot, "*", SearchOption.AllDirectories); }
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
                            Title = $"ARK Cheat im Installationsordner: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Cheat-Datei '{fn}' im ARK-Spielordner gefunden. " +
                                     "Cheats im Spielverzeichnis koennen beim Spielstart automatisch " +
                                     "geladen oder injiziert werden.",
                            Detail = $"Spiel-Pfad: {arkRoot}"
                        });
                        continue;
                    }

                    // Check for cheat DLLs
                    if (KnownCheatDllNames.Any(c => fn.Equals(c, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ARK Cheat-DLL im Spielordner: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Bekannte Cheat-DLL '{fn}' im ARK-Spielordner. " +
                                     "DLLs in diesem Ordner koennen per DLL-Hijacking automatisch geladen werden.",
                            Detail = $"Spiel-Pfad: {arkRoot}"
                        });
                        continue;
                    }

                    // Check for EAC directory tampering
                    if (file.Contains("EasyAntiCheat", StringComparison.OrdinalIgnoreCase))
                    {
                        var ext = Path.GetExtension(fn).ToLowerInvariant();
                        if (ext == ".dll" && (fn.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                              fn.Contains("patch", StringComparison.OrdinalIgnoreCase) ||
                                              fn.Contains("hook", StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"EAC-Bypass-DLL in ARK-EAC-Ordner: {fn}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fn,
                                Reason = $"Verdaechtige DLL '{fn}' im ARK-EasyAntiCheat-Verzeichnis. " +
                                         "Manipulation von EAC-Dateien ist ein bekanntes Bypass-Muster.",
                                Detail = "EasyAntiCheat-Verzeichnis-Manipulation erkannt"
                            });
                        }

                        // Unexpected EXE in EAC folder
                        if (ext == ".exe" &&
                            !fn.Equals("EasyAntiCheat_EOS.exe", StringComparison.OrdinalIgnoreCase) &&
                            !fn.Equals("EasyAntiCheat_Setup.exe", StringComparison.OrdinalIgnoreCase) &&
                            !fn.Equals("EasyAntiCheat.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Unbekannte EXE im ARK-EAC-Ordner: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Unbekannte Executable '{fn}' im ARK-EasyAntiCheat-Verzeichnis.",
                                Detail = $"Pfad: {file}"
                            });
                        }
                    }

                    // Steam API replacement check
                    if (fn.Equals("steam_api64.dll", StringComparison.OrdinalIgnoreCase) ||
                        fn.Equals("steam_api.dll", StringComparison.OrdinalIgnoreCase))
                    {
                        var parent = Path.GetDirectoryName(file) ?? string.Empty;
                        if (parent.Equals(arkRoot, StringComparison.OrdinalIgnoreCase))
                        {
                            long fileSize = 0;
                            try { fileSize = new FileInfo(file).Length; } catch { }
                            bool suspiciousSize = fileSize > 0 && fileSize < 50_000;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = suspiciousSize
                                    ? $"Verdaechtig kleine Steam-API-DLL in ARK: {fn}"
                                    : $"Steam-API-DLL im ARK-Stammordner: {fn}",
                                Risk = suspiciousSize ? RiskLevel.Critical : RiskLevel.Medium,
                                Location = file,
                                FileName = fn,
                                Reason = suspiciousSize
                                    ? $"'{fn}' in ARK-Spielordner ist ungewoehnlich klein ({fileSize / 1024} KB). " +
                                      "Stub-Replacements der Steam-API sind ein Muster fuer ARK-Cheat-Loader."
                                    : $"'{fn}' im ARK-Spielordner gefunden. Ersetzte Steam-API kann DRM umgehen.",
                                Detail = $"Groesse: {fileSize / 1024} KB, Pfad: {file}"
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckArkAppDataAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appDataRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            var arkAppDataPaths = new[]
            {
                // ARK: Survival Evolved uses "Pal" folder (UE4 legacy)
                Path.Combine(localAppData, "Pal"),
                Path.Combine(localAppData, "ShooterGame"),
                Path.Combine(localAppData, "ARK"),
                Path.Combine(localAppData, "ARKSurvival"),
                // ARK: Survival Ascended
                Path.Combine(localAppData, "ARKSurvivalAscended"),
                Path.Combine(appDataRoaming, "ARK"),
                Path.Combine(appDataRoaming, "ARKSurvival"),
            };

            foreach (var arkAppPath in arkAppDataPaths)
            {
                if (!Directory.Exists(arkAppPath)) continue;

                string[] files;
                try { files = Directory.GetFiles(arkAppPath, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(fn).ToLowerInvariant();

                    // Executables in ARK AppData folder are always suspicious
                    if (ext == ".exe" || ext == ".sys")
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Ausfuehrbare Datei in ARK-AppData: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Ausfuehrbare Datei '{fn}' in ARK-AppData-Verzeichnis. " +
                                     "ARK speichert hier keine eigenen Executables; " +
                                     "das Vorhandensein ist verdaechtig.",
                            Detail = $"Pfad: {file}"
                        });
                        continue;
                    }

                    // Known cheat DLLs
                    if (ext == ".dll" && KnownCheatDllNames.Any(c =>
                        fn.Equals(c, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Bekannte ARK-Cheat-DLL in AppData: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Bekannte ARK-Cheat-DLL '{fn}' in AppData-Verzeichnis.",
                            Detail = $"Pfad: {file}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckArkDocumentsFolderAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            var arkDocPaths = new[]
            {
                Path.Combine(documents, "ARK"),
                Path.Combine(documents, "ARK Survival Evolved"),
                Path.Combine(documents, "ARK Survival Ascended"),
                Path.Combine(documents, "ShooterGame"),
            };

            foreach (var arkDocPath in arkDocPaths)
            {
                if (!Directory.Exists(arkDocPath)) continue;

                string[] files;
                try { files = Directory.GetFiles(arkDocPath, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(fn).ToLowerInvariant();

                    if (ext == ".exe" || ext == ".dll" || ext == ".sys")
                    {
                        bool isKnownCheat =
                            KnownCheatExeNames.Any(c => fn.Equals(c, StringComparison.OrdinalIgnoreCase)) ||
                            KnownCheatDllNames.Any(c => fn.Equals(c, StringComparison.OrdinalIgnoreCase));

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = isKnownCheat
                                ? $"Bekanntes ARK-Cheat-Tool im Dokumentenordner: {fn}"
                                : $"Ausfuehrbare Datei im ARK-Dokumentenordner: {fn}",
                            Risk = isKnownCheat ? RiskLevel.Critical : RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = isKnownCheat
                                ? $"Bekanntes ARK-Cheat-Tool '{fn}' im Dokumentenordner."
                                : $"'{fn}' im ARK-Dokumentenordner — ARK speichert hier keine Executables.",
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
                        Title = $"ARK Cheat-Download: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Bekanntes ARK-Cheat-Tool '{fn}' im Downloads-Ordner. " +
                                 "Deutet auf kuerzlichen Download oder Verwendung hin.",
                        Detail = $"Downloads: {downloads}"
                    });
                    continue;
                }

                // Heuristic name check
                var fnLower = fn.ToLowerInvariant();
                if ((fnLower.Contains("ark") || fnLower.Contains("shooter")) &&
                    (fnLower.Contains("cheat") || fnLower.Contains("hack") ||
                     fnLower.Contains("aimbot") || fnLower.Contains("esp") ||
                     fnLower.Contains("bypass") || fnLower.Contains("dupe") ||
                     fnLower.Contains("trainer") || fnLower.Contains("inject") ||
                     fnLower.Contains("exploit") || fnLower.Contains("god")))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtiger ARK-Dateiname im Downloads-Ordner: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Datei '{fn}' enthaelt sowohl 'ark'/'shooter' als auch " +
                                 "einen cheat-relevanten Begriff.",
                        Detail = $"Downloads: {downloads}"
                    });
                }
            }
        }, ct);

    private Task CheckArkIniConfigsAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            // ARK stores its config in various locations
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            var configSearchPaths = new[]
            {
                Path.Combine(localAppData, "Pal", "Saved", "Config"),
                Path.Combine(localAppData, "ShooterGame", "Saved", "Config"),
                Path.Combine(localAppData, "ARK", "Saved", "Config"),
                Path.Combine(localAppData, "ARKSurvivalAscended", "Saved", "Config"),
                Path.Combine(documents, "ARK"),
                Path.Combine(documents, "ARK Survival Evolved"),
                Path.Combine(documents, "ARK Survival Ascended"),
                @"C:\Program Files (x86)\Steam\steamapps\common\ARK\ShooterGame\Saved\Config",
                @"C:\Program Files\Steam\steamapps\common\ARK\ShooterGame\Saved\Config",
                @"D:\SteamLibrary\steamapps\common\ARK\ShooterGame\Saved\Config",
            };

            var targetIniNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "GameUserSettings.ini", "Game.ini", "Engine.ini",
                "Input.ini", "Scalability.ini",
            };

            foreach (var configPath in configSearchPaths)
            {
                if (!Directory.Exists(configPath)) continue;

                string[] iniFiles;
                try { iniFiles = Directory.GetFiles(configPath, "*.ini", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var iniFile in iniFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(iniFile);

                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(iniFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    // Check for cheat-injected INI settings
                    var cheatIniHits = ArkIniCheatKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    // False positive guard: bCheatMode alone in a singleplayer config is less suspicious
                    bool onlyCheatMode = cheatIniHits.Count == 1 &&
                        cheatIniHits[0].StartsWith("bCheatMode", StringComparison.OrdinalIgnoreCase);

                    if (cheatIniHits.Count >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ARK-INI-Konfiguration mit Cheat-Einstellungen: {fn}",
                            Risk = RiskLevel.High,
                            Location = iniFile,
                            FileName = fn,
                            Reason = $"ARK-INI-Datei enthaelt {cheatIniHits.Count} verdaechtige Einstellungen. " +
                                     "Mehrere dieser Werte zusammen deuten auf eine manipulierte Konfiguration hin.",
                            Detail = "Einstellungen: " + string.Join(", ", cheatIniHits.Take(6))
                        });
                    }
                    else if (cheatIniHits.Count >= 1 && !onlyCheatMode)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ARK-INI-Datei mit verdaechtiger Einstellung: {fn}",
                            Risk = RiskLevel.Medium,
                            Location = iniFile,
                            FileName = fn,
                            Reason = $"ARK-INI-Datei enthaelt verdaechtige Einstellung: '{cheatIniHits[0]}'.",
                            Detail = $"INI-Pfad: {iniFile}"
                        });
                    }

                    // Scan for cheat config keywords even in INI files
                    var cheatCfgHits = CheatConfigKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (cheatCfgHits.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ARK-INI-Datei mit Cheat-Schluesselbegriffen: {fn}",
                            Risk = RiskLevel.High,
                            Location = iniFile,
                            FileName = fn,
                            Reason = $"ARK-INI-Datei enthaelt {cheatCfgHits.Count} Cheat-Schluesselbegriffe. " +
                                     "Diese Schluesselbegriffe sind typisch fuer Cheat-Konfigurationsdateien.",
                            Detail = "Begriffe: " + string.Join(", ", cheatCfgHits.Take(6))
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
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
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
                    if (ext != ".cfg" && ext != ".ini" && ext != ".json" &&
                        ext != ".txt" && ext != ".xml" && ext != ".conf") continue;

                    var fn = Path.GetFileName(file);
                    var fnLower = fn.ToLowerInvariant();

                    // Direct name match
                    if (fnLower.Contains("ark_cheat") || fnLower.Contains("ark_hack") ||
                        fnLower.Contains("ark_esp") || fnLower.Contains("ark_aimbot") ||
                        fnLower.Contains("arkhack") || fnLower.Contains("arkcheat"))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ARK-Cheat-Konfigurationsdatei: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Dateiname '{fn}' entspricht bekanntem ARK-Cheat-Konfigurationsmuster.",
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

                    // Only scan files with ARK context
                    if (!content.Contains("ark", StringComparison.OrdinalIgnoreCase) &&
                        !content.Contains("shooter", StringComparison.OrdinalIgnoreCase) &&
                        !fnLower.Contains("ark") && !fnLower.Contains("shooter")) continue;

                    var hits = CheatConfigKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ARK-Cheat-Konfiguration erkannt: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Datei enthaelt {hits.Count} ARK-Cheat-Konfigurationsschluesselbegriffe.",
                            Detail = "Schluesselbegriffe: " + string.Join(", ", hits.Take(8))
                        });
                    }
                    else if (hits.Count >= 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ARK-Cheat-Config-Stichwort gefunden: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Datei enthaelt ARK-Cheat-Begriff: '{hits[0]}'.",
                            Detail = $"Gefunden in: {file}"
                        });
                    }
                }
            }
        }, ct);

    private Task CheckArkPluginFolderAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var arkPaths = new[]
            {
                @"C:\Program Files (x86)\Steam\steamapps\common\ARK",
                @"C:\Program Files\Steam\steamapps\common\ARK",
                @"D:\SteamLibrary\steamapps\common\ARK",
                @"E:\SteamLibrary\steamapps\common\ARK",
                @"C:\Program Files (x86)\Steam\steamapps\common\ARK Survival Ascended",
                @"D:\SteamLibrary\steamapps\common\ARK Survival Ascended",
            };

            var pluginSubFolders = new[]
            {
                "ShooterGame\\Binaries\\Win64\\plugins",
                "ShooterGame\\Plugins",
                "Plugins",
                "plugins",
                "ShooterGame\\Content\\Mods",
                "mods",
            };

            foreach (var arkRoot in arkPaths)
            {
                if (!Directory.Exists(arkRoot)) continue;

                foreach (var pluginSub in pluginSubFolders)
                {
                    var pluginPath = Path.Combine(arkRoot, pluginSub);
                    if (!Directory.Exists(pluginPath)) continue;

                    string[] pluginFiles;
                    try { pluginFiles = Directory.GetFiles(pluginPath, "*", SearchOption.AllDirectories); }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var pluginFile in pluginFiles)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(pluginFile);
                        var fnLower = fn.ToLowerInvariant();
                        var ext = Path.GetExtension(fn).ToLowerInvariant();

                        // Known cheat DLLs in plugin folder
                        if (KnownCheatDllNames.Any(c => fn.Equals(c, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Bekannte Cheat-DLL in ARK-Plugin-Ordner: {fn}",
                                Risk = RiskLevel.Critical,
                                Location = pluginFile,
                                FileName = fn,
                                Reason = $"Bekannte ARK-Cheat-DLL '{fn}' im Plugin-Verzeichnis. " +
                                         "Cheat-DLLs als Plugins getarnt werden beim Spielstart geladen.",
                                Detail = $"Plugin-Pfad: {pluginPath}"
                            });
                            continue;
                        }

                        // Heuristic: plugin name contains cheat indicators
                        if (fnLower.Contains("cheat") || fnLower.Contains("hack") ||
                            fnLower.Contains("aimbot") || fnLower.Contains("esp") ||
                            fnLower.Contains("bypass") || fnLower.Contains("exploit") ||
                            fnLower.Contains("inject") || fnLower.Contains("dupe"))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Verdaechtiges ARK-Plugin: {fn}",
                                Risk = RiskLevel.High,
                                Location = pluginFile,
                                FileName = fn,
                                Reason = $"ARK-Plugin '{fn}' enthaelt cheat-relevante Begriffe im Namen.",
                                Detail = $"Plugin-Pfad: {pluginPath}"
                            });
                            continue;
                        }

                        // Content scan for DLLs and scripts
                        if (ext != ".dll" && ext != ".lua" && ext != ".py" &&
                            ext != ".cfg" && ext != ".ini" && ext != ".json") continue;

                        string content;
                        try
                        {
                            using var fs = new FileStream(pluginFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }

                        var contentHits = ArkPluginCheatKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (contentHits.Count >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"ARK-Plugin mit Cheat-Inhalt: {fn}",
                                Risk = RiskLevel.High,
                                Location = pluginFile,
                                FileName = fn,
                                Reason = $"ARK-Plugin enthaelt {contentHits.Count} verdaechtige Cheat-Zeichenketten.",
                                Detail = "Begriffe: " + string.Join(", ", contentHits.Take(6))
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckSteamApiReplacementAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var arkPaths = new[]
            {
                @"C:\Program Files (x86)\Steam\steamapps\common\ARK\ShooterGame\Binaries\Win64",
                @"C:\Program Files\Steam\steamapps\common\ARK\ShooterGame\Binaries\Win64",
                @"D:\SteamLibrary\steamapps\common\ARK\ShooterGame\Binaries\Win64",
                @"C:\Program Files (x86)\Steam\steamapps\common\ARK Survival Ascended\ShooterGame\Binaries\Win64",
                @"D:\SteamLibrary\steamapps\common\ARK Survival Ascended\ShooterGame\Binaries\Win64",
            };

            var apiFiles = new[] { "steam_api64.dll", "steam_api.dll", "steamclient.dll" };

            foreach (var arkBinPath in arkPaths)
            {
                if (!Directory.Exists(arkBinPath)) continue;

                foreach (var apiDll in apiFiles)
                {
                    var apiPath = Path.Combine(arkBinPath, apiDll);
                    if (!File.Exists(apiPath)) continue;
                    ct.ThrowIfCancellationRequested();

                    ctx.IncrementFiles();
                    long fileSize = 0;
                    try { fileSize = new FileInfo(apiPath).Length; } catch { }

                    bool suspiciousSize = fileSize > 0 && fileSize < 50_000;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = suspiciousSize
                            ? $"Verdaechtig kleine Steam-API-DLL in ARK: {apiDll}"
                            : $"Steam-API-DLL in ARK-Binaries: {apiDll}",
                        Risk = suspiciousSize ? RiskLevel.Critical : RiskLevel.Medium,
                        Location = apiPath,
                        FileName = apiDll,
                        Reason = suspiciousSize
                            ? $"'{apiDll}' im ARK-Binaries-Ordner ist ungewoehnlich klein ({fileSize / 1024} KB). " +
                              "Stub-Replacements der Steam-API sind ein bekanntes Cheat-Loader-Muster."
                            : $"'{apiDll}' im ARK-Binaries-Verzeichnis. Ersetzte Steam-DLLs koennen " +
                              "Cheat-Loader starten oder DRM-Pruefen umgehen.",
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
                                Title = $"ARK-Cheat-Autostart in Registry (HKCU): {valueName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKCU\{runPath}",
                                FileName = valueName,
                                Reason = $"Registry-Autostart-Eintrag '{valueName}' enthaelt ARK-Cheat-Schluesselbegriffe. " +
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
                                Title = $"ARK-Cheat-Autostart in Registry (HKLM): {valueName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{runPath}",
                                FileName = valueName,
                                Reason = $"Registry-Autostart-Eintrag '{valueName}' (HKLM) enthaelt ARK-Cheat-Schluesselbegriffe.",
                                Detail = $"Wert: {value}"
                            });
                        }
                    }
                }
                catch { }
            }

            // Check ARK-specific registry for tampering
            var arkRegKeys = new[]
            {
                @"SOFTWARE\Studio Wildcard",
                @"SOFTWARE\WOW6432Node\Studio Wildcard",
                @"SOFTWARE\ARK",
                @"SOFTWARE\WOW6432Node\ARK",
            };

            foreach (var arkKey in arkRegKeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(arkKey);
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
                                Title = $"Verdaechtiger ARK-Registry-Wert: {valueName}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{arkKey}",
                                FileName = "Registry",
                                Reason = $"Verdaechtiger Wert '{valueName}' im ARK-Registry-Schluessel.",
                                Detail = $"Schluessel: {arkKey}"
                            });
                        }
                    }
                }
                catch { }
            }

            // Check installed software for ARK cheat tools
            var uninstallPaths = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };

            foreach (var uninst in uninstallPaths)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(uninst);
                    if (key == null) continue;

                    foreach (var sub in key.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var entry = key.OpenSubKey(sub);
                            ctx.IncrementRegistryKeys();
                            var dispName = entry?.GetValue("DisplayName") as string ?? string.Empty;
                            if ((dispName.Contains("ark", StringComparison.OrdinalIgnoreCase) ||
                                 dispName.Contains("shooter", StringComparison.OrdinalIgnoreCase)) &&
                                (dispName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                 dispName.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                                 dispName.Contains("aimbot", StringComparison.OrdinalIgnoreCase) ||
                                 dispName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                 dispName.Contains("trainer", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "ARK-Cheat-Software installiert",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKLM\{uninst}\{sub}",
                                    FileName = "Registry",
                                    Reason = $"Installierte Software '{dispName}' entspricht ARK-Cheat-Muster.",
                                    Detail = $"DisplayName: {dispName}"
                                });
                            }
                        }
                        catch { }
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
                            (decodedLower.Contains("ark") || decodedLower.Contains("shooter")) &&
                            (decodedLower.Contains("cheat") || decodedLower.Contains("hack") ||
                             decodedLower.Contains("aimbot") || decodedLower.Contains("bypass") ||
                             decodedLower.Contains("esp") || decodedLower.Contains("inject") ||
                             decodedLower.Contains("trainer") || decodedLower.Contains("dupe")));

                        if (isExeHit || isKeywordHit)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"ARK-Cheat-Programmaufruf in UserAssist: {Path.GetFileName(decoded)}",
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
                            (valueNameLower.Contains("ark") || valueNameLower.Contains("shooter")) &&
                            (valueNameLower.Contains("cheat") || valueNameLower.Contains("hack") ||
                             valueNameLower.Contains("bypass") || valueNameLower.Contains("esp") ||
                             valueNameLower.Contains("aimbot") || valueNameLower.Contains("inject") ||
                             valueNameLower.Contains("dupe") || valueNameLower.Contains("trainer")));

                        if (isCheatTool || isKeywordHit)
                        {
                            var displayName = key.GetValue(valueName) as string ?? string.Empty;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"ARK-Cheat-Spur in MUICache: {Path.GetFileName(valueName)}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{muiPath}",
                                FileName = Path.GetFileName(valueName),
                                Reason = $"MUICache-Eintrag deutet auf ausgefuehrtes ARK-Cheat-Tool hin: '{valueName}'. " +
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
                    if (!fnLower.Contains("ark") && !fnLower.Contains("shooter") &&
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

                    var hits = ArkOffsetKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ARK-Speicher-Offset-Datei: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Datei enthaelt {hits.Count} ARK/UE4-Klassen-/Offset-Bezeichner. " +
                                     "Solche Dateien werden von Cheat-Entwicklern fuer ARK-Speichermanipulation verwendet.",
                            Detail = "Bezeichner: " + string.Join(", ", hits.Take(8))
                        });
                    }
                }
            }
        }, ct);

    private Task CheckArkSavedGamesAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            var savedGamePaths = new[]
            {
                Path.Combine(localAppData, "Pal", "Saved", "SaveGames"),
                Path.Combine(localAppData, "ShooterGame", "Saved", "SaveGames"),
                @"C:\Program Files (x86)\Steam\steamapps\common\ARK\ShooterGame\Saved\SavedArks",
                @"C:\Program Files\Steam\steamapps\common\ARK\ShooterGame\Saved\SavedArks",
                @"D:\SteamLibrary\steamapps\common\ARK\ShooterGame\Saved\SavedArks",
            };

            foreach (var savedPath in savedGamePaths)
            {
                if (!Directory.Exists(savedPath)) continue;

                string[] allFiles;
                try { allFiles = Directory.GetFiles(savedPath, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var file in allFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(fn).ToLowerInvariant();

                    // Executables or DLLs in saved game folder are always suspicious
                    if (ext == ".exe" || ext == ".dll" || ext == ".sys")
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Ausfuehrbare Datei in ARK-Spielstand-Ordner: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Ausfuehrbare Datei '{fn}' im ARK-Spielstand-Ordner. " +
                                     "ARK speichert hier keine Executables; " +
                                     "das Vorhandensein ist ein Indiz fuer versteckte Cheat-Tools.",
                            Detail = $"Pfad: {file}"
                        });
                        continue;
                    }

                    // Check for suspicious .ark save files with cheat names
                    if (ext == ".ark" || ext == ".arkprofile" || ext == ".arktribe")
                    {
                        var fnLower = fn.ToLowerInvariant();
                        if (fnLower.Contains("cheat") || fnLower.Contains("hack") ||
                            fnLower.Contains("dupe") || fnLower.Contains("exploit") ||
                            fnLower.Contains("god") || fnLower.Contains("admin") ||
                            fnLower.Contains("bypass"))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Verdaechtige ARK-Spielstanddatei: {fn}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = fn,
                                Reason = $"ARK-Spielstanddatei '{fn}' enthaelt verdaechtige Begriffe. " +
                                         "Manipulierte .ark-Dateien koennen geclonte Dinos, " +
                                         "verdoppelte Items oder Admin-Exploits enthalten.",
                                Detail = $"Pfad: {file}"
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckServerLogExploitsAsync(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            // ARK server logs can reveal cheat/exploit usage patterns
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            var logPaths = new[]
            {
                Path.Combine(localAppData, "Pal", "Saved", "Logs"),
                Path.Combine(localAppData, "ShooterGame", "Saved", "Logs"),
                @"C:\Program Files (x86)\Steam\steamapps\common\ARK\ShooterGame\Saved\Logs",
                @"C:\Program Files\Steam\steamapps\common\ARK\ShooterGame\Saved\Logs",
                @"D:\SteamLibrary\steamapps\common\ARK\ShooterGame\Saved\Logs",
                @"C:\ARKServer\ShooterGame\Saved\Logs",
                @"D:\ARKServer\ShooterGame\Saved\Logs",
            };

            var serverExploitKeywords = new[]
            {
                "cheat addexperience", "cheat giveitem", "cheat spawndino",
                "cheat fly", "cheat ghost", "cheat god", "cheat teleport",
                "cheat setplayerpos", "cheat infinitestats",
                "cheat givearmorset", "cheat giveweaponset",
                "forcetame", "dotame", "cheat hurtme",
                "cheat walk", "cheat slomo", "cheat summon",
                "dupe exploit", "mesh exploit", "meshing",
                "undermesh", "mesh abuse", "structure exploit",
                "tribe wipe", "foundation wipe",
                "cheat destroyall", "cheat destroywilddinos",
                "cheat killplayer", "cheat banplayer",
            };

            foreach (var logPath in logPaths)
            {
                if (!Directory.Exists(logPath)) continue;

                string[] logFiles;
                try { logFiles = Directory.GetFiles(logPath, "*.log", SearchOption.TopDirectoryOnly); }
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

                    // Count exploit signatures
                    var exploitHits = serverExploitKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (exploitHits.Count >= 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ARK-Serverlog mit Exploit-Signaturen: {Path.GetFileName(logFile)}",
                            Risk = RiskLevel.Critical,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"ARK-Serverlog enthaelt {exploitHits.Count} Exploit-/Cheat-Signaturen. " +
                                     "Admin-Befehle auf einem offiziellen Server oder " +
                                     "verdaechtige Muster koennen auf Exploitation hinweisen.",
                            Detail = "Signaturen: " + string.Join(", ", exploitHits.Take(6))
                        });
                    }
                    else if (exploitHits.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ARK-Serverlog mit Cheat-Befehlen: {Path.GetFileName(logFile)}",
                            Risk = RiskLevel.High,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"ARK-Serverlog enthaelt {exploitHits.Count} Admin-/Cheat-Befehlseintraege.",
                            Detail = "Befehle: " + string.Join(", ", exploitHits.Take(4))
                        });
                    }

                    // Specific meshing / exploit indicators
                    if (content.Contains("meshing", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("undermesh", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("mesh exploit", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ARK-Meshing-Exploit-Spur im Serverlog",
                            Risk = RiskLevel.High,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = "ARK-Serverlog enthaelt Meshing-Exploit-Begriffe. " +
                                     "Meshing ist eine bekannte ARK-Exploit-Technik, bei der Spieler " +
                                     "durch Texturen und Strukturen gelangen.",
                            Detail = $"Log: {logFile}"
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
