using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class EscapeFromTarkovCheatScanModule : IScanModule
{
    public string Name => "Escape from Tarkov Cheat Detection";
    public double Weight => 4.4;
    public int ParallelGroup => 4;

    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string RoamingAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string ProgramFiles =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    private static readonly string ProgramFilesX86 =
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

    private static readonly string[] EftInstallPaths =
    {
        Path.Combine(LocalAppData, "Battlestate Games", "EscapeFromTarkov"),
        Path.Combine(LocalAppData, "Battlestate Games", "Escape from Tarkov"),
        @"C:\Battlestate Games\EFT",
        @"C:\Battlestate Games\Escape from Tarkov",
        @"C:\Games\EscapeFromTarkov",
        @"C:\Games\Escape from Tarkov",
        @"D:\Battlestate Games\EFT",
        @"D:\Games\EscapeFromTarkov",
        Path.Combine(ProgramFiles, "Battlestate Games", "EscapeFromTarkov"),
        Path.Combine(ProgramFilesX86, "Battlestate Games", "EscapeFromTarkov"),
        Path.Combine(ProgramFiles, "Steam", "steamapps", "common", "Escape from Tarkov"),
        Path.Combine(ProgramFilesX86, "Steam", "steamapps", "common", "Escape from Tarkov"),
        @"C:\Steam\steamapps\common\Escape from Tarkov",
        @"D:\Steam\steamapps\common\Escape from Tarkov",
        @"E:\Steam\steamapps\common\Escape from Tarkov",
        @"C:\SteamLibrary\steamapps\common\Escape from Tarkov",
        @"D:\SteamLibrary\steamapps\common\Escape from Tarkov",
    };

    private static readonly string[] KnownCheatExeNames =
    {
        "TarkovCheat.exe",
        "EFTCheat.exe",
        "TarkovAimbot.exe",
        "TarkovESP.exe",
        "TarkovHack.exe",
        "TarkovExternal.exe",
        "EFT_External.exe",
        "EFT-External.exe",
        "TarkovRadar.exe",
        "TarkovWallhack.exe",
        "EscapeCheat.exe",
        "EscapeHack.exe",
        "EFTLoader.exe",
        "TarkovLoader.exe",
        "EFTAimbot.exe",
        "TarkovAim.exe",
        "eft_cheat.exe",
        "eft_hack.exe",
        "eft_esp.exe",
        "eft_aimbot.exe",
        "eft_radar.exe",
        "tarkov_cheat.exe",
        "tarkov_hack.exe",
        "tarkov_esp.exe",
        "tarkov_aimbot.exe",
        "tarkov_radar.exe",
        "tarkov_wallhack.exe",
        "Hakurai.exe",
        "HakuraiExternal.exe",
        "ShouldWork.exe",
        "T-Rex-EFT.exe",
        "TRexEFT.exe",
        "EFT-Radar.exe",
        "EFTRadar.exe",
        "EFT-Aimbot.exe",
        "EFTAimAssist.exe",
        "TarkovAimAssist.exe",
        "TarkovGod.exe",
        "TarkovNoRecoil.exe",
        "TarkovSpeedHack.exe",
        "TarkovMagicBullets.exe",
        "TarkovLootESP.exe",
        "TarkovItemESP.exe",
        "TarkovPlayerESP.exe",
        "TarkovBotESP.exe",
        "EFTMenu.exe",
        "TarkovMenu.exe",
        "TarkovOverlay.exe",
        "EFTOverlay.exe",
        "EFTBypass.exe",
        "TarkovBypass.exe",
        "BattlEyeBypass.exe",
        "BEBypassEFT.exe",
        "EFT-DMA-Radar.exe",
        "EFTDMARadar.exe",
        "Tarkov-DMA.exe",
        "TarkovDMA.exe",
        "DMARadarEFT.exe",
        "eft_dma.exe",
        "tarkov_dma.exe",
        "EFT-DMA.exe",
        "RadarEFT.exe",
        "WebRadarEFT.exe",
        "EFTWebRadar.exe",
        "tarkov_loot_esp.exe",
        "tarkov_player_esp.exe",
        "tarkov_no_recoil.exe",
        "tarkov_infinite_ammo.exe",
        "tarkov_god_mode.exe",
        "tarkov_speed.exe",
        "tarkov_teleport.exe",
        "tarkov_item.exe",
        "tarkov_ruble.exe",
        "tarkov_account.exe",
        "eft_trainer.exe",
        "shoreline_cheat.exe",
        "woods_cheat.exe",
        "customs_cheat.exe",
        "streets_cheat.exe",
        "labs_cheat.exe",
        "factory_cheat.exe",
        "reserve_cheat.exe",
        "tarkov_external.exe",
        "tarkov_internal.exe",
        "tarkovesp.exe",
        "tarkovbot.exe",
        "tarkovaim.exe",
        "eft_memory.exe",
        "eft_reader.exe",
        "tarkov_memory.exe",
        "tarkov_chams.exe",
        "eft_chams.exe",
        "tarkov_spoofer.exe",
        "eft_spoofer.exe",
        "tarkov_triggerbot.exe",
        "eft_triggerbot.exe",
        "tarkov_silent.exe",
        "tarkov_silent_aim.exe",
        "eft_silent_aim.exe",
        "tarkov_nametag.exe",
        "tarkov_healthhack.exe",
        "eft_healthhack.exe",
        "tarkov_stamina.exe",
        "eft_stamina.exe",
        "tarkov_norecoil.exe",
        "eft_norecoil.exe",
        "tarkov_novibration.exe",
        "eft_novibration.exe",
        "tarkov_spread.exe",
        "tarkov_fov.exe",
        "tarkov_brightness.exe",
        "eft_brightness.exe",
        "tarkov_nightvision.exe",
        "eft_nightvision.exe",
        "tarkov_thermalvision.exe",
        "tarkov_loot_filter.exe",
        "eft_loot_filter.exe",
        "tarkov_item_teleport.exe",
        "eft_item_teleport.exe",
        "radar_eft.exe",
        "eft_radar_tool.exe",
        "tarkov_map_radar.exe",
    };

    private static readonly string[] KnownCheatDllNames =
    {
        "TarkovCheat.dll",
        "EFTCheat.dll",
        "TarkovHook.dll",
        "EFTHook.dll",
        "TarkovESP.dll",
        "EFTInject.dll",
        "TarkovInject.dll",
        "eft_cheat.dll",
        "tarkov_cheat.dll",
        "tarkov_hook.dll",
        "eft_hook.dll",
        "HakuraiEFT.dll",
        "TarkovInternal.dll",
        "EFTInternal.dll",
        "TarkovInjector.dll",
        "EFTInjector.dll",
        "BattlEyeBypass.dll",
        "bebypass_eft.dll",
    };

    private static readonly string[] KnownCheatProcessNames =
    {
        "TarkovCheat",
        "EFTCheat",
        "TarkovAimbot",
        "TarkovESP",
        "TarkovHack",
        "TarkovExternal",
        "EFT_External",
        "EFT-External",
        "TarkovRadar",
        "TarkovWallhack",
        "EFTLoader",
        "TarkovLoader",
        "Hakurai",
        "HakuraiExternal",
        "ShouldWork",
        "TRexEFT",
        "EFTRadar",
        "EFT-DMA-Radar",
        "TarkovDMA",
        "DMARadarEFT",
        "RadarEFT",
        "WebRadarEFT",
        "EFTWebRadar",
        "TarkovOverlay",
        "EFTOverlay",
        "TarkovMenu",
        "EFTMenu",
    };

    private static readonly string[] CheatConfigKeywords =
    {
        "aimbot_key",
        "aimbot_bone",
        "aimbot_fov",
        "aimbot_smooth",
        "aimbot_speed",
        "esp_enabled",
        "esp_distance",
        "loot_esp",
        "player_esp",
        "item_filter",
        "item_esp",
        "npc_esp",
        "scav_esp",
        "boss_esp",
        "corpse_esp",
        "container_esp",
        "exit_esp",
        "no_recoil",
        "no_sway",
        "no_spread",
        "speed_hack",
        "god_mode",
        "infinite_stamina",
        "auto_loot",
        "loot_filter",
        "magic_bullets",
        "no_visor",
        "thermal_vision",
        "night_vision_hack",
        "chams_enabled",
        "wallhack_enabled",
        "radar_enabled",
        "radar_port",
        "radar_host",
        "websocket_port",
        "triggerbot_enabled",
        "silent_aim",
        "prediction_enabled",
        "skeleton_esp",
        "health_bar",
        "distance_esp",
        "name_esp",
    };

    private static readonly string[] EftOffsetKeywords =
    {
        "GClass",
        "EFT.Player",
        "GameWorld",
        "LocalGameWorld",
        "MainPlayer",
        "PlayerOwner",
        "ObservedPlayerView",
        "ClientGameWorld",
        "TarkovApplication",
        "GamePlayerOwner",
        "BifacialTransform",
        "EFT.Interactive",
        "LootItem",
        "LootableContainer",
        "BSG.CameraEffects",
        "ProceduralWeaponAnimation",
        "FirearmController",
        "EFT.Weapon",
        "ItemFactory",
        "GUIDComponent",
        "InventoryController",
        "HealthController",
        "MovementContext",
        "Physical",
        "PlayerBody",
        "Skeleton",
        "EFT.Bot",
        "BotOwner",
        "AiDataBase",
        "GameObjects.FindObjectOfType",
        "UnityEngine.Camera",
        "WorldToScreenPoint",
        "LocalPlayer",
        "AllPlayers",
    };

    private static readonly string[] LogCheatSignatures =
    {
        "aimbot initialized",
        "esp enabled",
        "cheat loaded",
        "battleye bypass",
        "be bypass",
        "injection successful",
        "hook installed",
        "tarkov cheat",
        "eft cheat",
        "hakurai",
        "t-rex eft",
        "radar connected",
        "websocket relay",
        "dma read",
        "memory read successful",
        "offset found",
        "PlayerList found",
        "GameWorld found",
        "LocalPlayer found",
        "loot esp active",
        "player esp active",
        "recoil disabled",
        "silent aim active",
        "triggerbot active",
    };

    private static readonly string[] BattleEyeBypassArtifacts =
    {
        "BEClient_x64.dll",
        "BEClient.dll",
        "BEService.exe",
        "BattlEye_stub.dll",
        "be_bypass.dll",
        "battleye_bypass.dll",
        "be_nulled.dll",
        "BEService_fake.exe",
    };

    private static readonly string[] RadarConfigFileNames =
    {
        "radar.json",
        "radar.cfg",
        "radar_config.json",
        "websocket.json",
        "relay.json",
        "eft_radar.json",
        "tarkov_radar.json",
        "radar_settings.json",
        "radar.ini",
    };

    private static readonly string[] SuspiciousScriptNames =
    {
        "relay.py",
        "radar_relay.py",
        "eft_relay.py",
        "tarkov_relay.py",
        "websocket_relay.py",
        "ws_relay.py",
        "radar_server.py",
        "eft_server.py",
        "map_relay.js",
        "radar_relay.js",
        "eft_relay.js",
        "tarkov_relay.js",
        "websocket_server.js",
        "relay.js",
    };

    private static readonly string[] ScanDirectories;

    static EscapeFromTarkovCheatScanModule()
    {
        ScanDirectories = new[]
        {
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(UserProfile, "Documents"),
            Path.GetTempPath(),
            Path.Combine(LocalAppData, "Temp"),
            RoamingAppData,
            LocalAppData,
            Path.Combine(UserProfile, "AppData"),
        };
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.02, Name, "Scanning for known EFT cheat executables...");
        await ScanForKnownCheatFilesAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.18, Name, "Scanning EFT install directories for tampering...");
        await ScanEftInstallDirectoriesAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.32, Name, "Scanning for cheat configuration files...");
        await ScanForCheatConfigFilesAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.45, Name, "Scanning for EFT offset and memory dump files...");
        await ScanForOffsetAndDumpFilesAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.55, Name, "Scanning EFT logs for cheat signatures...");
        await ScanEftLogsAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.65, Name, "Scanning for BattlEye bypass artifacts...");
        await ScanForBattleEyeBypassArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.75, Name, "Scanning for radar/DMA cheat artifacts...");
        await ScanForRadarAndDmaArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.85, Name, "Scanning running processes...");
        ScanRunningProcesses(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.93, Name, "Scanning registry for EFT-related cheat entries...");
        ScanRegistry(ctx, ct);

        ctx.Report(1.0, Name, "EFT cheat scan complete.");
    }

    private async Task ScanForKnownCheatFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in ScanDirectories)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            await ScanDirectoryForCheatFilesAsync(ctx, ct, dir, recursive: false).ConfigureAwait(false);

            string[] subdirs;
            try
            {
                subdirs = Directory.GetDirectories(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var sub in subdirs)
            {
                ct.ThrowIfCancellationRequested();
                await ScanDirectoryForCheatFilesAsync(ctx, ct, sub, recursive: false).ConfigureAwait(false);
            }

            await Task.Yield();
        }
    }

    private async Task ScanDirectoryForCheatFilesAsync(ScanContext ctx, CancellationToken ct, string dir, bool recursive)
    {
        string[] files;
        try
        {
            var option = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            files = Directory.GetFiles(dir, "*.*", option);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);

            foreach (var cheatExe in KnownCheatExeNames)
            {
                if (!fileName.Equals(cheatExe, StringComparison.OrdinalIgnoreCase)) continue;

                long fileSize = 0;
                try { fileSize = new FileInfo(file).Length; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Known EFT cheat executable found: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' matches the name of a known Escape from Tarkov " +
                             "cheat application. This file should not be present on the system of " +
                             "a legitimate player.",
                    Detail = $"Directory: {dir} | File size: {fileSize} bytes"
                });
                break;
            }

            foreach (var cheatDll in KnownCheatDllNames)
            {
                if (!fileName.Equals(cheatDll, StringComparison.OrdinalIgnoreCase)) continue;

                long fileSize = 0;
                try { fileSize = new FileInfo(file).Length; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Known EFT cheat DLL found: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' matches the name of a known Escape from Tarkov " +
                             "cheat library used for process injection or external memory reading.",
                    Detail = $"Directory: {dir} | File size: {fileSize} bytes"
                });
                break;
            }

            await Task.Yield();
        }
    }

    private async Task ScanEftInstallDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var eftPath in EftInstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(eftPath)) continue;

            await ScanEftInstallForTamperingAsync(ctx, ct, eftPath).ConfigureAwait(false);
        }
    }

    private async Task ScanEftInstallForTamperingAsync(ScanContext ctx, CancellationToken ct, string eftPath)
    {
        var battleEyeDir = Path.Combine(eftPath, "BattlEye");
        if (Directory.Exists(battleEyeDir))
        {
            await ScanBattleEyeDirForTamperingAsync(ctx, ct, battleEyeDir).ConfigureAwait(false);
        }

        string[] topFiles;
        try
        {
            topFiles = Directory.GetFiles(eftPath, "*.*", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach (var file in topFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);

            foreach (var bypassFile in BattleEyeBypassArtifacts)
            {
                if (!fileName.Equals(bypassFile, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"BattlEye bypass artifact in EFT install: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' found in the EFT install directory '{eftPath}' " +
                             "is associated with BattlEye anti-cheat bypass techniques. This file " +
                             "does not belong in the game directory and indicates tampering.",
                    Detail = $"EFT install path: {eftPath}"
                });
                break;
            }

            foreach (var cheatExe in KnownCheatExeNames)
            {
                if (!fileName.Equals(cheatExe, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat executable placed in EFT install directory: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"The known cheat tool '{fileName}' was found directly inside the EFT " +
                             $"installation directory '{eftPath}'. Placing cheats in the game folder " +
                             "can be used to ensure they launch alongside the game.",
                    Detail = $"EFT install path: {eftPath}"
                });
                break;
            }
        }

        await Task.Yield();
    }

    private async Task ScanBattleEyeDirForTamperingAsync(ScanContext ctx, CancellationToken ct, string battleEyeDir)
    {
        string[] files;
        try
        {
            files = Directory.GetFiles(battleEyeDir, "*.*", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        var expectedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "BEClient_x64.dll", "BEClient.dll", "BEService.exe",
            "BEService_x64.exe", "BattlEye.dll"
        };

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);

            if (expectedFiles.Contains(fileName))
            {
                long fileSize = 0;
                try { fileSize = new FileInfo(file).Length; } catch { }

                if (fileSize < 10 * 1024)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"BattlEye file suspiciously small in EFT directory: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The BattlEye file '{fileName}' in the EFT BattlEye directory is only " +
                                 $"{fileSize} bytes, which is far smaller than a legitimate BattlEye binary. " +
                                 "This can indicate the file was replaced with a stub to disable BattlEye " +
                                 "protection for Escape from Tarkov.",
                        Detail = $"File size: {fileSize} bytes | BattlEye dir: {battleEyeDir}"
                    });
                }
            }
            else
            {
                if (fileName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Unexpected executable in EFT BattlEye directory: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"An unexpected executable or library '{fileName}' was found inside the " +
                                 $"EFT BattlEye directory '{battleEyeDir}'. Only official BattlEye files " +
                                 "should be present in this folder. Extra files may indicate BattlEye bypass injection.",
                        Detail = $"BattlEye dir: {battleEyeDir}"
                    });
                }
            }
        }

        await Task.Yield();
    }

    private async Task ScanForCheatConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var configPatterns = new[] { "*.json", "*.cfg", "*.ini", "*.xml", "*.yaml", "*.yml" };

        foreach (var dir in ScanDirectories)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            foreach (var pattern in configPatterns)
            {
                string[] files;
                try
                {
                    files = Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    await InspectConfigFileForCheatKeywordsAsync(ctx, ct, file).ConfigureAwait(false);
                }
            }

            string[] subdirs;
            try
            {
                subdirs = Directory.GetDirectories(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var sub in subdirs)
            {
                ct.ThrowIfCancellationRequested();

                foreach (var pattern in configPatterns)
                {
                    string[] files;
                    try
                    {
                        files = Directory.GetFiles(sub, pattern, SearchOption.TopDirectoryOnly);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        continue;
                    }

                    foreach (var file in files)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();

                        await InspectConfigFileForCheatKeywordsAsync(ctx, ct, file).ConfigureAwait(false);
                    }
                }
            }

            await Task.Yield();
        }

        foreach (var eftPath in EftInstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(eftPath)) continue;

            foreach (var pattern in configPatterns)
            {
                string[] files;
                try
                {
                    files = Directory.GetFiles(eftPath, pattern, SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    await InspectConfigFileForCheatKeywordsAsync(ctx, ct, file).ConfigureAwait(false);
                }
            }

            await Task.Yield();
        }
    }

    private async Task InspectConfigFileForCheatKeywordsAsync(ScanContext ctx, CancellationToken ct, string filePath)
    {
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(content)) return;

        var matchedKeywords = new List<string>();

        foreach (var keyword in CheatConfigKeywords)
        {
            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                matchedKeywords.Add(keyword);
        }

        if (matchedKeywords.Count >= 2)
        {
            var fileName = Path.GetFileName(filePath);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"EFT cheat configuration file detected: {fileName}",
                Risk = matchedKeywords.Count >= 4 ? RiskLevel.Critical : RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"The file '{fileName}' contains {matchedKeywords.Count} keywords associated with " +
                         "Escape from Tarkov cheat configuration, including parameters for aimbot, ESP, " +
                         "loot filtering, and anti-recoil cheats.",
                Detail = $"Matched keywords ({matchedKeywords.Count}): {string.Join(", ", matchedKeywords.Take(10))}"
            });
        }
    }

    private async Task ScanForOffsetAndDumpFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var offsetFileNames = new[]
        {
            "offsets.json", "offsets.h", "offsets.hpp", "offsets.cs",
            "offsets.txt", "offsets.ini", "offsets.cfg",
            "eft_offsets.json", "tarkov_offsets.json",
            "eft_offsets.h", "tarkov_offsets.h",
            "dump.cs", "dump.h", "sdk.h", "sdk.hpp",
            "eft_sdk.h", "tarkov_sdk.h",
            "eft_dump.cs", "eft_dump.h",
        };

        foreach (var dir in ScanDirectories)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*offset*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                await InspectFileForEftOffsetsAsync(ctx, ct, file).ConfigureAwait(false);
            }

            foreach (var offsetFile in offsetFileNames)
            {
                var fullPath = Path.Combine(dir, offsetFile);
                if (!File.Exists(fullPath)) continue;

                ctx.IncrementFiles();
                await InspectFileForEftOffsetsAsync(ctx, ct, fullPath).ConfigureAwait(false);
            }

            string[] dumpFiles;
            try
            {
                dumpFiles = Directory.GetFiles(dir, "*dump*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                dumpFiles = Array.Empty<string>();
            }

            foreach (var file in dumpFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                await InspectFileForEftOffsetsAsync(ctx, ct, file).ConfigureAwait(false);
            }

            await Task.Yield();
        }
    }

    private async Task InspectFileForEftOffsetsAsync(ScanContext ctx, CancellationToken ct, string filePath)
    {
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(content)) return;

        var matchedOffsets = new List<string>();

        foreach (var keyword in EftOffsetKeywords)
        {
            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                matchedOffsets.Add(keyword);
        }

        if (matchedOffsets.Count >= 3)
        {
            var fileName = Path.GetFileName(filePath);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"EFT memory offset file detected: {fileName}",
                Risk = RiskLevel.Critical,
                Location = filePath,
                FileName = fileName,
                Reason = $"The file '{fileName}' contains {matchedOffsets.Count} Escape from Tarkov-specific " +
                         "memory class names and offsets used for memory reading cheats (ESP, aimbot, DMA). " +
                         "These offset files are core components of EFT external cheats and DMA radar tools.",
                Detail = $"EFT-specific identifiers found ({matchedOffsets.Count}): {string.Join(", ", matchedOffsets.Take(8))}"
            });
        }
    }

    private async Task ScanEftLogsAsync(ScanContext ctx, CancellationToken ct)
    {
        var logPaths = new List<string>();

        foreach (var eftBase in EftInstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            var logsPath = Path.Combine(eftBase, "Logs");
            if (Directory.Exists(logsPath))
                logPaths.Add(logsPath);
        }

        var bsgLogsPath = Path.Combine(LocalAppData, "Battlestate Games", "EscapeFromTarkov", "Logs");
        if (Directory.Exists(bsgLogsPath) && !logPaths.Contains(bsgLogsPath))
            logPaths.Add(bsgLogsPath);

        foreach (var logDir in logPaths)
        {
            ct.ThrowIfCancellationRequested();

            string[] logFiles;
            try
            {
                logFiles = Directory.GetFiles(logDir, "*.log", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var logFile in logFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                await InspectLogFileForCheatSignaturesAsync(ctx, ct, logFile).ConfigureAwait(false);
            }

            await Task.Yield();
        }

        var eftCrashLogPath = Path.Combine(LocalAppData, "Battlestate Games", "EscapeFromTarkov", "CrashDumps");
        if (Directory.Exists(eftCrashLogPath))
        {
            string[] crashFiles;
            try
            {
                crashFiles = Directory.GetFiles(eftCrashLogPath, "*.txt", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                crashFiles = Array.Empty<string>();
            }

            foreach (var crashFile in crashFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                await InspectLogFileForCheatSignaturesAsync(ctx, ct, crashFile).ConfigureAwait(false);
            }
        }
    }

    private async Task InspectLogFileForCheatSignaturesAsync(ScanContext ctx, CancellationToken ct, string logFile)
    {
        string content;
        try
        {
            using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(content)) return;

        var matchedSignatures = new List<string>();

        foreach (var sig in LogCheatSignatures)
        {
            if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                matchedSignatures.Add(sig);
        }

        if (matchedSignatures.Count >= 1)
        {
            var fileName = Path.GetFileName(logFile);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"EFT log file contains cheat signatures: {fileName}",
                Risk = RiskLevel.High,
                Location = logFile,
                FileName = fileName,
                Reason = $"The EFT log file '{fileName}' contains {matchedSignatures.Count} text signatures " +
                         "associated with cheat software activity, including BattlEye bypass attempts, " +
                         "injection confirmations, and ESP initialization messages.",
                Detail = $"Matched signatures ({matchedSignatures.Count}): {string.Join(", ", matchedSignatures.Take(5))}"
            });
        }
    }

    private async Task ScanForBattleEyeBypassArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in ScanDirectories)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*battleye*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);

                if (fileName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("patch", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("nulled", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("fake", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("stub", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"BattlEye bypass artifact found: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' in '{dir}' appears to be a BattlEye anti-cheat " +
                                 "bypass tool based on its filename. BattlEye is the anti-cheat system used by " +
                                 "Escape from Tarkov, and files named to suggest bypassing it are a strong " +
                                 "indicator of cheat activity.",
                        Detail = $"Directory: {dir}"
                    });
                }
            }

            string[] beFiles;
            try
            {
                beFiles = Directory.GetFiles(dir, "*be_bypass*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                beFiles = Array.Empty<string>();
            }

            foreach (var file in beFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"BattlEye bypass file detected: {Path.GetFileName(file)}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason = "A file with 'be_bypass' in its name was found, which matches the naming " +
                             "convention of BattlEye bypass libraries used by EFT cheats.",
                    Detail = $"Directory: {dir}"
                });
            }

            await Task.Yield();
        }
    }

    private async Task ScanForRadarAndDmaArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in ScanDirectories)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            foreach (var radarFile in RadarConfigFileNames)
            {
                var fullPath = Path.Combine(dir, radarFile);
                if (!File.Exists(fullPath)) continue;

                ctx.IncrementFiles();
                await InspectRadarConfigAsync(ctx, ct, fullPath).ConfigureAwait(false);
            }

            foreach (var scriptName in SuspiciousScriptNames)
            {
                var fullPath = Path.Combine(dir, scriptName);
                if (!File.Exists(fullPath)) continue;

                ctx.IncrementFiles();
                await InspectRelayScriptAsync(ctx, ct, fullPath).ConfigureAwait(false);
            }

            string[] subdirs;
            try
            {
                subdirs = Directory.GetDirectories(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var sub in subdirs)
            {
                ct.ThrowIfCancellationRequested();

                bool isDmaOrRadarDir =
                    sub.Contains("radar", StringComparison.OrdinalIgnoreCase) ||
                    sub.Contains("dma", StringComparison.OrdinalIgnoreCase) ||
                    sub.Contains("eft-dma", StringComparison.OrdinalIgnoreCase) ||
                    sub.Contains("tarkov-dma", StringComparison.OrdinalIgnoreCase) ||
                    sub.Contains("eft_radar", StringComparison.OrdinalIgnoreCase) ||
                    sub.Contains("tarkov_radar", StringComparison.OrdinalIgnoreCase);

                if (isDmaOrRadarDir)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious DMA/radar directory found: {Path.GetFileName(sub)}",
                        Risk = RiskLevel.High,
                        Location = sub,
                        Reason = $"A directory named '{Path.GetFileName(sub)}' was found under '{dir}'. " +
                                 "Directories with 'radar', 'dma', or 'tarkov-radar' in their name frequently " +
                                 "contain EFT DMA radar cheats or web-based radar relay tools.",
                        Detail = $"Parent directory: {dir}"
                    });
                }

                foreach (var radarFile in RadarConfigFileNames)
                {
                    var fullPath = Path.Combine(sub, radarFile);
                    if (!File.Exists(fullPath)) continue;

                    ctx.IncrementFiles();
                    await InspectRadarConfigAsync(ctx, ct, fullPath).ConfigureAwait(false);
                }

                foreach (var scriptName in SuspiciousScriptNames)
                {
                    var fullPath = Path.Combine(sub, scriptName);
                    if (!File.Exists(fullPath)) continue;

                    ctx.IncrementFiles();
                    await InspectRelayScriptAsync(ctx, ct, fullPath).ConfigureAwait(false);
                }
            }

            await Task.Yield();
        }
    }

    private async Task InspectRadarConfigAsync(ScanContext ctx, CancellationToken ct, string filePath)
    {
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(content)) return;

        var radarKeywords = new[]
        {
            "websocket", "radar_port", "radar_host", "relay_port", "ws_port",
            "map_data", "player_positions", "loot_positions", "eft", "tarkov",
            "GameWorld", "LocalPlayer", "AllPlayers", "LootItems",
        };

        var matched = new List<string>();
        foreach (var kw in radarKeywords)
        {
            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                matched.Add(kw);
        }

        if (matched.Count >= 2)
        {
            var fileName = Path.GetFileName(filePath);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"EFT radar cheat configuration file detected: {fileName}",
                Risk = RiskLevel.Critical,
                Location = filePath,
                FileName = fileName,
                Reason = $"The file '{fileName}' contains {matched.Count} keywords consistent with an " +
                         "EFT web-based radar cheat configuration. Radar cheats relay game data over " +
                         "WebSocket to a secondary device, allowing the player to see all enemies and loot.",
                Detail = $"Matched radar config keywords ({matched.Count}): {string.Join(", ", matched)}"
            });
        }
    }

    private async Task InspectRelayScriptAsync(ScanContext ctx, CancellationToken ct, string filePath)
    {
        string content;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(content)) return;

        var relayKeywords = new[]
        {
            "websocket", "socket", "EFT", "Tarkov", "GameWorld",
            "LocalPlayer", "AllPlayers", "loot", "relay",
            "memory", "ReadProcessMemory", "rpm", "read_process_memory",
            "player_list", "loot_list", "map", "radar",
        };

        var matched = new List<string>();
        foreach (var kw in relayKeywords)
        {
            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                matched.Add(kw);
        }

        if (matched.Count >= 3)
        {
            var fileName = Path.GetFileName(filePath);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"EFT radar relay script detected: {fileName}",
                Risk = RiskLevel.Critical,
                Location = filePath,
                FileName = fileName,
                Reason = $"The script '{fileName}' contains {matched.Count} keywords consistent with an " +
                         "EFT WebSocket radar relay script. These scripts read EFT process memory and " +
                         "broadcast game state data over a local network to a radar display on another device.",
                Detail = $"Matched relay script keywords ({matched.Count}): {string.Join(", ", matched.Take(8))}"
            });
        }
    }

    private void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        System.Diagnostics.Process[] processes;
        try
        {
            processes = System.Diagnostics.Process.GetProcesses();
        }
        catch
        {
            return;
        }

        foreach (var proc in processes)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            string procName;
            try
            {
                procName = proc.ProcessName;
            }
            catch
            {
                proc.Dispose();
                continue;
            }

            foreach (var cheatProc in KnownCheatProcessNames)
            {
                if (!procName.Equals(cheatProc, StringComparison.OrdinalIgnoreCase)) continue;

                string procPath = string.Empty;
                try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"EFT cheat process currently running: {procName}",
                    Risk = RiskLevel.Critical,
                    Location = procPath,
                    FileName = procName + ".exe",
                    Reason = $"The process '{procName}' (PID: {proc.Id}) is currently running and matches " +
                             "the name of a known Escape from Tarkov cheat tool. Active cheat processes " +
                             "indicate real-time cheat usage.",
                    Detail = $"PID: {proc.Id} | Path: {(string.IsNullOrEmpty(procPath) ? "unavailable" : procPath)}"
                });
                break;
            }

            proc.Dispose();
        }
    }

    private void ScanRegistry(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ScanRunKey(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ScanIfeoForEftBinaries(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ScanBattleEyeServiceKey(ctx);

        ct.ThrowIfCancellationRequested();
        ScanUninstallForCheatSoftware(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ScanMuiCacheForEftCheats(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ScanUserAssistForEftCheats(ctx, ct);
    }

    private static readonly string[] MuiCacheEftCheatFragments =
    {
        "tarkovcheat", "eftcheat", "tarkovhack", "efthack",
        "tarkovesp", "tarkovbot", "tarkovaim", "eftesp",
        "eftaimbot", "eftradar", "tarkovradar", "tarkovbypass",
        "eftbypass", "tarkovloader", "eftloader", "tarkovtrainer",
        "efttrainer", "tarkovexternal", "eftexternal", "tarkovinternal",
        "eftinternal", "radareft", "tarkovmemory", "eftmemory",
        "eftradar", "tarkov_cheat", "eft_cheat", "tarkov_hack",
        "eft_hack", "tarkov_esp", "eft_esp", "tarkov_aimbot",
        "eft_aimbot", "tarkov_radar", "eft_radar", "tarkov_bypass",
        "eft_bypass", "tarkov_loader", "eft_loader", "tarkov_trainer",
        "eft_trainer", "tarkov_spoofer", "eft_spoofer",
        "hakurai", "t-rex-eft", "trexeft",
    };

    private void ScanMuiCacheForEftCheats(ScanContext ctx, CancellationToken ct)
    {
        const string muiCacheKey = @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(muiCacheKey, writable: false);
            if (key is null) return;

            foreach (string valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                string vLower = valueName.ToLowerInvariant();
                foreach (string frag in MuiCacheEftCheatFragments)
                {
                    if (vLower.Contains(frag, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"EFT Cheat Tool Execution in MUICache: {Path.GetFileName(valueName)}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{muiCacheKey}",
                            FileName = Path.GetFileName(valueName),
                            Reason = $"MUICache registry entry '{valueName}' matches known EFT cheat tool name " +
                                     $"pattern '{frag}'. MUICache records friendly names of recently executed programs, " +
                                     "indicating this EFT cheat tool was previously launched on this system.",
                            Detail = $"Registry value: {valueName} | Matched fragment: {frag}"
                        });
                        break;
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    private static string Rot13Decode(string input)
    {
        var sb = new System.Text.StringBuilder(input.Length);
        foreach (char c in input)
        {
            if (c >= 'a' && c <= 'z')
                sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else if (c >= 'A' && c <= 'Z')
                sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else
                sb.Append(c);
        }
        return sb.ToString();
    }

    private void ScanUserAssistForEftCheats(ScanContext ctx, CancellationToken ct)
    {
        const string userAssistBase = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

        try
        {
            using var baseKey = Registry.CurrentUser.OpenSubKey(userAssistBase, writable: false);
            if (baseKey is null) return;

            foreach (string guidName in baseKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var countKey = baseKey.OpenSubKey(guidName + @"\Count", writable: false);
                    if (countKey is null) continue;

                    foreach (string valueName in countKey.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();

                        string decoded = Rot13Decode(valueName);
                        string decodedLower = decoded.ToLowerInvariant();

                        foreach (string frag in MuiCacheEftCheatFragments)
                        {
                            if (decodedLower.Contains(frag, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"EFT Cheat Tool in UserAssist History: {Path.GetFileName(decoded)}",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                    FileName = Path.GetFileName(decoded),
                                    Reason = $"UserAssist registry entry decodes (ROT13) to '{decoded}', matching " +
                                             $"EFT cheat tool pattern '{frag}'. UserAssist records program execution history, " +
                                             "confirming this EFT cheat tool was previously run on this user account.",
                                    Detail = $"ROT13 encoded value: {valueName} | Decoded: {decoded}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    private void ScanRunKey(ScanContext ctx, CancellationToken ct)
    {
        var runKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        foreach (var keyPath in runKeys)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath, writable: false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    var value = key.GetValue(valueName)?.ToString() ?? string.Empty;

                    foreach (var cheatExe in KnownCheatExeNames)
                    {
                        if (!value.Contains(cheatExe, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"EFT cheat registered in startup Run key: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\{keyPath}\{valueName}",
                            Reason = $"The registry autorun value '{valueName}' under '{keyPath}' references " +
                                     $"the known EFT cheat '{cheatExe}'. This causes the cheat to start " +
                                     "automatically with Windows, ensuring it is running when Tarkov launches.",
                            Detail = $"Registry value: {TruncateString(value, 200)}"
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }

        foreach (var keyPath in runKeys)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    var value = key.GetValue(valueName)?.ToString() ?? string.Empty;

                    foreach (var cheatExe in KnownCheatExeNames)
                    {
                        if (!value.Contains(cheatExe, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"EFT cheat registered in system startup Run key: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{keyPath}\{valueName}",
                            Reason = $"The registry autorun value '{valueName}' under system '{keyPath}' " +
                                     $"references the known EFT cheat '{cheatExe}'. A system-level autorun " +
                                     "entry means the cheat runs for all users at startup.",
                            Detail = $"Registry value: {TruncateString(value, 200)}"
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private void ScanIfeoForEftBinaries(ScanContext ctx, CancellationToken ct)
    {
        const string ifeoBase = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        var eftBinaries = new[]
        {
            "EscapeFromTarkov.exe",
            "BEService.exe",
            "BEClient_x64.dll",
        };

        foreach (var binary in eftBinaries)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    Path.Combine(ifeoBase, binary), writable: false);

                ctx.IncrementRegistryKeys();
                if (key is null) continue;

                var debugger = key.GetValue("Debugger")?.ToString();
                ctx.IncrementRegistryKeys();

                if (!string.IsNullOrWhiteSpace(debugger))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"IFEO debugger set for EFT binary: {binary}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{ifeoBase}\{binary}",
                        Reason = $"An Image File Execution Options debugger entry was found for '{binary}'. " +
                                 "This means when the EFT executable (or BattlEye component) starts, " +
                                 "Windows will launch the specified debugger instead, which can be used to " +
                                 "bypass BattlEye or replace the game process with a cheat loader.",
                        Detail = $"Debugger path: {debugger}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private void ScanBattleEyeServiceKey(ScanContext ctx)
    {
        const string beServiceKey = @"SYSTEM\CurrentControlSet\Services\BEService";

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(beServiceKey, writable: false);
            ctx.IncrementRegistryKeys();

            if (key is null) return;

            var startValue = key.GetValue("Start");
            ctx.IncrementRegistryKeys();

            if (startValue is int startInt && startInt == 4)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "BattlEye service (BEService) disabled in registry",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{beServiceKey}",
                    Reason = "The BattlEye service (BEService) has Start value 4 (disabled) in the registry. " +
                             "EFT relies on BattlEye; disabling the service is a common step when setting up " +
                             "cheats that require anti-cheat to be non-functional.",
                    Detail = $"Start value: {startInt} (Disabled=4)"
                });
            }

            var imagePath = key.GetValue("ImagePath")?.ToString();
            ctx.IncrementRegistryKeys();

            if (!string.IsNullOrEmpty(imagePath) &&
                !imagePath.Contains("BEService", StringComparison.OrdinalIgnoreCase) &&
                !imagePath.Contains("BattlEye", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "BattlEye service ImagePath appears tampered",
                    Risk = RiskLevel.Critical,
                    Location = $@"HKLM\{beServiceKey}",
                    Reason = "The BattlEye service ImagePath does not point to a BattlEye binary. " +
                             "This indicates the service entry was modified to either disable BattlEye " +
                             "or redirect it to a fake/stub executable.",
                    Detail = $"ImagePath: {imagePath}"
                });
            }
        }
        catch (UnauthorizedAccessException) { }
    }

    private void ScanUninstallForCheatSoftware(ScanContext ctx, CancellationToken ct)
    {
        const string uninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

        var cheatAppNames = new[]
        {
            "tarkovcheat", "eftcheat", "tarkovhack", "tarkovaimbot",
            "hakurai", "t-rex-eft", "eft-radar", "eft-dma",
            "tarkov-dma", "tarkov radar", "eft radar", "tarkov cheat",
            "escape from tarkov cheat", "tarkov esp",
        };

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(uninstallKey, writable: false);
            if (key is null) return;

            ctx.IncrementRegistryKeys();

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    using var subKey = key.OpenSubKey(subKeyName, writable: false);
                    if (subKey is null) continue;

                    ctx.IncrementRegistryKeys();

                    var displayName = subKey.GetValue("DisplayName")?.ToString() ?? string.Empty;

                    foreach (var cheatApp in cheatAppNames)
                    {
                        if (!displayName.Contains(cheatApp, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"EFT cheat software found in installed programs: {displayName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{uninstallKey}\{subKeyName}",
                            Reason = $"The installed program '{displayName}' matches the name of a known " +
                                     "Escape from Tarkov cheat application. The program was formally installed " +
                                     "on this system.",
                            Detail = $"Display name: {displayName} | Registry key: {subKeyName}"
                        });
                        break;
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }
        catch (UnauthorizedAccessException) { }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(uninstallKey, writable: false);
            if (key is null) return;

            ctx.IncrementRegistryKeys();

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();

                try
                {
                    using var subKey = key.OpenSubKey(subKeyName, writable: false);
                    if (subKey is null) continue;

                    ctx.IncrementRegistryKeys();

                    var displayName = subKey.GetValue("DisplayName")?.ToString() ?? string.Empty;

                    foreach (var cheatApp in cheatAppNames)
                    {
                        if (!displayName.Contains(cheatApp, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"EFT cheat software in user installed programs: {displayName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\{uninstallKey}\{subKeyName}",
                            Reason = $"The user-installed program '{displayName}' matches the name of a known " +
                                     "Escape from Tarkov cheat application.",
                            Detail = $"Display name: {displayName} | Registry key: {subKeyName}"
                        });
                        break;
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
    }

    private static string TruncateString(string input, int maxLength)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        return input.Length <= maxLength ? input : input[..maxLength] + "...";
    }
}
