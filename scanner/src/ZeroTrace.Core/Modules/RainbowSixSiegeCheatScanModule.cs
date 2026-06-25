using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class RainbowSixSiegeCheatScanModule : IScanModule
{
    public string Name => "Rainbow Six Siege Cheat Detection";
    public double Weight => 4.1;
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

    private static readonly string[] R6InstallPaths =
    {
        Path.Combine(ProgramFiles, "Ubisoft", "Ubisoft Game Launcher", "games", "Tom Clancy's Rainbow Six Siege"),
        Path.Combine(ProgramFiles, "Ubisoft", "Ubisoft Game Launcher", "games", "Rainbow Six Siege"),
        Path.Combine(ProgramFilesX86, "Ubisoft", "Ubisoft Game Launcher", "games", "Tom Clancy's Rainbow Six Siege"),
        Path.Combine(ProgramFilesX86, "Ubisoft", "Rainbow Six Siege"),
        Path.Combine(ProgramFiles, "Ubisoft", "Rainbow Six Siege"),
        Path.Combine(ProgramFiles, "Ubisoft Connect", "games", "Tom Clancy's Rainbow Six Siege"),
        Path.Combine(LocalAppData, "Ubisoft Game Launcher", "games", "Tom Clancy's Rainbow Six Siege"),
        @"C:\Ubisoft\Tom Clancy's Rainbow Six Siege",
        @"C:\Games\Rainbow Six Siege",
        @"D:\Ubisoft\Tom Clancy's Rainbow Six Siege",
        @"D:\Games\Rainbow Six Siege",
        Path.Combine(ProgramFiles, "Steam", "steamapps", "common", "Tom Clancy's Rainbow Six Siege"),
        Path.Combine(ProgramFilesX86, "Steam", "steamapps", "common", "Tom Clancy's Rainbow Six Siege"),
        @"C:\SteamLibrary\steamapps\common\Tom Clancy's Rainbow Six Siege",
        @"D:\SteamLibrary\steamapps\common\Tom Clancy's Rainbow Six Siege",
        @"E:\SteamLibrary\steamapps\common\Tom Clancy's Rainbow Six Siege",
    };

    private static readonly string[] KnownCheatExeNames =
    {
        "R6Cheat.exe",
        "SiegeCheat.exe",
        "R6Hack.exe",
        "RainbowCheat.exe",
        "SiegeExternal.exe",
        "R6External.exe",
        "R6Aimbot.exe",
        "SiegeAimbot.exe",
        "R6ESP.exe",
        "SiegeESP.exe",
        "R6Wallhack.exe",
        "SiegeWallhack.exe",
        "r6_wallhack.exe",
        "siege_esp.exe",
        "r6_radar.exe",
        "siege_gadget.exe",
        "r6_gadget_bypass.exe",
        "siege_speed.exe",
        "r6_speedhack.exe",
        "r6_cheat.exe",
        "siege_cheat.exe",
        "rainbow_cheat.exe",
        "r6_hack.exe",
        "siege_hack.exe",
        "r6_loader.exe",
        "siege_loader.exe",
        "R6Loader.exe",
        "SiegeLoader.exe",
        "OxideR6.exe",
        "Oxide_R6.exe",
        "GreazySiege.exe",
        "Greazy.exe",
        "HxCheats.exe",
        "Hx-Cheats.exe",
        "R6S-ESP.exe",
        "Siege-Aimbot.exe",
        "SiegeAim.exe",
        "r6_aimassist.exe",
        "siege_aimassist.exe",
        "r6_triggerbot.exe",
        "siege_triggerbot.exe",
        "r6_norecoil.exe",
        "siege_norecoil.exe",
        "r6_godmode.exe",
        "siege_godmode.exe",
        "R6Bypass.exe",
        "SiegeBypass.exe",
        "uplay_bypass.exe",
        "ubisoft_bypass.exe",
        "r6_menu.exe",
        "siege_menu.exe",
        "R6Menu.exe",
        "SiegeMenu.exe",
        "r6_overlay.exe",
        "siege_overlay.exe",
        "R6Overlay.exe",
        "SiegeOverlay.exe",
        "FairFightBypass.exe",
        "fairfight_bypass.exe",
        "r6_fairfight.exe",
        "r6sharp.exe",
        "R6Sharp.exe",
        "siege_operator_esp.exe",
        "r6_operator_hack.exe",
        "SiegeVulkanHook.exe",
        "r6_vulkan_hook.exe",
    };

    private static readonly string[] KnownCheatDllNames =
    {
        "R6Sharp.dll",
        "R6Cheat.dll",
        "SiegeCheat.dll",
        "SiegeInternal.dll",
        "R6Internal.dll",
        "R6Hook.dll",
        "SiegeHook.dll",
        "r6_cheat.dll",
        "siege_cheat.dll",
        "r6_hook.dll",
        "siege_hook.dll",
        "R6Inject.dll",
        "SiegeInject.dll",
        "r6_inject.dll",
        "siege_inject.dll",
        "ubisoft_bypass.dll",
        "uplay_r2_loader64.dll",
        "uplay_r2_loader.dll",
        "BattlEyeBypass.dll",
        "be_bypass_r6.dll",
        "r6_bypass.dll",
        "siege_bypass.dll",
        "SiegeVulkanLayer.dll",
        "r6_vulkan_layer.dll",
        "R6VulkanHook.dll",
        "dxgi_hook_r6.dll",
        "d3d11_hook_r6.dll",
        "FairFightBypass.dll",
    };

    private static readonly string[] KnownCheatProcessNames =
    {
        "R6Cheat",
        "SiegeCheat",
        "R6Hack",
        "RainbowCheat",
        "SiegeExternal",
        "R6External",
        "R6Aimbot",
        "SiegeAimbot",
        "R6ESP",
        "SiegeESP",
        "r6_cheat",
        "siege_cheat",
        "r6_hack",
        "siege_hack",
        "R6Loader",
        "SiegeLoader",
        "OxideR6",
        "Greazy",
        "HxCheats",
        "R6Sharp",
        "R6Bypass",
        "SiegeBypass",
        "uplay_bypass",
        "FairFightBypass",
        "R6Overlay",
        "SiegeOverlay",
        "R6Menu",
        "SiegeMenu",
    };

    private static readonly string[] CheatConfigKeywords =
    {
        "pick_operator",
        "auto_plant",
        "auto_defuse",
        "god_mode_siege",
        "god_mode",
        "no_recoil",
        "no_sway",
        "no_spread",
        "esp_enabled",
        "player_esp",
        "wallhack_enabled",
        "operator_esp",
        "gadget_esp",
        "drone_esp",
        "camera_esp",
        "aimbot_enabled",
        "aimbot_key",
        "aimbot_bone",
        "aimbot_fov",
        "aimbot_smooth",
        "triggerbot_enabled",
        "silent_aim",
        "prediction_enabled",
        "speed_hack",
        "speed_multiplier",
        "infinite_health",
        "no_flash",
        "no_smoke",
        "rapid_fire",
        "auto_fire",
        "drone_hack",
        "camera_hack",
        "unlimited_gadget",
        "infinite_ammo",
        "anti_flash",
        "skeleton_esp",
        "health_bar",
        "distance_esp",
        "name_esp",
        "chams_enabled",
        "r6_wallhack",
        "siege_wallhack",
        "operator_unlock",
    };

    private static readonly string[] R6OffsetKeywords =
    {
        "ACE_SDK",
        "ACE::Player",
        "ACE::Entity",
        "ACE::Pawn",
        "ACE::Camera",
        "GameBase",
        "GameManager",
        "PlayerBase",
        "LocalPlayer",
        "AllEntities",
        "EntityList",
        "Bone::Head",
        "Bone::Neck",
        "Bone::Chest",
        "WorldToScreen",
        "ViewMatrix",
        "ViewAngle",
        "Health",
        "MaxHealth",
        "Team",
        "IsAlive",
        "IsVisible",
        "Gadget",
        "Operator",
        "PlayerController",
        "CameraManager",
        "GameState",
        "MatchState",
        "Rappel",
        "SiegePlayer",
        "SiegeEngine",
        "AnvilEngine",
    };

    private static readonly string[] LogCheatSignatures =
    {
        "aimbot initialized",
        "esp enabled",
        "cheat loaded",
        "siege cheat",
        "r6 cheat",
        "battleye bypass",
        "be bypass",
        "injection successful",
        "hook installed",
        "oxide loaded",
        "greazy loaded",
        "r6sharp initialized",
        "hxcheats",
        "fairfight bypass",
        "uplay bypass",
        "wallhack enabled",
        "no recoil enabled",
        "operator esp active",
        "gadget esp active",
        "triggerbot active",
        "silent aim active",
        "speed hack enabled",
        "vulkan hook installed",
        "dxgi hook installed",
    };

    private static readonly string[] UbisoftBypassArtifacts =
    {
        "uplay_r2_loader64.dll",
        "uplay_r2_loader.dll",
        "uplay_r1_loader64.dll",
        "uplay_r1_loader.dll",
        "upc_r1_loader64.dll",
        "ubisoft_bypass.dll",
        "uplay_bypass.dll",
        "uplay_bypass.exe",
        "ubi_bypass.dll",
        "ubisoft_bypass.exe",
    };

    private static readonly string[] ScanDirectories;

    static RainbowSixSiegeCheatScanModule()
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
        };
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.02, Name, "Scanning for known R6 Siege cheat executables...");
        await ScanForKnownCheatFilesAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.18, Name, "Scanning R6 Siege install directories for tampering...");
        await ScanR6InstallDirectoriesAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.30, Name, "Scanning for Ubisoft/BattlEye bypass artifacts...");
        await ScanForAntiCheatBypassArtifactsAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.42, Name, "Scanning for cheat configuration files...");
        await ScanForCheatConfigFilesAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.55, Name, "Scanning for R6 memory offset files...");
        await ScanForOffsetFilesAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.65, Name, "Scanning R6 AppData directories...");
        await ScanR6AppDataAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.75, Name, "Scanning for Vulkan/DirectX hook DLLs...");
        await ScanForVulkanAndDxHookDllsAsync(ctx, ct).ConfigureAwait(false);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.85, Name, "Scanning running processes...");
        ScanRunningProcesses(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ctx.Report(0.93, Name, "Scanning registry for R6 cheat entries...");
        ScanRegistry(ctx, ct);

        ctx.Report(1.0, Name, "Rainbow Six Siege cheat scan complete.");
    }

    private async Task ScanForKnownCheatFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in ScanDirectories)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            await ScanDirectoryForCheatFilesAsync(ctx, ct, dir).ConfigureAwait(false);

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
                await ScanDirectoryForCheatFilesAsync(ctx, ct, sub).ConfigureAwait(false);
            }

            await Task.Yield();
        }
    }

    private async Task ScanDirectoryForCheatFilesAsync(ScanContext ctx, CancellationToken ct, string dir)
    {
        string[] files;
        try
        {
            files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly);
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
                    Title = $"Known R6 Siege cheat executable found: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' matches the name of a known Rainbow Six Siege " +
                             "cheat application. This file should not be present on the system of a " +
                             "legitimate player.",
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
                    Title = $"Known R6 Siege cheat DLL found: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' matches the name of a known Rainbow Six Siege " +
                             "cheat library used for process injection, Vulkan hooking, or DirectX hooking.",
                    Detail = $"Directory: {dir} | File size: {fileSize} bytes"
                });
                break;
            }

            foreach (var bypassDll in UbisoftBypassArtifacts)
            {
                if (!fileName.Equals(bypassDll, StringComparison.OrdinalIgnoreCase)) continue;

                long fileSize = 0;
                try { fileSize = new FileInfo(file).Length; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Ubisoft/Uplay bypass DLL found in user directory: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' in '{dir}' matches the naming convention of a " +
                             "Uplay/Ubisoft Connect bypass DLL. These DLLs are used to bypass Ubisoft's " +
                             "authentication and can also be used to evade Ubisoft's server-side anti-cheat.",
                    Detail = $"Directory: {dir} | File size: {fileSize} bytes"
                });
                break;
            }
        }

        await Task.Yield();
    }

    private async Task ScanR6InstallDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var r6Path in R6InstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(r6Path)) continue;

            await ScanR6InstallForTamperingAsync(ctx, ct, r6Path).ConfigureAwait(false);
        }
    }

    private async Task ScanR6InstallForTamperingAsync(ScanContext ctx, CancellationToken ct, string r6Path)
    {
        var battleEyeDir = Path.Combine(r6Path, "BattlEye");
        if (Directory.Exists(battleEyeDir))
        {
            await ScanR6BattleEyeDirAsync(ctx, ct, battleEyeDir).ConfigureAwait(false);
        }

        string[] topFiles;
        try
        {
            topFiles = Directory.GetFiles(r6Path, "*.dll", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        var expectedDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "RainbowSix.exe", "RainbowSix_BE.exe", "vulkan-1.dll",
            "EasyAntiCheat.dll", "steam_api64.dll", "uplay_r2_loader64.dll",
        };

        foreach (var file in topFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);

            foreach (var cheatDll in KnownCheatDllNames)
            {
                if (!fileName.Equals(cheatDll, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat DLL placed in R6 Siege install directory: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = fileName,
                    Reason = $"The known R6 cheat DLL '{fileName}' was found inside the Rainbow Six " +
                             $"Siege installation directory '{r6Path}'. DLLs placed in the game directory " +
                             "are often loaded automatically by the game executable via DLL hijacking.",
                    Detail = $"R6 install path: {r6Path}"
                });
                break;
            }

            if (fileName.Equals("uplay_r2_loader64.dll", StringComparison.OrdinalIgnoreCase) ||
                fileName.Equals("uplay_r2_loader.dll", StringComparison.OrdinalIgnoreCase))
            {
                long fileSize = 0;
                try { fileSize = new FileInfo(file).Length; } catch { }

                if (fileSize < 50 * 1024)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspiciously small uplay_r2_loader DLL in R6 directory: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' in the R6 Siege directory is only {fileSize} bytes, " +
                                 "which is far smaller than the legitimate Uplay loader DLL. A fake or stub " +
                                 "uplay_r2_loader64.dll is a common technique to bypass Ubisoft authentication " +
                                 "checks and disable anti-cheat integration.",
                        Detail = $"File size: {fileSize} bytes | R6 path: {r6Path}"
                    });
                }
            }
        }

        await Task.Yield();
    }

    private async Task ScanR6BattleEyeDirAsync(ScanContext ctx, CancellationToken ct, string battleEyeDir)
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

        var legitimateBEFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "BEClient_x64.dll", "BEClient.dll", "BEService.exe",
            "BEService_x64.exe", "BattlEye.dll", "BELauncher.exe",
        };

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);

            if (legitimateBEFiles.Contains(fileName))
            {
                long fileSize = 0;
                try { fileSize = new FileInfo(file).Length; } catch { }

                if (fileSize < 10 * 1024)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"BattlEye file suspiciously small in R6 Siege directory: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The BattlEye file '{fileName}' in R6 Siege's BattlEye directory is only " +
                                 $"{fileSize} bytes — far too small for a legitimate BattlEye binary. " +
                                 "This indicates the file may have been replaced with a stub or empty file " +
                                 "to disable BattlEye protection in Rainbow Six Siege.",
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
                        Title = $"Unexpected executable in R6 Siege BattlEye directory: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"An unexpected executable or library '{fileName}' was found inside the " +
                                 $"R6 Siege BattlEye directory '{battleEyeDir}'. This directory should only " +
                                 "contain official BattlEye files. Extra DLLs/EXEs here can be used for " +
                                 "BattlEye bypass injection when the game starts.",
                        Detail = $"BattlEye dir: {battleEyeDir}"
                    });
                }
            }
        }

        await Task.Yield();
    }

    private async Task ScanForAntiCheatBypassArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var dir in ScanDirectories)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            string[] beFiles;
            try
            {
                beFiles = Directory.GetFiles(dir, "*battleye*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in beFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);

                if (fileName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("patch", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("nulled", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("stub", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"BattlEye bypass artifact found: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' in '{dir}' appears to be a BattlEye bypass artifact. " +
                                 "BattlEye is one of two anti-cheat layers in Rainbow Six Siege. Bypassing it " +
                                 "is a prerequisite for running most R6 cheats.",
                        Detail = $"Directory: {dir}"
                    });
                }
            }

            string[] fairFightFiles;
            try
            {
                fairFightFiles = Directory.GetFiles(dir, "*fairfight*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                fairFightFiles = Array.Empty<string>();
            }

            foreach (var file in fairFightFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);

                if (fileName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("evade", StringComparison.OrdinalIgnoreCase) ||
                    fileName.Contains("spoof", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FairFight bypass artifact found: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The file '{fileName}' appears to target FairFight, Ubisoft's server-side " +
                                 "statistical anti-cheat system used in Rainbow Six Siege. FairFight evasion " +
                                 "tools are specifically designed to keep cheat behavior under FairFight's " +
                                 "statistical detection thresholds.",
                        Detail = $"Directory: {dir}"
                    });
                }
            }

            string[] ubisoftBypassFiles;
            try
            {
                ubisoftBypassFiles = Directory.GetFiles(dir, "*uplay*bypass*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                ubisoftBypassFiles = Array.Empty<string>();
            }

            foreach (var file in ubisoftBypassFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Uplay bypass artifact found: {Path.GetFileName(file)}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason = $"The file '{Path.GetFileName(file)}' in '{dir}' contains 'uplay' and 'bypass' " +
                             "in its name, matching the pattern of Uplay/Ubisoft Connect bypass tools used " +
                             "to circumvent Ubisoft's platform-level anti-cheat checks in R6 Siege.",
                    Detail = $"Directory: {dir}"
                });
            }

            await Task.Yield();
        }
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
                Title = $"R6 Siege cheat configuration file detected: {fileName}",
                Risk = matchedKeywords.Count >= 4 ? RiskLevel.Critical : RiskLevel.High,
                Location = filePath,
                FileName = fileName,
                Reason = $"The file '{fileName}' contains {matchedKeywords.Count} keywords associated with " +
                         "Rainbow Six Siege cheat configuration, including aimbot, ESP, operator hacks, " +
                         "gadget bypasses, and anti-recoil parameters.",
                Detail = $"Matched keywords ({matchedKeywords.Count}): {string.Join(", ", matchedKeywords.Take(10))}"
            });
        }
    }

    private async Task ScanForOffsetFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var offsetFilePatterns = new[] { "*offset*", "*sdk*", "*dump*" };

        foreach (var dir in ScanDirectories)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            foreach (var pattern in offsetFilePatterns)
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

                    await InspectFileForR6OffsetsAsync(ctx, ct, file).ConfigureAwait(false);
                }
            }

            await Task.Yield();
        }
    }

    private async Task InspectFileForR6OffsetsAsync(ScanContext ctx, CancellationToken ct, string filePath)
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

        var matched = new List<string>();
        foreach (var keyword in R6OffsetKeywords)
        {
            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                matched.Add(keyword);
        }

        if (matched.Count >= 3)
        {
            var fileName = Path.GetFileName(filePath);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"R6 Siege memory offset file detected: {fileName}",
                Risk = RiskLevel.Critical,
                Location = filePath,
                FileName = fileName,
                Reason = $"The file '{fileName}' contains {matched.Count} Rainbow Six Siege-specific " +
                         "memory class names and offsets used for cheat development (ESP, aimbot). " +
                         "These are produced by memory dumping tools targeting R6's ACE engine.",
                Detail = $"R6-specific identifiers ({matched.Count}): {string.Join(", ", matched.Take(8))}"
            });
        }
    }

    private async Task ScanR6AppDataAsync(ScanContext ctx, CancellationToken ct)
    {
        var r6AppDataPaths = new[]
        {
            Path.Combine(RoamingAppData, "Rainbow Six Siege"),
            Path.Combine(RoamingAppData, "Ubisoft", "Rainbow Six Siege"),
            Path.Combine(LocalAppData, "Rainbow Six Siege"),
            Path.Combine(LocalAppData, "Ubisoft", "Rainbow Six Siege"),
            Path.Combine(RoamingAppData, "R6Cheat"),
            Path.Combine(RoamingAppData, "SiegeCheat"),
            Path.Combine(RoamingAppData, "Oxide"),
            Path.Combine(RoamingAppData, "Greazy"),
            Path.Combine(RoamingAppData, "HxCheats"),
            Path.Combine(RoamingAppData, "R6Sharp"),
            Path.Combine(LocalAppData, "R6Cheat"),
            Path.Combine(LocalAppData, "SiegeCheat"),
            Path.Combine(LocalAppData, "Oxide"),
            Path.Combine(LocalAppData, "Greazy"),
        };

        foreach (var appDataPath in r6AppDataPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(appDataPath)) continue;

            var dirName = Path.GetFileName(appDataPath);
            var isKnownCheatDir =
                dirName.Equals("R6Cheat", StringComparison.OrdinalIgnoreCase) ||
                dirName.Equals("SiegeCheat", StringComparison.OrdinalIgnoreCase) ||
                dirName.Equals("Oxide", StringComparison.OrdinalIgnoreCase) ||
                dirName.Equals("Greazy", StringComparison.OrdinalIgnoreCase) ||
                dirName.Equals("HxCheats", StringComparison.OrdinalIgnoreCase) ||
                dirName.Equals("R6Sharp", StringComparison.OrdinalIgnoreCase);

            if (isKnownCheatDir)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Known R6 cheat AppData directory found: {dirName}",
                    Risk = RiskLevel.Critical,
                    Location = appDataPath,
                    Reason = $"A directory named '{dirName}' was found in AppData, matching the name of a " +
                             "known Rainbow Six Siege cheat tool. This directory is created by the cheat " +
                             "software to store configuration, logs, and cache files.",
                    Detail = $"Path: {appDataPath}"
                });
            }

            string[] files;
            try
            {
                files = Directory.GetFiles(appDataPath, "*.*", SearchOption.AllDirectories);
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

                if (fileName.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
                {
                    await InspectLogFileForCheatSignaturesAsync(ctx, ct, file).ConfigureAwait(false);
                }

                if (fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".ini", StringComparison.OrdinalIgnoreCase))
                {
                    await InspectConfigFileForCheatKeywordsAsync(ctx, ct, file).ConfigureAwait(false);
                }

                foreach (var cheatExe in KnownCheatExeNames)
                {
                    if (!fileName.Equals(cheatExe, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"R6 cheat executable in AppData: {fileName}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason = $"The known R6 Siege cheat executable '{fileName}' was found in the " +
                                 $"AppData directory '{appDataPath}'. Cheats stored in AppData are often " +
                                 "designed to run without elevated privileges.",
                        Detail = $"AppData path: {appDataPath}"
                    });
                    break;
                }
            }

            await Task.Yield();
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
                Title = $"R6 Siege cheat log signatures detected: {fileName}",
                Risk = RiskLevel.High,
                Location = logFile,
                FileName = fileName,
                Reason = $"The log file '{fileName}' contains {matchedSignatures.Count} text signatures " +
                         "associated with R6 Siege cheat software, including Oxide, Greazy, R6Sharp, " +
                         "BattlEye bypass confirmations, and ESP/aimbot activation messages.",
                Detail = $"Matched signatures ({matchedSignatures.Count}): {string.Join(", ", matchedSignatures.Take(5))}"
            });
        }
    }

    private async Task ScanForVulkanAndDxHookDllsAsync(ScanContext ctx, CancellationToken ct)
    {
        var vulkanAndDxHookNames = new[]
        {
            "vulkan-1.dll",
            "VkLayer_r6_esp.dll",
            "VkLayer_siege_hack.dll",
            "VkLayer_cheat.dll",
            "SiegeVulkanLayer.dll",
            "r6_vulkan_layer.dll",
            "R6VulkanHook.dll",
            "dxgi.dll",
            "d3d11.dll",
            "d3d12.dll",
            "dxgi_hook_r6.dll",
            "d3d11_hook_r6.dll",
            "d3d12_hook_r6.dll",
            "dxgi_r6.dll",
        };

        var suspiciousDllContexts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "VkLayer_r6_esp.dll",
            "VkLayer_siege_hack.dll",
            "VkLayer_cheat.dll",
            "SiegeVulkanLayer.dll",
            "r6_vulkan_layer.dll",
            "R6VulkanHook.dll",
            "dxgi_hook_r6.dll",
            "d3d11_hook_r6.dll",
            "d3d12_hook_r6.dll",
            "dxgi_r6.dll",
        };

        foreach (var r6Path in R6InstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(r6Path)) continue;

            foreach (var hookDll in vulkanAndDxHookNames)
            {
                var fullPath = Path.Combine(r6Path, hookDll);
                if (!File.Exists(fullPath)) continue;

                ctx.IncrementFiles();

                if (suspiciousDllContexts.Contains(hookDll))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Vulkan/DX hook cheat DLL in R6 install: {hookDll}",
                        Risk = RiskLevel.Critical,
                        Location = fullPath,
                        FileName = hookDll,
                        Reason = $"The file '{hookDll}' found in the Rainbow Six Siege installation directory " +
                                 $"'{r6Path}' is a Vulkan or DirectX hook DLL used for rendering-level " +
                                 "wallhack and ESP overlays. R6 Siege uses Vulkan, making Vulkan layer " +
                                 "injection a common vector for visual cheats.",
                        Detail = $"R6 install path: {r6Path}"
                    });
                }
                else if (hookDll.Equals("dxgi.dll", StringComparison.OrdinalIgnoreCase) ||
                         hookDll.Equals("d3d11.dll", StringComparison.OrdinalIgnoreCase) ||
                         hookDll.Equals("d3d12.dll", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Potentially proxied DirectX DLL in R6 Siege directory: {hookDll}",
                        Risk = RiskLevel.High,
                        Location = fullPath,
                        FileName = hookDll,
                        Reason = $"The file '{hookDll}' was found in the R6 Siege directory. While this " +
                                 "file name is a standard Windows DirectX component, its presence inside " +
                                 "the game directory indicates a DLL proxy technique commonly used to " +
                                 "inject wallhack and ESP overlays into the game's render pipeline.",
                        Detail = $"R6 install path: {r6Path}"
                    });
                }
            }

            await Task.Yield();
        }

        var vulkanLayerPaths = new[]
        {
            Path.Combine(UserProfile, ".vulkan", "explicit_layer.d"),
            Path.Combine(UserProfile, ".vulkan", "implicit_layer.d"),
            Path.Combine(LocalAppData, "vulkan", "explicit_layer.d"),
            Path.Combine(LocalAppData, "vulkan", "implicit_layer.d"),
        };

        foreach (var layerPath in vulkanLayerPaths)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(layerPath)) continue;

            string[] layerFiles;
            try
            {
                layerFiles = Directory.GetFiles(layerPath, "*.json", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var layerFile in layerFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                await InspectVulkanLayerManifestAsync(ctx, ct, layerFile).ConfigureAwait(false);
            }

            await Task.Yield();
        }
    }

    private async Task InspectVulkanLayerManifestAsync(ScanContext ctx, CancellationToken ct, string filePath)
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

        var suspiciousLayerKeywords = new[]
        {
            "esp", "wallhack", "cheat", "hack", "siege_layer", "r6_layer",
            "rainbow", "siege", "overlay_hack", "aimbot", "r6s_hook",
        };

        var matched = new List<string>();
        foreach (var kw in suspiciousLayerKeywords)
        {
            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                matched.Add(kw);
        }

        if (matched.Count >= 1)
        {
            var fileName = Path.GetFileName(filePath);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Suspicious Vulkan layer manifest referencing R6 Siege: {fileName}",
                Risk = RiskLevel.Critical,
                Location = filePath,
                FileName = fileName,
                Reason = $"The Vulkan layer manifest '{fileName}' contains {matched.Count} keywords " +
                         "associated with Rainbow Six Siege cheating (wallhack, ESP, overlay injection). " +
                         "Implicit Vulkan layers are loaded for every Vulkan application and can inject " +
                         "code into R6 Siege's rendering pipeline without requiring process injection.",
                Detail = $"Matched keywords ({matched.Count}): {string.Join(", ", matched)}"
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
                    Title = $"R6 Siege cheat process currently running: {procName}",
                    Risk = RiskLevel.Critical,
                    Location = procPath,
                    FileName = procName + ".exe",
                    Reason = $"The process '{procName}' (PID: {proc.Id}) is currently running and matches " +
                             "the name of a known Rainbow Six Siege cheat tool. An active cheat process " +
                             "indicates real-time cheat use or readiness.",
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
        ScanIfeoForR6Binaries(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ScanBattleEyeServiceKey(ctx);

        ct.ThrowIfCancellationRequested();
        ScanUninstallForCheatSoftware(ctx, ct);

        ct.ThrowIfCancellationRequested();
        ScanVulkanRegistryLayers(ctx, ct);
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
                            Title = $"R6 Siege cheat registered in startup Run key: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\{keyPath}\{valueName}",
                            Reason = $"The registry autorun value '{valueName}' under '{keyPath}' references " +
                                     $"the known R6 Siege cheat '{cheatExe}'. This ensures the cheat launches " +
                                     "automatically with Windows before Rainbow Six Siege starts.",
                            Detail = $"Registry value: {TruncateString(value, 200)}"
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private void ScanIfeoForR6Binaries(ScanContext ctx, CancellationToken ct)
    {
        const string ifeoBase = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        var r6Binaries = new[]
        {
            "RainbowSix.exe",
            "RainbowSix_BE.exe",
            "BEService.exe",
        };

        foreach (var binary in r6Binaries)
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
                        Title = $"IFEO debugger set for R6 Siege binary: {binary}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{ifeoBase}\{binary}",
                        Reason = $"An Image File Execution Options debugger entry was found for '{binary}'. " +
                                 "When the R6 Siege executable or BattlEye starts, Windows will launch the " +
                                 "specified debugger instead, which is used to bypass anti-cheat or inject cheats.",
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
                    Reason = "The BattlEye service (BEService) is set to Disabled (Start=4) in the registry. " +
                             "Rainbow Six Siege uses BattlEye as one of its anti-cheat layers. Disabling " +
                             "this service is a standard step in setting up many R6 cheats.",
                    Detail = $"Start value: {startInt} (Disabled=4)"
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
            "r6cheat", "siegecheat", "r6hack", "rainbowcheat", "oxide r6",
            "greazy", "hxcheats", "r6sharp", "r6s-esp", "siege-aimbot",
            "r6 esp", "siege esp", "rainbow six cheat", "r6 siege cheat",
            "siege aimbot", "r6 aimbot", "uplay bypass", "ubisoft bypass",
        };

        foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            try
            {
                using var key = hive.OpenSubKey(uninstallKey, writable: false);
                if (key is null) continue;

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
                                Title = $"R6 Siege cheat software found in installed programs: {displayName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"{uninstallKey}\{subKeyName}",
                                Reason = $"The installed program '{displayName}' matches the name of a known " +
                                         "Rainbow Six Siege cheat application. This was formally installed " +
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
        }
    }

    private void ScanVulkanRegistryLayers(ScanContext ctx, CancellationToken ct)
    {
        var vulkanLayerKeys = new[]
        {
            @"SOFTWARE\Khronos\Vulkan\ImplicitLayers",
            @"SOFTWARE\Khronos\Vulkan\ExplicitLayers",
            @"SOFTWARE\WOW6432Node\Khronos\Vulkan\ImplicitLayers",
            @"SOFTWARE\WOW6432Node\Khronos\Vulkan\ExplicitLayers",
        };

        var cheatLayerKeywords = new[]
        {
            "esp", "wallhack", "cheat", "hack", "siege", "rainbow", "r6",
            "aimbot", "overlay_hack", "r6s", "cheater",
        };

        foreach (var keyPath in vulkanLayerKeys)
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

                    foreach (var kw in cheatLayerKeywords)
                    {
                        if (!valueName.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious Vulkan layer registered with R6-related name: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{keyPath}\{valueName}",
                            Reason = $"A Vulkan layer manifest registered at '{keyPath}' has a path containing " +
                                     $"the keyword '{kw}', associated with R6 Siege cheating. Implicit Vulkan " +
                                     "layers load into every Vulkan application automatically, including " +
                                     "Rainbow Six Siege, and can be used for wallhack and ESP injection.",
                            Detail = $"Layer path: {valueName}"
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static string TruncateString(string input, int maxLength)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        return input.Length <= maxLength ? input : input[..maxLength] + "...";
    }
}
