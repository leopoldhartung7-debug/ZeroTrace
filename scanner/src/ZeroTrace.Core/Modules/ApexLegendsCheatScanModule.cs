using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class ApexLegendsCheatScanModule : IScanModule
{
    public string Name => "Apex Legends Cheat Detection";
    public double Weight => 4.0;
    public int ParallelGroup => 4;

    private static readonly string[] CheatExeNames =
    [
        "apexcheat.exe", "apexhack.exe", "apexaimbot.exe", "apexesp.exe",
        "apexexternal.exe", "apexinternal.exe", "apexlegendscheat.exe",
        "apex_legend_hack.exe", "apex_aimbot.exe", "apex_esp.exe",
        "apex_wallhack.exe", "apex_triggerbot.exe", "apex_no_recoil.exe",
        "apex_speedhack.exe", "apex_bypass.exe", "apex_spoofer.exe",
        "apex_loader.exe", "apex_injector.exe", "apexloader.exe",
        "apexinjector.exe", "r5apex_bypass.exe", "ea_bypass.exe",
        "easyanticheat_bypass_apex.exe", "eac_bypass_apex.exe",
        "apex_eac_bypass.exe", "apexeacbypass.exe", "loadercheat.exe",
        "loadercheat_apex.exe", "cheatloader_apex.exe", "apex_cheat_loader.exe",
        "apex_dma.exe", "apex_radar.exe", "apex_map_hack.exe",
        "apexmaphack.exe", "apexradar.exe", "apex_external.exe",
        "r5apex_cheat.exe", "r5apexhack.exe", "ea_cheat_bypass.exe",
        "origin_bypass.exe", "origin_crack.exe", "ea_crack.exe",
        "apex_loot_esp.exe", "apex_player_esp.exe", "apex_item_esp.exe",
        "apex_movement.exe", "apex_bhop.exe", "apex_spinbot.exe",
        "apexspinbot.exe", "apex_hvh.exe", "silent_aim_apex.exe",
        "triggerbot_apex.exe", "aimassist_apex.exe", "apexaimassist.exe",
        "apex_health_esp.exe", "apex_shield_esp.exe", "apex_team_check.exe",
        "apex_heal_bot.exe", "apex_auto_heal.exe", "apex_rotation.exe",
        "r5reloaded_cheat.exe", "r5apex_loader.exe",
    ];

    private static readonly string[] CheatDllNames =
    [
        "r5apex.dll", "apex_cheat.dll", "apex_hook.dll", "eac_bypass.dll",
        "r5apex_eac_bypass.dll", "eac_loader.dll", "apex_internal.dll",
        "apex_inject.dll", "apexinternal.dll", "apexhook.dll",
        "ea_bypass.dll", "origin_bypass.dll", "eac_hook.dll",
        "apex_memory.dll", "apex_offsets.dll", "r5apex_internal.dll",
        "apexloader.dll", "easyanticheat_bypass.dll",
    ];

    private static readonly string[] CheatConfigKeywords =
    [
        "aimbot_smoothing_apex", "aimbot_fov_apex", "aimbot_bone_apex",
        "esp_boxes_apex", "esp_health_apex", "esp_shield_apex",
        "esp_ammo_apex", "esp_distance_apex", "no_recoil_apex",
        "silent_aim_apex", "triggerbot_apex", "item_esp", "loot_esp_apex",
        "speedhack_apex", "bhop_apex", "spinbot_apex", "wallhack_apex",
        "movement_hack_apex", "healing_esp", "teammate_check",
        "r5apex_aimbot", "r5apex_esp", "r5apex_wallhack",
        "apex_aim_key", "apex_esp_key", "apex_triggerbot_key",
        "aimbot_enabled_apex", "esp_enabled_apex", "wallhack_enabled_apex",
        "no_recoil_enabled", "silent_aim_enabled", "spinbot_enabled",
        "loot_esp_enabled", "item_filter_apex", "auto_heal_enabled",
        "aim_at_head_apex", "aim_at_body_apex", "aim_at_closest",
        "aimbot_prediction_apex", "movement_prediction_apex",
        "apex_player_list", "apex_bone_list", "apex_hitbox",
        "apex_team_filter", "apex_visibility_check", "apex_aim_step",
        "apex_smooth_factor", "draw_fov_circle_apex", "draw_crosshair_apex",
    ];

    private static readonly string[] OffsetKeywords =
    [
        "LocalPlayer", "EntityList", "ViewMatrix", "Health", "Shield",
        "TeamNum", "WorldToScreen", "m_iHealth", "m_iShieldHealth",
        "m_iTeamNum", "m_vecOrigin", "m_vecVelocity", "m_bAlive",
        "m_Anim", "m_nModelIndex", "r5apex", "r5apex.exe",
        "PlayerArray", "RootComponent", "RelativeLocation",
        "AbsoluteLocation", "Bones", "BoneArray", "BoneMatrix",
    ];

    private static readonly string[] EacBypassTools =
    [
        "eac_bypass", "easyanticheat_bypass", "eac_loader", "eac_hook",
        "eac_spoofer", "eac_disable", "eac_patch", "eac_inject",
        "apex_eac", "r5apex_eac", "be_bypass", "anticheat_bypass",
        "eac_killer", "eac_unload", "eac_disable_tool",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var tasks = new List<Task>
        {
            ScanApexDirectoriesAsync(ctx, ct),
            ScanProcessesAsync(ctx, ct),
            ScanConfigFilesAsync(ctx, ct),
            ScanOffsetFilesAsync(ctx, ct),
            ScanRegistryAsync(ctx, ct),
            ScanEacBypassArtifactsAsync(ctx, ct),
            ScanApexAppDataAsync(ctx, ct),
            ScanLoaderArtifactsAsync(ctx, ct),
        };
        await Task.WhenAll(tasks);
    }

    private async Task ScanApexDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        var apexPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Origin Games", "Apex"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Origin Games", "Apex"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "EA Games", "Apex Legends"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "EA Games", "Apex Legends"),
            Path.Combine("C:\\", "Program Files (x86)", "Origin Games", "Apex"),
            Path.Combine("C:\\", "Program Files", "EA Games", "Apex Legends"),
            Path.Combine("D:\\", "Origin Games", "Apex"),
            Path.Combine("D:\\", "EA Games", "Apex Legends"),
        };

        // Also check Steam libraries
        var steamPaths = GetSteamApexPaths();
        var allPaths = apexPaths.Concat(steamPaths).ToArray();

        foreach (var apexRoot in allPaths)
        {
            if (!Directory.Exists(apexRoot)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(apexRoot, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                foreach (var cheatExe in CheatExeNames)
                {
                    if (fn.Equals(cheatExe, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Apex Legends Cheat Executable",
                            Risk = Risk.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known Apex cheat executable '{fn}' found in Apex game directory",
                            Detail = $"Path: {file}"
                        });
                        break;
                    }
                }

                foreach (var cheatDll in CheatDllNames)
                {
                    if (fn.Equals(cheatDll, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Apex Cheat DLL in Game Directory",
                            Risk = Risk.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"Cheat/bypass DLL '{fn}' placed in Apex game directory",
                            Detail = "DLL-based cheat injection or EAC bypass artifact"
                        });
                        break;
                    }
                }
            }
        }
        await Task.CompletedTask;
    }

    private static IEnumerable<string> GetSteamApexPaths()
    {
        var results = new List<string>();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam");
            var steamPath = key?.GetValue("InstallPath") as string;
            if (steamPath != null)
            {
                results.Add(Path.Combine(steamPath, "steamapps", "common", "Apex Legends"));
            }
        }
        catch { }

        var drives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed);
        foreach (var drive in drives)
        {
            results.Add(Path.Combine(drive.RootDirectory.FullName, "SteamLibrary", "steamapps", "common", "Apex Legends"));
            results.Add(Path.Combine(drive.RootDirectory.FullName, "Steam", "steamapps", "common", "Apex Legends"));
        }
        return results;
    }

    private async Task ScanProcessesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var processes = ctx.GetProcessSnapshot();
            foreach (var proc in processes)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementProcesses();
                var pname = proc.ProcessName + ".exe";

                foreach (var cheat in CheatExeNames)
                {
                    if (pname.Equals(cheat, StringComparison.OrdinalIgnoreCase))
                    {
                        string procPath = string.Empty;
                        try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Apex Cheat Process Running",
                            Risk = Risk.Critical,
                            Location = procPath,
                            FileName = pname,
                            Reason = $"Known Apex cheat process '{pname}' is currently active",
                            Detail = $"PID: {proc.Id}, Path: {procPath}"
                        });
                        break;
                    }
                }
            }
        }, ct);
    }

    private async Task ScanConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var configDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Apex"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ApexLegends"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Apex"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ApexLegends"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Apex"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "ApexLegends"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
        };

        foreach (var dir in configDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext != ".ini" && ext != ".cfg" && ext != ".json" && ext != ".txt" && ext != ".xml") continue;

                string content;
                try
                {
                    ctx.IncrementFiles();
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                var hits = CheatConfigKeywords.Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)).ToList();
                if (hits.Count >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Apex Cheat Configuration File",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Config file contains {hits.Count} Apex cheat keywords",
                        Detail = "Keywords: " + string.Join(", ", hits.Take(8))
                    });
                }
                else if (hits.Count == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Apex Cheat Config Keyword",
                        Risk = Risk.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"File contains Apex cheat keyword: {hits[0]}",
                        Detail = $"File: {file}"
                    });
                }
            }
        }
    }

    private async Task ScanOffsetFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var baseDir in searchDirs)
        {
            if (!Directory.Exists(baseDir)) continue;

            string[] files;
            try { files = Directory.GetFiles(baseDir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext != ".json" && ext != ".hpp" && ext != ".h" && ext != ".cpp" && ext != ".txt") continue;

                var fn = Path.GetFileName(file);
                if (!fn.Contains("offset", StringComparison.OrdinalIgnoreCase) &&
                    !fn.Contains("apex", StringComparison.OrdinalIgnoreCase) &&
                    !fn.Contains("r5apex", StringComparison.OrdinalIgnoreCase) &&
                    !fn.Contains("dump", StringComparison.OrdinalIgnoreCase)) continue;

                string content;
                try
                {
                    ctx.IncrementFiles();
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                var hits = OffsetKeywords.Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)).ToList();
                if (hits.Count >= 3)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Apex Memory Offset File",
                        Risk = Risk.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"File contains {hits.Count} Apex memory offset identifiers",
                        Detail = "Offsets: " + string.Join(", ", hits.Take(8))
                    });
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanRegistryAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // EAC service disabled
            try
            {
                using var svc = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\EasyAntiCheat");
                if (svc != null)
                {
                    ctx.IncrementRegistryKeys();
                    var start = svc.GetValue("Start");
                    if (start is int s && s == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "EasyAntiCheat Service Disabled",
                            Risk = Risk.High,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat",
                            FileName = "Registry",
                            Reason = "EasyAntiCheat service Start=4 (disabled) — may allow Apex EAC bypass",
                            Detail = "EAC must be running for Apex Legends to function legitimately"
                        });
                    }
                }
            }
            catch { }

            // EAC_EOS service
            try
            {
                using var svc = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS");
                if (svc != null)
                {
                    ctx.IncrementRegistryKeys();
                    var start = svc.GetValue("Start");
                    if (start is int s && s == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "EasyAntiCheat EOS Service Disabled",
                            Risk = Risk.High,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS",
                            FileName = "Registry",
                            Reason = "EasyAntiCheat_EOS service disabled — Apex EAC bypass indicator",
                            Detail = "EAC EOS integration disabled may permit cheat injection"
                        });
                    }
                }
            }
            catch { }

            // Origin/EA App registry for bypass configs
            var eaKeys = new[]
            {
                @"SOFTWARE\EA Games\Apex Legends",
                @"SOFTWARE\Electronic Arts\EA Desktop",
                @"SOFTWARE\Origin",
            };
            foreach (var eaKey in eaKeys)
            {
                try
                {
                    using var k = Registry.CurrentUser.OpenSubKey(eaKey);
                    if (k == null) continue;
                    ctx.IncrementRegistryKeys();
                    foreach (var valName in k.GetValueNames())
                    {
                        if (valName.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains("hack", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Suspicious EA/Origin Registry Value",
                                Risk = Risk.High,
                                Location = $@"HKCU\{eaKey}",
                                FileName = "Registry",
                                Reason = $"Suspicious registry value '{valName}' in EA/Origin path",
                                Detail = $"Value: {valName}"
                            });
                        }
                    }
                }
                catch { }
            }

            // Scan installed software for Apex cheat tools
            var uninstallKeys = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };
            foreach (var uninstKey in uninstallKeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(uninstKey);
                    if (key == null) continue;
                    foreach (var sub in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var entry = key.OpenSubKey(sub);
                            ctx.IncrementRegistryKeys();
                            var name = entry?.GetValue("DisplayName") as string ?? string.Empty;
                            if (name.Contains("apex", StringComparison.OrdinalIgnoreCase) &&
                                (name.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                 name.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                                 name.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                 name.Contains("aimbot", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Apex Cheat Software Installed",
                                    Risk = Risk.Critical,
                                    Location = $@"HKLM\{uninstKey}\{sub}",
                                    FileName = "Registry",
                                    Reason = $"Installed software '{name}' matches Apex cheat pattern",
                                    Detail = $"DisplayName: {name}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }, ct);
    }

    private async Task ScanEacBypassArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var scanDirs = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        };

        foreach (var dir in scanDirs)
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

                foreach (var bypassTool in EacBypassTools)
                {
                    if (fn.Contains(bypassTool, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "EAC Bypass Tool Artifact",
                            Risk = Risk.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"EAC bypass tool artifact '{fn}' found",
                            Detail = "EasyAntiCheat bypass artifact — used to circumvent Apex Legends protection"
                        });
                        break;
                    }
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanApexAppDataAsync(ScanContext ctx, CancellationToken ct)
    {
        // Scan saved game data for cheat artifact injections
        var savedPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Respawn", "Apex"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Respawn", "Apex"),
        };

        foreach (var savedPath in savedPaths)
        {
            if (!Directory.Exists(savedPath)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(savedPath, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fn = Path.GetFileName(file);
                var ext = Path.GetExtension(fn).ToLowerInvariant();

                // Unexpected executables in saved game dir
                if (ext == ".exe" || ext == ".dll" || ext == ".sys")
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Executable in Apex Saved Game Directory",
                        Risk = Risk.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Executable file '{fn}' in Apex saved game path — suspicious placement",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                if (ext == ".cfg" || ext == ".ini" || ext == ".json")
                {
                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hits = CheatConfigKeywords.Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)).ToList();
                    if (hits.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Keywords in Apex App Data",
                            Risk = Risk.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Apex saved data file contains {hits.Count} cheat keyword(s)",
                            Detail = "Keywords: " + string.Join(", ", hits.Take(5))
                        });
                    }
                }
            }
        }
    }

    private async Task ScanLoaderArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        // Check for DMA cheat configs targeting Apex
        var dmaDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)),
            Path.GetTempPath(),
        };

        foreach (var dir in dmaDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*.json", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var fn = Path.GetFileName(file);
                if (!fn.Contains("apex", StringComparison.OrdinalIgnoreCase) &&
                    !fn.Contains("r5apex", StringComparison.OrdinalIgnoreCase) &&
                    !fn.Contains("dma", StringComparison.OrdinalIgnoreCase)) continue;

                string content;
                try
                {
                    ctx.IncrementFiles();
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                if (content.Contains("r5apex", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("EntityList", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("LocalPlayer", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Apex DMA Cheat Config",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = "JSON file contains Apex DMA cheat process/offset identifiers",
                        Detail = "DMA (Direct Memory Access) cheats bypass EAC via hardware PCIe cards"
                    });
                }
            }
        }

        // Radar cheat server artifacts
        var radarFiles = new[] { "apex_radar.exe", "apexradar.exe", "r5_radar.exe", "apex_radar_server.exe" };
        var commonDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.GetTempPath(),
        };

        foreach (var dir in commonDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] exeFiles;
            try { exeFiles = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in exeFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fn = Path.GetFileName(file);
                if (radarFiles.Any(r => fn.Equals(r, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Apex Radar Cheat Tool",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Apex radar cheat executable '{fn}' found",
                        Detail = "Radar cheats expose all player positions via external display"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }
}
