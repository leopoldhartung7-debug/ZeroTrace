using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class PubgCheatScanModule : IScanModule
{
    public string Name => "PUBG / Battlegrounds Cheat Detection";
    public double Weight => 4.0;
    public int ParallelGroup => 4;

    private static readonly string[] CheatExeNames =
    [
        "pubgcheat.exe", "pubghack.exe", "pubgaimbot.exe", "pubgesp.exe",
        "pubgexternal.exe", "pubg_wallhack.exe", "tslgame_hack.exe",
        "pubg_aimbot.exe", "pubg_loot_esp.exe", "pubg_vehicle_esp.exe",
        "pubg_dma.exe", "pubg_radar.exe", "battlegrounds_cheat.exe",
        "pubg_no_recoil.exe", "pubg_spoofer.exe", "pubg_bypass.exe",
        "pubg_external.exe", "emulatorhack.exe", "pubglite_hack.exe",
        "pubg_mobile_hack.exe", "pubgmobile_hack.exe", "tsl_cheat.exe",
        "bgmi_hack.exe", "pubg_internal.dll", "tslgame_cheat.exe",
        "pubg_loader.exe", "tsl_loader.exe", "tslloader.exe",
        "pubg_injector.exe", "tsl_injector.exe", "pubginjector.exe",
        "battleye_bypass_pubg.exe", "be_bypass_pubg.exe", "pubg_be.exe",
        "pubg_hvh.exe", "pubg_spinbot.exe", "pubg_triggerbot.exe",
        "pubg_silentaim.exe", "pubg_instant_kill.exe", "pubg_speedhack.exe",
        "pubg_bhop.exe", "pubg_fly.exe", "pubg_teleport.exe",
        "pubg_auto_heal.exe", "pubg_auto_loot.exe", "pubg_loot_filter.exe",
        "pubg_zone_esp.exe", "pubg_vehicle.exe", "pubg_car_esp.exe",
        "pubg_kill_all.exe", "pubg_crate_esp.exe", "pubg_parachute.exe",
        "pubg_bomb_esp.exe", "pubg_radar_server.exe", "pubgradar.exe",
        "pubg_dma_cheat.exe", "dma_pubg.exe", "pubg_memory.exe",
        "tslgame_external.exe", "tslgame_memory.exe", "pubg_unreal.exe",
    ];

    private static readonly string[] CheatConfigKeywords =
    [
        "aimbot_smooth_pubg", "aimbot_fov_pubg", "esp_boxes_pubg",
        "esp_health_pubg", "esp_loot_pubg", "loot_filter_pubg",
        "vehicle_esp", "bomb_esp", "zone_esp", "parachute_hack",
        "no_recoil_pubg", "no_spread_pubg", "silent_aim_pubg",
        "triggerbot_pubg", "bhop_pubg", "speedhack_pubg",
        "instant_kill", "auto_heal", "auto_loot", "loot_esp_pubg",
        "crate_esp", "player_esp_pubg", "radar_pubg", "map_hack_pubg",
        "pubg_aimbot", "pubg_esp", "pubg_wallhack", "pubg_aim",
        "tslgame_aim", "tslgame_esp", "aim_at_head_pubg",
        "aim_at_body_pubg", "aim_prediction_pubg", "aim_bone_pubg",
        "draw_fov_pubg", "draw_esp_pubg", "draw_loot_pubg",
        "filter_ammo", "filter_armor", "filter_helmet", "filter_meds",
        "filter_weapons", "loot_priority", "auto_pickup",
        "recoil_control", "spread_control", "bullet_drop_pubg",
        "lead_target_pubg", "bullet_velocity_pubg",
    ];

    private static readonly string[] OffsetKeywords =
    [
        "TslGame-Win64-Shipping", "GWorld", "GNames", "ULevel",
        "APlayerController", "ACharacter", "USkeletalMeshComponent",
        "BoneArray", "ComponentBoundsToLocalBound", "m_team",
        "PlayerArray", "ActorArray", "ItemTable",
        "UGameInstance", "UWorld", "PersistentLevel",
        "TslPlayerController", "TslCharacter", "TslInventory",
        "TslLootDropContainer", "TslVehicle", "TslAirDrop",
        "TslProjectile", "BluezoneRadius", "PlayZone",
        "ActorList", "EntityArray", "WorldToScreen",
        "ViewMatrix", "LocalPlayer", "CameraManager",
    ];

    private static readonly string[] BeBypassTools =
    [
        "be_bypass", "battleye_bypass", "be_loader", "beloader",
        "be_hook", "be_spoofer", "be_disable", "be_patch",
        "be_inject", "pubg_be_bypass", "pubgbebypass",
        "beservice_bypass", "beclient_bypass", "battleeye_bypass",
        "battle_eye_bypass", "be_kill", "be_unload",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var tasks = new List<Task>
        {
            ScanPubgInstallPathsAsync(ctx, ct),
            ScanProcessesAsync(ctx, ct),
            ScanConfigFilesAsync(ctx, ct),
            ScanOffsetFilesAsync(ctx, ct),
            ScanRegistryAsync(ctx, ct),
            ScanBeBypassArtifactsAsync(ctx, ct),
            ScanRadarDmaArtifactsAsync(ctx, ct),
            ScanPubgAppDataAsync(ctx, ct),
        };
        await Task.WhenAll(tasks);
    }

    private async Task ScanPubgInstallPathsAsync(ScanContext ctx, CancellationToken ct)
    {
        var pubgPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TslGame"),
            @"C:\Program Files (x86)\Steam\steamapps\common\PUBG",
            @"C:\Program Files\Steam\steamapps\common\PUBG",
            @"D:\SteamLibrary\steamapps\common\PUBG",
            @"E:\SteamLibrary\steamapps\common\PUBG",
        };

        // Get Steam path from registry
        try
        {
            using var steamKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam");
            var steamPath = steamKey?.GetValue("InstallPath") as string;
            if (steamPath != null)
            {
                pubgPaths = [.. pubgPaths, Path.Combine(steamPath, "steamapps", "common", "PUBG")];
            }
        }
        catch { }

        foreach (var pubgRoot in pubgPaths)
        {
            if (!Directory.Exists(pubgRoot)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(pubgRoot, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                if (CheatExeNames.Any(c => fn.Equals(c, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PUBG Cheat in Game Directory",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Cheat tool '{fn}' found in PUBG game directory",
                        Detail = $"Path: {file}"
                    });
                }

                // BattlEye directory tampering
                if (file.Contains("BattlEye", StringComparison.OrdinalIgnoreCase))
                {
                    var ext = Path.GetExtension(fn).ToLowerInvariant();
                    if (ext == ".dll" && fn.Contains("bypass", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "BattlEye Bypass DLL in PUBG",
                            Risk = Risk.Critical,
                            Location = file,
                            FileName = fn,
                            Reason = $"BattlEye bypass DLL '{fn}' in PUBG BattlEye directory",
                            Detail = "DLL replacement attack against PUBG's BattlEye protection"
                        });
                    }
                }
            }
        }
        await Task.CompletedTask;
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

                if (CheatExeNames.Any(c => pname.Equals(c, StringComparison.OrdinalIgnoreCase)))
                {
                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PUBG Cheat Process Running",
                        Risk = Risk.Critical,
                        Location = procPath,
                        FileName = pname,
                        Reason = $"Known PUBG cheat process '{pname}' is currently running",
                        Detail = $"PID: {proc.Id}"
                    });
                }
            }
        }, ct);
    }

    private async Task ScanConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var configDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TslGame", "Saved"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "TslGame"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "PUBG"),
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
                if (ext != ".ini" && ext != ".cfg" && ext != ".json" && ext != ".txt") continue;

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
                if (hits.Count >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PUBG Cheat Configuration File",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Config file contains {hits.Count} PUBG cheat keywords",
                        Detail = "Keywords: " + string.Join(", ", hits.Take(8))
                    });
                }
                else if (hits.Count == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PUBG Cheat Config Keyword",
                        Risk = Risk.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"File contains PUBG cheat keyword: {hits[0]}",
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
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        };

        foreach (var baseDir in searchDirs)
        {
            if (!Directory.Exists(baseDir)) continue;

            string[] files;
            try { files = Directory.GetFiles(baseDir, "*.*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext != ".json" && ext != ".hpp" && ext != ".h" && ext != ".cpp") continue;

                var fn = Path.GetFileName(file);
                if (!fn.Contains("pubg", StringComparison.OrdinalIgnoreCase) &&
                    !fn.Contains("tsl", StringComparison.OrdinalIgnoreCase) &&
                    !fn.Contains("offset", StringComparison.OrdinalIgnoreCase) &&
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
                        Title = "PUBG Memory Offset File",
                        Risk = Risk.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"File contains {hits.Count} PUBG UE4 memory offset identifiers",
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
            // BattlEye service status for PUBG
            try
            {
                using var be = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\BEService");
                if (be != null)
                {
                    ctx.IncrementRegistryKeys();
                    var start = be.GetValue("Start");
                    if (start is int s && s == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "BattlEye Service Disabled (PUBG)",
                            Risk = Risk.High,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Services\BEService",
                            FileName = "Registry",
                            Reason = "BattlEye service is disabled — PUBG anti-cheat bypass indicator",
                            Detail = "BEService Start=4 (Disabled)"
                        });
                    }
                }
            }
            catch { }

            // Scan installed software
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
                        try
                        {
                            using var entry = key.OpenSubKey(sub);
                            ctx.IncrementRegistryKeys();
                            var dispName = entry?.GetValue("DisplayName") as string ?? string.Empty;
                            if ((dispName.Contains("pubg", StringComparison.OrdinalIgnoreCase) ||
                                 dispName.Contains("battlegrounds", StringComparison.OrdinalIgnoreCase)) &&
                                (dispName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                 dispName.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                                 dispName.Contains("aimbot", StringComparison.OrdinalIgnoreCase) ||
                                 dispName.Contains("bypass", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "PUBG Cheat Software Installed",
                                    Risk = Risk.Critical,
                                    Location = $@"HKLM\{uninst}\{sub}",
                                    FileName = "Registry",
                                    Reason = $"Installed software '{dispName}' matches PUBG cheat pattern",
                                    Detail = $"DisplayName: {dispName}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }

            // PUBG-specific registry paths
            var pubgKeys = new[]
            {
                @"SOFTWARE\PUBG Corporation",
                @"SOFTWARE\KRAFTON",
                @"SOFTWARE\WOW6432Node\PUBG Corporation",
            };
            foreach (var pkey in pubgKeys)
            {
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey(pkey);
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
                                Title = "Suspicious PUBG Registry Value",
                                Risk = Risk.High,
                                Location = $@"HKLM\{pkey}",
                                FileName = "Registry",
                                Reason = $"Suspicious registry value '{valName}' under PUBG/KRAFTON key",
                                Detail = $"Registry key: {pkey}"
                            });
                        }
                    }
                }
                catch { }
            }
        }, ct);
    }

    private async Task ScanBeBypassArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var scanDirs = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
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

                if (BeBypassTools.Any(t => fn.Contains(t, StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "BattlEye Bypass Tool (PUBG)",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"BattlEye bypass tool '{fn}' targeting PUBG",
                        Detail = "Bypasses PUBG's BattlEye kernel driver to enable cheats"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }

    private async Task ScanRadarDmaArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        // DMA cheat configs targeting PUBG
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.GetTempPath(),
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            string[] jsonFiles;
            try { jsonFiles = Directory.GetFiles(dir, "*.json", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var file in jsonFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fn = Path.GetFileName(file);
                if (!fn.Contains("pubg", StringComparison.OrdinalIgnoreCase) &&
                    !fn.Contains("tsl", StringComparison.OrdinalIgnoreCase) &&
                    !fn.Contains("dma", StringComparison.OrdinalIgnoreCase) &&
                    !fn.Contains("radar", StringComparison.OrdinalIgnoreCase)) continue;

                string content;
                try
                {
                    ctx.IncrementFiles();
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                if (content.Contains("TslGame", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("GWorld", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("PlayerArray", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PUBG DMA/Radar Cheat Config",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = "JSON config contains PUBG DMA/radar cheat process identifiers",
                        Detail = "DMA and radar cheats bypass BattlEye via hardware-level memory reading"
                    });
                }
            }
        }
    }

    private async Task ScanPubgAppDataAsync(ScanContext ctx, CancellationToken ct)
    {
        var pubgAppData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TslGame", "Saved");
        if (!Directory.Exists(pubgAppData)) return;

        string[] files;
        try { files = Directory.GetFiles(pubgAppData, "*", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var fn = Path.GetFileName(file);
            var ext = Path.GetExtension(fn).ToLowerInvariant();

            if (ext == ".exe" || ext == ".dll" || ext == ".sys")
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Executable in PUBG AppData Directory",
                    Risk = Risk.High,
                    Location = file,
                    FileName = fn,
                    Reason = $"Executable '{fn}' placed in PUBG saved data path — suspicious",
                    Detail = $"Path: {file}"
                });
            }
        }
        await Task.CompletedTask;
    }
}
