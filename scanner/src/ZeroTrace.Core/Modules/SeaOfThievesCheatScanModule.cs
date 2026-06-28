using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class SeaOfThievesCheatScanModule : IScanModule
{
    public string Name => "Sea of Thieves Cheat Forensic Scan";
    public double Weight => 3.2;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    // -------------------------------------------------------------------------
    // Known SoT cheat executable filenames
    // -------------------------------------------------------------------------
    private static readonly string[] SotCheatExecutables =
    {
        "sot_cheat.exe", "sot_hack.exe", "sot_aimbot.exe", "sot_treasure.exe",
        "sot_skeleton.exe", "sot_loot_radar.exe", "seaofthieves_cheat.exe",
        "seaofthieves_hack.exe", "piratecheat.exe", "cursed_chest.exe",
        "sot_trainer.exe", "sotcheat.exe", "sothack.exe", "sot_cheater.exe",
        "sot_mod.exe", "sot_loader.exe", "sot_injector.exe", "sot_internal.exe",
        "sot_external.exe", "sot_wallhack.exe", "sot_godmode.exe",
        "sot_speedhack.exe", "sot_teleport.exe", "sot_menu.exe",
        "seaofthieves_trainer.exe", "seaofthieves_mod.exe", "sot_premium.exe",
        "sot_private.exe", "sot_undetected.exe", "pirate_cheat.exe",
        "pirate_hack.exe", "treasure_hack.exe", "gold_hack_sot.exe",
        "sot_x_ray.exe", "sot_xray.exe", "sot_noclip.exe", "sot_fly.exe",
        "sot_speedboat.exe", "sot_fast_sail.exe", "sot_cannon.exe",
        "sot_autofire.exe", "sot_recoil.exe", "sot_no_recoil.exe",
    };

    // -------------------------------------------------------------------------
    // Known SoT cheat DLL filenames
    // -------------------------------------------------------------------------
    private static readonly string[] SotCheatDlls =
    {
        "sot_esp.dll", "sot_player_esp.dll", "sot_ship_esp.dll",
        "sot_skeleton_esp.dll", "sot_cheat.dll", "sot_hack.dll",
        "sot_internal.dll", "sot_inject.dll", "sot_hook.dll",
        "sot_memory.dll", "sot_offsets.dll", "sot_overlay.dll",
        "sot_render.dll", "sot_draw.dll", "sot_input.dll",
        "sot_aimbot.dll", "sot_aim.dll", "seaofthieves_esp.dll",
        "seaofthieves_cheat.dll", "sot_treasure_esp.dll",
        "sot_loot_esp.dll", "sot_crew_esp.dll", "sot_island_esp.dll",
        "sot_animal_esp.dll", "sot_shark_esp.dll", "sot_barrel_esp.dll",
        "sot_kraken_esp.dll", "sot_megalodon_esp.dll", "sot_fort_esp.dll",
        "sot_ship_health.dll", "sot_anchor_hack.dll",
    };

    // -------------------------------------------------------------------------
    // EAC bypass artifacts targeting Sea of Thieves
    // -------------------------------------------------------------------------
    private static readonly string[] SotEacBypassFiles =
    {
        "sot_eac_bypass.dll", "eac_sot.exe", "easyanticheat_bypass_sot.dll",
        "eac_sot_bypass.dll", "sot_eac.dll", "eac_bypass_sot.exe",
        "sot_eac_patch.dll", "sot_anticheat_bypass.dll", "sot_eac_hook.dll",
        "eac_hook_sot.dll", "eac_disable_sot.exe", "sot_eac_killer.exe",
        "sot_eac_disable.dll", "sot_eac_spoofer.dll", "seaofthieves_eac_bypass.dll",
        "seaofthieves_eac.exe", "sot_anticheat_disable.dll",
    };

    // -------------------------------------------------------------------------
    // External radar and map tools for SoT
    // -------------------------------------------------------------------------
    private static readonly string[] SotRadarFiles =
    {
        "sot_radar.exe", "sot_map_esp.html", "websocket_relay_sot.py",
        "sot_radar.dll", "sot_map_hack.exe", "sot_minimap.exe",
        "sot_compass_hack.exe", "sot_tracker.exe", "sot_player_radar.exe",
        "sot_ship_radar.exe", "sot_treasure_radar.exe", "sot_loot_map.html",
        "sot_world_map.html", "sot_external_radar.exe", "sot_radar_server.exe",
        "sot_websocket.py", "sot_socket_relay.py", "sot_radar_client.exe",
        "sot_radar_overlay.exe", "sot_map_overlay.exe", "seaofthieves_radar.exe",
        "sot_island_map.html", "sot_event_radar.exe", "sot_fort_radar.exe",
    };

    // -------------------------------------------------------------------------
    // SoT process memory reading tool artifacts
    // -------------------------------------------------------------------------
    private static readonly string[] SotMemoryToolFiles =
    {
        "sot_read_mem.exe", "sot_mem_reader.exe", "sot_memory_reader.exe",
        "sot_process_read.exe", "sot_dumper.exe", "sot_dump.exe",
        "sot_sdk_dump.exe", "sot_offset_dumper.exe", "sot_mem.exe",
        "sot_memory.exe", "sot_read_process.exe", "sea_mem_reader.exe",
        "seaofthieves_dumper.exe", "sot_dma.exe", "sot_dma_reader.exe",
        "sot_external_mem.exe", "sot_external_read.exe",
    };

    // -------------------------------------------------------------------------
    // Windows Store / UWP bypass tools for SoT
    // -------------------------------------------------------------------------
    private static readonly string[] UwpBypassFiles =
    {
        "uwp_bypass_sot.exe", "store_bypass_sot.exe", "sot_uwp_bypass.dll",
        "sot_uwp_patch.exe", "microsoft_store_bypass.exe", "uwp_unpack_sot.exe",
        "sot_appx_bypass.exe", "sot_package_bypass.dll", "sot_xbox_bypass.exe",
        "xblgamesave_bypass_sot.dll", "uwp_inject_sot.dll", "sot_winstore_bypass.dll",
        "sot_appcontainer_bypass.exe", "sot_integrity_bypass.dll",
        "sot_sandbox_bypass.dll", "uwp_hook_sot.dll",
    };

    // -------------------------------------------------------------------------
    // SoT memory offset / SDK identifier files
    // -------------------------------------------------------------------------
    private static readonly string[] SotOffsetFiles =
    {
        "sot_offsets.json", "sot_offsets.txt", "sot_offsets.hpp",
        "sot_offsets.h", "sot_addresses.txt", "sot_addresses.json",
        "sot_patterns.txt", "sot_sdk.hpp", "sot_sdk.h",
        "sot_dump.json", "sot_classes.hpp", "sot_structs.hpp",
        "seaofthieves_offsets.json", "seaofthieves_offsets.txt",
        "sot_memory_addresses.txt", "sot_pointer_map.json",
    };

    // -------------------------------------------------------------------------
    // SoT-specific cheat config keywords
    // -------------------------------------------------------------------------
    private static readonly string[] SotCheatConfigKeywords =
    {
        "sot_aimbot", "sot_esp", "sot_wallhack", "sot_player_esp",
        "sot_ship_esp", "sot_skeleton_esp", "sot_treasure_esp",
        "sot_loot_esp", "sot_noclip", "sot_godmode", "sot_speedhack",
        "sot_teleport", "sot_speedboat", "sot_fast_sail", "sot_anchor_drop",
        "sot_cannon_hack", "sot_x_ray", "sot_xray", "sot_instant_respawn",
        "player_esp_sot", "ship_esp_sot", "aimbot_sot", "wallhack_sot",
        "esp_sot", "noclip_sot", "godmode_sot", "speedhack_sot",
        "sot_draw_players", "sot_draw_ships", "sot_draw_treasure",
        "sot_draw_skeletons", "sot_draw_animals", "sot_draw_loot",
        "sot_draw_barrels", "sot_draw_chests", "sot_draw_skulls",
        "sot_crew_info", "sot_ship_info", "sot_health_bar",
        "sot_distance_check", "sot_fov_circle", "sot_smooth_aim",
        "sot_aim_key", "sot_esp_key", "sot_menu_key", "sot_panic_key",
        "aimbot_enabled_sot", "esp_enabled_sot", "noclip_enabled_sot",
        "godmode_enabled_sot", "speedhack_enabled_sot",
    };

    // -------------------------------------------------------------------------
    // SoT memory offsets (DMA / external cheat artifact keywords)
    // -------------------------------------------------------------------------
    private static readonly string[] SotOffsetKeywords =
    {
        "LocalPlayer", "PlayerArray", "ShipArray", "TreasureArray",
        "SkeletonArray", "CrewArray", "WorldToScreen", "ViewMatrix",
        "CameraManager", "m_iHealth", "m_vecOrigin", "m_vecLocation",
        "m_pShip", "m_pCrew", "m_pTreasure", "ShipHealth",
        "HullDamage", "IslandList", "FortList", "EventList",
        "AthenaGameMode", "SeaOfThieves", "Athena", "GalleonShip",
        "SloopShip", "BrigantineShip", "SkeletonFort", "FleetBattle",
        "MegShark", "Kraken", "TreasureChest", "SeaPost",
        "m_bIsAlive", "PlayerController", "APlayerState",
        "ActorArray", "GObjects", "GNames", "UWorld",
    };

    // -------------------------------------------------------------------------
    // UserAssist / MUICache keywords for SoT cheats
    // -------------------------------------------------------------------------
    private static readonly string[] SotCheatExecutionKeywords =
    {
        "sot_cheat", "sot_hack", "sot_esp", "sot_aimbot", "sot_loader",
        "sot_injector", "sot_radar", "sot_bypass", "sot_eac", "sotcheat",
        "sothack", "sotesp", "seaofthieves_cheat", "seaofthieves_hack",
        "piratecheat", "cursed_chest", "sot_trainer", "sot_godmode",
        "sot_noclip", "sot_speedhack", "sot_teleport", "sot_mod",
        "treasure_hack", "gold_hack_sot", "sot_wallhack", "sot_xray",
        "sot_internal", "sot_external", "sot_menu", "sot_premium",
    };

    // -------------------------------------------------------------------------
    // Registry Run key keywords for SoT cheats
    // -------------------------------------------------------------------------
    private static readonly string[] SotCheatRunKeywords =
    {
        "sot_cheat", "sot_hack", "sot_esp", "sot_aimbot", "sot_loader",
        "sot_injector", "sot_bypass", "sot_eac", "sotcheat", "sothack",
        "seaofthieves_cheat", "seaofthieves_hack", "piratecheat",
        "sot_trainer", "sot_godmode", "sot_noclip", "sot_radar",
        "sot_speedhack", "sot_teleport", "sot_mod", "sot_menu",
    };

    // -------------------------------------------------------------------------
    // Suspicious content in modified UWP AppxManifest.xml for SoT
    // -------------------------------------------------------------------------
    private static readonly string[] AppxManifestTamperKeywords =
    {
        "runFullTrust", "allowElevation", "uiAccess=\"true\"",
        "SeDebugPrivilege", "allInterfaces", "packagedCOM",
        "virtualApplicationRoot", "entryPoint=\"Windows.FullTrustApplication\"",
        "<rescap:Capability Name=\"runFullTrust\"",
        "broadFileSystemAccess", "unvirtualizedResources",
        "allowedIntents", "FullTrust",
    };

    // -------------------------------------------------------------------------
    // Hosts file block patterns for SoT / EAC / Microsoft Store servers
    // -------------------------------------------------------------------------
    private static readonly string[] SotHostsBlockPatterns =
    {
        "easyanticheat.net", "easyanticheat.io",
        "api.easyanticheat.net", "download.easyanticheat.net",
        "telemetry.easyanticheat.net", "updates.easyanticheat.net",
        "seaofthieves.com", "seaofthieves.microsoft.com",
        "xbox.com", "xboxlive.com", "live.xbox.com",
        "microsoft.com/store", "windowsupdate.com",
        "login.live.com", "auth.xboxlive.com",
        "rare.co.uk", "rareltd.com",
    };

    // -------------------------------------------------------------------------
    // Paths to scan for SoT cheat artifacts
    // -------------------------------------------------------------------------
    private static string[] GetSotScanPaths()
    {
        var localApp    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var temp        = Path.GetTempPath();
        var documents   = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var desktop     = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

        return new[]
        {
            Path.Combine(localApp, "Packages"),
            Path.Combine(localApp, "Temp"),
            Path.Combine(appData, "SeaOfThieves"),
            Path.Combine(appData, "sot"),
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(documents, "Sea of Thieves"),
            Path.Combine(documents, "SeaOfThieves"),
            Path.Combine(documents, "sot"),
            temp,
            desktop,
        };
    }

    // -------------------------------------------------------------------------
    // Get UWP package root directories for Sea of Thieves
    // -------------------------------------------------------------------------
    private static List<string> GetSotUwpPackagePaths()
    {
        var result = new List<string>();
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var packagesRoot = Path.Combine(localApp, "Packages");

        try
        {
            if (!Directory.Exists(packagesRoot)) return result;
            foreach (var dir in Directory.GetDirectories(packagesRoot))
            {
                var name = Path.GetFileName(dir);
                if (name.Contains("SeaOfThieves", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Rare", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("Microsoft.SeaOfThieves", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(dir);
                }
            }
        }
        catch { }

        return result;
    }

    // -------------------------------------------------------------------------
    // ROT13 for UserAssist decoding
    // -------------------------------------------------------------------------
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

    // -------------------------------------------------------------------------
    // Entry point
    // -------------------------------------------------------------------------
    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting Sea of Thieves cheat forensic scan...");

        await Task.WhenAll(
            CheckSotCheatExecutables(ctx, ct),
            CheckSotCheatDlls(ctx, ct),
            CheckEacBypassFiles(ctx, ct),
            CheckSotRadarFiles(ctx, ct),
            CheckSotMemoryToolFiles(ctx, ct),
            CheckUwpBypassFiles(ctx, ct),
            CheckSotOffsetFiles(ctx, ct),
            CheckSotUwpPackageTampering(ctx, ct),
            CheckSotConfigFilesForCheatKeywords(ctx, ct),
            CheckRegistryRunKeys(ctx, ct),
            CheckUserAssistSotCheats(ctx, ct),
            CheckMuiCacheSotCheats(ctx, ct),
            CheckTempFolderSotArtifacts(ctx, ct),
            CheckHostsFileSotBlocking(ctx, ct),
            CheckSotEacServiceRegistry(ctx, ct),
            CheckSotProcesses(ctx, ct)
        );

        ctx.Report(1.0, Name, "Sea of Thieves cheat forensic scan complete.");
    }

    // -------------------------------------------------------------------------
    // Check 1: Known SoT cheat executables across common directories
    // -------------------------------------------------------------------------
    private Task CheckSotCheatExecutables(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var exeSet = SotCheatExecutables.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var searchDirs = GetSotScanPaths();

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!exeSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Sea of Thieves Cheat Executable: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Sea of Thieves cheat executable '{fn}' found. This file is a known cheat " +
                                   "tool targeting Sea of Thieves, providing capabilities such as player ESP, " +
                                   "aimbot, treasure radar, skeleton awareness, or game manipulation functions " +
                                   "that violate Rare's terms of service.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 2: Known SoT cheat DLLs across common directories
    // -------------------------------------------------------------------------
    private Task CheckSotCheatDlls(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var dllSet = SotCheatDlls.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var searchDirs = GetSotScanPaths();

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.dll", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!dllSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Sea of Thieves Cheat DLL: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Sea of Thieves cheat library '{fn}' found. These DLLs are injected " +
                                   "into the SoT game process or used externally to provide ESP overlays, " +
                                   "aimbot functionality, or memory reading for player and treasure locations.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 3: EAC bypass artifacts for Sea of Thieves
    // -------------------------------------------------------------------------
    private Task CheckEacBypassFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var eacSet = SotEacBypassFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EasyAntiCheat"),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);

                    if (eacSet.Contains(fn))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"EAC Bypass Tool for Sea of Thieves: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Known EasyAntiCheat bypass artifact '{fn}' found for Sea of Thieves. " +
                                       "EAC bypass tools disable or circumvent the anti-cheat kernel-mode " +
                                       "protection used by Sea of Thieves, allowing cheat injection and operation " +
                                       "without triggering standard detection mechanisms.",
                            Detail   = $"Full path: {file}"
                        });
                        continue;
                    }

                    // Fuzzy filename match: eac + bypass + sot context
                    var fnLower = fn.ToLowerInvariant();
                    if ((fnLower.Contains("eac") || fnLower.Contains("easyanticheat")) &&
                        (fnLower.Contains("bypass") || fnLower.Contains("patch") ||
                         fnLower.Contains("disable") || fnLower.Contains("hook") ||
                         fnLower.Contains("kill") || fnLower.Contains("inject")) &&
                        (fnLower.Contains("sot") || fnLower.Contains("seaofthieves") || fnLower.Contains("pirate")) &&
                        (fn.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                         fn.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                         fn.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Suspicious EAC Bypass File (SoT): {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"File '{fn}' combines EasyAntiCheat-related, bypass-related, and " +
                                       "Sea of Thieves-related name components. This naming pattern is " +
                                       "characteristic of anti-cheat evasion tools targeting Sea of Thieves.",
                            Detail   = $"Full path: {file}"
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 4: External radar and map ESP tool artifacts for SoT
    // -------------------------------------------------------------------------
    private Task CheckSotRadarFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var radarSet = SotRadarFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!radarSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Sea of Thieves Radar/Map Hack: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Sea of Thieves radar or map hack artifact '{fn}' found. External radar " +
                                   "tools expose the positions of all players, ships, treasure chests, skeletons, " +
                                   "and world events on an external overlay or browser-based map, eliminating " +
                                   "the information asymmetry fundamental to Sea of Thieves gameplay.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 5: SoT process memory reading tool artifacts
    // -------------------------------------------------------------------------
    private Task CheckSotMemoryToolFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var memSet = SotMemoryToolFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!memSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Sea of Thieves Memory Reading Tool: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Sea of Thieves memory reading tool '{fn}' found. These tools read the " +
                                   "SoT game process memory using Windows ReadProcessMemory or DMA hardware " +
                                   "to extract player positions, treasure locations, and game object data " +
                                   "without injection — evading most in-process anti-cheat checks.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 6: Windows Store / UWP bypass artifacts for Sea of Thieves
    // -------------------------------------------------------------------------
    private Task CheckUwpBypassFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var uwpSet = UwpBypassFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!uwpSet.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Windows Store (UWP) Bypass Tool for SoT: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known UWP/Microsoft Store bypass tool '{fn}' found for Sea of Thieves. " +
                                   "Sea of Thieves is a UWP (Universal Windows Platform) application distributed " +
                                   "through the Microsoft Store. UWP bypass tools circumvent AppContainer " +
                                   "sandboxing, code integrity checks, and package signature validation to " +
                                   "enable cheat injection into the protected SoT process.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 7: SoT memory offset / SDK files (DMA / external cheat artifacts)
    // -------------------------------------------------------------------------
    private Task CheckSotOffsetFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var offsetFileSet = SotOffsetFiles.ToHashSet(StringComparer.OrdinalIgnoreCase);

            var searchDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.GetTempPath(),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    // Exact filename match
                    if (offsetFileSet.Contains(fn))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Sea of Thieves Offset File: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Known Sea of Thieves memory offset file '{fn}' found. These files contain " +
                                       "memory addresses and pointer paths used by external or DMA-based SoT " +
                                       "cheat tools to locate game objects such as players, ships, and treasure " +
                                       "without requiring code injection.",
                            Detail   = $"Full path: {file}"
                        });
                        continue;
                    }

                    // Content scan for SoT offset keywords in relevant file types
                    if (ext != ".json" && ext != ".hpp" && ext != ".h" &&
                        ext != ".cpp" && ext != ".txt" && ext != ".ini") continue;

                    bool nameRelevant = fn.Contains("sot", StringComparison.OrdinalIgnoreCase) ||
                                        fn.Contains("seaofthieves", StringComparison.OrdinalIgnoreCase) ||
                                        fn.Contains("offset", StringComparison.OrdinalIgnoreCase) ||
                                        fn.Contains("sdk", StringComparison.OrdinalIgnoreCase) ||
                                        fn.Contains("dump", StringComparison.OrdinalIgnoreCase) ||
                                        fn.Contains("athena", StringComparison.OrdinalIgnoreCase);

                    if (!nameRelevant) continue;

                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hits = SotOffsetKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count >= 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Sea of Thieves Memory Offset / SDK File: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"File '{fn}' contains {hits.Count} Sea of Thieves game memory offset " +
                                       "identifiers. Offset files are used by DMA-based and external SoT " +
                                       "cheats to locate and read player positions, ship states, and world " +
                                       "object data from process memory without requiring code injection.",
                            Detail   = "Offsets found: " + string.Join(", ", hits.Take(8))
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 8: UWP package directory tampering (modified AppxManifest.xml etc.)
    // -------------------------------------------------------------------------
    private Task CheckSotUwpPackageTampering(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var packagePaths = GetSotUwpPackagePaths();
            if (packagePaths.Count == 0) return;

            foreach (var pkgDir in packagePaths)
            {
                if (ct.IsCancellationRequested) return;

                // Look for AppxManifest.xml modifications
                var manifestPath = Path.Combine(pkgDir, "AC", "AppRepository", "AppxManifest.xml");
                var manifestAlt  = Path.Combine(pkgDir, "AppxManifest.xml");

                foreach (var mPath in new[] { manifestPath, manifestAlt })
                {
                    if (!File.Exists(mPath)) continue;
                    if (ct.IsCancellationRequested) return;

                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(mPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hits = AppxManifestTamperKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"SoT UWP AppxManifest Tampering: {Path.GetFileName(mPath)}",
                            Risk     = RiskLevel.High,
                            Location = mPath,
                            FileName = Path.GetFileName(mPath),
                            Reason   = $"Sea of Thieves UWP AppxManifest.xml contains suspicious capability " +
                                       $"declarations: {string.Join(", ", hits)}. Modified manifests can " +
                                       $"grant elevated privileges, full file system access, or disable " +
                                       $"UWP sandboxing to allow cheat injection into the SoT process.",
                            Detail   = "Suspicious declarations: " + string.Join(", ", hits)
                        });
                    }
                }

                // Check for unexpected executables in UWP package sub-directories
                var acLocalState = Path.Combine(pkgDir, "LocalState");
                var acTempState  = Path.Combine(pkgDir, "TempState");

                foreach (var stateDir in new[] { acLocalState, acTempState })
                {
                    if (!Directory.Exists(stateDir)) continue;
                    if (ct.IsCancellationRequested) return;

                    string[] stateFiles;
                    try { stateFiles = Directory.GetFiles(stateDir, "*", SearchOption.AllDirectories); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in stateFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        var fn  = Path.GetFileName(file);
                        var ext = Path.GetExtension(file).ToLowerInvariant();

                        if (ext != ".exe" && ext != ".dll" && ext != ".sys") continue;

                        // Flag executables in UWP local state that match cheat name patterns
                        var fnLower = fn.ToLowerInvariant();
                        if (fnLower.Contains("cheat") || fnLower.Contains("hack") ||
                            fnLower.Contains("bypass") || fnLower.Contains("inject") ||
                            fnLower.Contains("esp") || fnLower.Contains("aimbot") ||
                            fnLower.Contains("radar") || fnLower.Contains("trainer"))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Suspicious Executable in SoT UWP Package: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"Suspicious executable or DLL '{fn}' found inside the Sea of Thieves " +
                                           "UWP package directory '{stateDir}'. Cheat tools may plant modified " +
                                           "binaries in the UWP local state to persist across game launches " +
                                           "and avoid detection in standard file system scans.",
                                Detail   = $"UWP state dir: {stateDir}"
                            });
                        }
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 9: SoT config / save files for cheat configuration keywords
    // -------------------------------------------------------------------------
    private Task CheckSotConfigFilesForCheatKeywords(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var packagePaths = GetSotUwpPackagePaths();
            var localApp     = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            var configDirs = new List<string>
            {
                Path.Combine(appData, "SeaOfThieves"),
                Path.Combine(localApp, "SeaOfThieves"),
                Path.Combine(appData, "sot"),
                Path.Combine(localApp, "sot"),
            };

            foreach (var pkgDir in packagePaths)
            {
                configDirs.Add(Path.Combine(pkgDir, "LocalState"));
                configDirs.Add(Path.Combine(pkgDir, "Settings"));
            }

            foreach (var dir in configDirs)
            {
                if (!Directory.Exists(dir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext != ".cfg" && ext != ".ini" && ext != ".json" &&
                        ext != ".txt" && ext != ".xml" && ext != ".lua" &&
                        ext != ".yaml" && ext != ".yml") continue;

                    string content;
                    try
                    {
                        ctx.IncrementFiles();
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var hits = SotCheatConfigKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (hits.Count >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"SoT Cheat Configuration File: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"Sea of Thieves config file '{Path.GetFileName(file)}' contains " +
                                       $"{hits.Count} cheat-specific configuration keywords. This is highly " +
                                       "indicative of a cheat tool configuration file, storing settings " +
                                       "for ESP, aimbot, noclip, godmode, or other SoT cheats.",
                            Detail   = "Keywords: " + string.Join(", ", hits.Take(8))
                        });
                    }
                    else if (hits.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"SoT Config File Contains Cheat Keyword: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"Sea of Thieves config file '{Path.GetFileName(file)}' contains the " +
                                       $"keyword '{hits[0]}' associated with Sea of Thieves cheat tools.",
                            Detail   = "Matched: " + string.Join(", ", hits)
                        });
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 10: Registry Run keys for SoT cheat loaders
    // -------------------------------------------------------------------------
    private Task CheckRegistryRunKeys(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var runKeys = new[]
            {
                (Registry.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
                (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
            };

            foreach (var (hive, keyPath) in runKeys)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var key = hive.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();
                        var value = key.GetValue(valueName)?.ToString() ?? string.Empty;

                        foreach (var keyword in SotCheatRunKeywords)
                        {
                            if (valueName.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                                value.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"SoT Cheat Autostart Registry Entry: {valueName}",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKLM/HKCU\{keyPath}\{valueName}",
                                    Reason   = $"Registry Run key '{valueName}' references Sea of Thieves " +
                                               $"cheat-related keyword '{keyword}'. This indicates a cheat " +
                                               "tool is configured to launch automatically with Windows, " +
                                               "a persistence technique used by advanced SoT cheat loaders.",
                                    Detail   = $"Value: {value} | Key: {keyPath}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch { }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 11: UserAssist registry records for SoT cheat execution history
    // -------------------------------------------------------------------------
    private Task CheckUserAssistSotCheats(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            const string userAssistBase =
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

            try
            {
                using var baseKey = Registry.CurrentUser.OpenSubKey(userAssistBase, writable: false);
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
                            var decodedLower = decoded.ToLowerInvariant();

                            var hit = SotCheatExecutionKeywords.FirstOrDefault(k =>
                                decodedLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (hit is null) continue;

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
                                Title    = $"SoT Cheat Execution History (UserAssist): {Path.GetFileName(decoded)}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason   = $"UserAssist execution history contains record for Sea of Thieves " +
                                           $"cheat-related executable matching keyword '{hit}'. " +
                                           "UserAssist tracks programs the user has launched, indicating " +
                                           "this cheat tool was actively executed on this machine.",
                                Detail   = $"Decoded: {decoded} | Runs: {runCount} | " +
                                           $"Last: {lastRun?.ToString("u") ?? "unknown"}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 12: MUICache registry for SoT cheat execution artifacts
    // -------------------------------------------------------------------------
    private Task CheckMuiCacheSotCheats(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            const string muiCacheKey =
                @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(muiCacheKey, writable: false);
                if (key is null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    var valueNameLower = valueName.ToLowerInvariant();

                    var hit = SotCheatExecutionKeywords.FirstOrDefault(k =>
                        valueNameLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hit is null) continue;

                    var displayName = key.GetValue(valueName)?.ToString() ?? string.Empty;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"SoT Cheat Execution Artifact (MUICache): {Path.GetFileName(valueName)}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKCU\{muiCacheKey}",
                        FileName = Path.GetFileName(valueName),
                        Reason   = $"MUICache contains an entry for a Sea of Thieves cheat-related " +
                                   $"executable matching keyword '{hit}'. MUICache records the friendly " +
                                   "names of executables that have been run on this machine, providing " +
                                   "forensic evidence of past cheat tool execution.",
                        Detail   = $"Path: {valueName} | Display: {displayName}"
                    });
                }
            }
            catch { }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 13: Temp folder comprehensive scan for SoT cheat artifacts
    // -------------------------------------------------------------------------
    private Task CheckTempFolderSotArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var tempDirs = new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            };

            var allSotCheatFiles = SotCheatExecutables
                .Concat(SotCheatDlls)
                .Concat(SotEacBypassFiles)
                .Concat(SotRadarFiles)
                .Concat(SotMemoryToolFiles)
                .Concat(UwpBypassFiles)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var tempDir in tempDirs)
            {
                if (!Directory.Exists(tempDir)) continue;
                if (ct.IsCancellationRequested) return;

                string[] files;
                try { files = Directory.GetFiles(tempDir, "*.*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (!allSotCheatFiles.Contains(fn)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"SoT Cheat Artifact in Temp Folder: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Known Sea of Thieves cheat artifact '{fn}' found in the system Temp folder. " +
                                   "Cheat tools frequently extract, cache, or stage components in Temp " +
                                   "directories during loading, installation, or between game sessions.",
                        Detail   = $"Temp directory: {tempDir} | Full path: {file}"
                    });
                }

                // Also flag files with SoT-cheat naming patterns not in the explicit list
                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    var fn = Path.GetFileName(file);
                    if (allSotCheatFiles.Contains(fn)) continue;

                    var fnLower = fn.ToLowerInvariant();
                    var ext = Path.GetExtension(fn).ToLowerInvariant();
                    if (ext != ".exe" && ext != ".dll" && ext != ".sys") continue;

                    bool isSotRelated = fnLower.Contains("sot") || fnLower.Contains("seaofthieves") ||
                                        fnLower.Contains("piratecheat") || fnLower.Contains("piratemode");
                    bool isCheatRelated = fnLower.Contains("cheat") || fnLower.Contains("hack") ||
                                          fnLower.Contains("esp") || fnLower.Contains("aimbot") ||
                                          fnLower.Contains("bypass") || fnLower.Contains("inject") ||
                                          fnLower.Contains("radar") || fnLower.Contains("trainer") ||
                                          fnLower.Contains("noclip") || fnLower.Contains("godmode");

                    if (!isSotRelated || !isCheatRelated) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Suspicious SoT-Related Temp File: {fn}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Executable/DLL '{fn}' found in Temp folder combines Sea of Thieves " +
                                   "and cheat-related naming patterns. Temp folder placement is a common " +
                                   "staging behavior for cheat loaders and injectors.",
                        Detail   = $"Full path: {file}"
                    });
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 14: Hosts file entries blocking SoT / Xbox Live / EAC servers
    // -------------------------------------------------------------------------
    private Task CheckHostsFileSotBlocking(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            var hostsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "drivers", "etc", "hosts");

            if (!File.Exists(hostsPath)) return;

            string content;
            try
            {
                ctx.IncrementFiles();
                using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }

            foreach (var pattern in SotHostsBlockPatterns)
            {
                if (ct.IsCancellationRequested) return;
                if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                // Confirm it's an active blocking entry (points to 0.0.0.0 or 127.x.x.x)
                foreach (var line in content.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("#")) continue;
                    if (!trimmed.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    if (trimmed.StartsWith("0.0.0.0") || trimmed.StartsWith("127."))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Hosts File Blocking SoT/EAC Server: {pattern}",
                            Risk     = RiskLevel.High,
                            Location = hostsPath,
                            FileName = "hosts",
                            Reason   = $"The system hosts file contains an active redirect blocking '{pattern}'. " +
                                       "Blocking Sea of Thieves backend servers, Xbox Live authentication, or " +
                                       "EasyAntiCheat update/telemetry endpoints is a known technique used " +
                                       "alongside SoT cheat tools to prevent reporting and ban enforcement.",
                            Detail   = $"Blocking entry: {trimmed.Trim()}"
                        });
                        break;
                    }
                }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 15: EAC service registry state for SoT
    // -------------------------------------------------------------------------
    private Task CheckSotEacServiceRegistry(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var eacServiceKeys = new[]
            {
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat",
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS",
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_SoT",
                @"SYSTEM\CurrentControlSet\Services\EasyAntiCheat_SeaOfThieves",
            };

            foreach (var svcKey in eacServiceKeys)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(svcKey, writable: false);
                    if (key is null) continue;
                    ctx.IncrementRegistryKeys();

                    var start = key.GetValue("Start") as int?;
                    if (start == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"EasyAntiCheat Service Disabled (SoT): {Path.GetFileName(svcKey)}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{svcKey}",
                            Reason   = $"EasyAntiCheat service '{Path.GetFileName(svcKey)}' is set to Start=4 " +
                                       "(disabled). Disabling the EAC service allows Sea of Thieves cheat " +
                                       "tools to run without triggering kernel-mode anti-cheat protections. " +
                                       "Legitimate SoT installations require EAC to be enabled and running.",
                            Detail   = "Start=4 indicates SERVICE_DISABLED in Windows SCM"
                        });
                    }

                    var imagePath = key.GetValue("ImagePath") as string ?? string.Empty;
                    if (!string.IsNullOrEmpty(imagePath))
                    {
                        var fnLower = Path.GetFileName(imagePath).ToLowerInvariant();
                        if (fnLower.Contains("bypass") || fnLower.Contains("patch") ||
                            fnLower.Contains("hook") || fnLower.Contains("disable"))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"EAC Service ImagePath References Bypass Binary (SoT): {Path.GetFileName(imagePath)}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{svcKey}",
                                Reason   = $"EasyAntiCheat service ImagePath points to a potentially modified " +
                                           $"binary '{Path.GetFileName(imagePath)}'. This may indicate the " +
                                           "EAC service binary was replaced with a bypass shim that mimics " +
                                           "legitimate EAC but does not enforce protection for Sea of Thieves.",
                                Detail   = $"ImagePath: {imagePath}"
                            });
                        }
                    }
                }
                catch { }
            }

            // Also check Xbox Game Bar and Windows Store related registry modifications
            var xboxKeys = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR",
                @"SOFTWARE\Microsoft\GameBar",
                @"SYSTEM\CurrentControlSet\Services\XblGameSave",
                @"SYSTEM\CurrentControlSet\Services\XblAuthManager",
            };

            foreach (var xboxKey in xboxKeys)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(xboxKey, writable: false)
                                 ?? Registry.CurrentUser.OpenSubKey(xboxKey, writable: false);
                    if (key is null) continue;
                    ctx.IncrementRegistryKeys();

                    // Check for suspiciously disabled Xbox Live services
                    var start = key.GetValue("Start") as int?;
                    if (start == 4 && xboxKey.Contains("Services", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Xbox Live Service Disabled (SoT Context): {Path.GetFileName(xboxKey)}",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKLM\{xboxKey}",
                            Reason   = $"Xbox Live service '{Path.GetFileName(xboxKey)}' is disabled (Start=4). " +
                                       "Sea of Thieves requires Xbox Live services for authentication and telemetry. " +
                                       "Disabling these services can be part of a cheat setup that attempts to " +
                                       "interfere with ban enforcement and account reporting.",
                            Detail   = "Start=4 indicates SERVICE_DISABLED"
                        });
                    }
                }
                catch { }
            }
        }, ct);
    }

    // -------------------------------------------------------------------------
    // Check 16: Running processes matching known SoT cheat tool names
    // -------------------------------------------------------------------------
    private Task CheckSotProcesses(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            var allCheatProcNames = SotCheatExecutables
                .Concat(SotMemoryToolFiles)
                .Concat(SotRadarFiles.Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)))
                .Select(f => Path.GetFileNameWithoutExtension(f))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var proc in ctx.GetProcessSnapshot())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementProcesses();
                try
                {
                    var pname = proc.ProcessName;
                    if (!allCheatProcNames.Contains(pname)) continue;

                    string procPath = string.Empty;
                    try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"SoT Cheat Process Currently Running: {pname}",
                        Risk     = RiskLevel.Critical,
                        Location = string.IsNullOrEmpty(procPath) ? $"PID {proc.Id}" : procPath,
                        FileName = pname + ".exe",
                        Reason   = $"Known Sea of Thieves cheat process '{pname}' is currently active. " +
                                   "An actively running SoT cheat tool represents an immediate cheating " +
                                   "risk and confirms the cheat software is operational on this machine.",
                        Detail   = $"PID: {proc.Id} | Path: {procPath}"
                    });
                }
                catch { }
            }
        }, ct);
    }
}
