using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class CS2WallhackForensicScanModule : IScanModule
{
    public string Name => "CS2 Wallhack & ESP Cheat Forensic Scan";
    public double Weight => 4.0;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] CS2WallhackExecutables =
    [
        "cs2_wallhack.exe", "cs2_esp.exe", "cs2_wh.exe", "cs2_wall.exe",
        "cs2_visual.exe", "cs2_glow.exe", "cs2_player_esp.exe",
        "cs2_enemy_esp.exe", "cs2_box_esp.exe", "cs2_skeleton_esp.exe",
        "cs2_health_esp.exe", "cs2_weapon_esp.exe", "cs2_bomb_esp.exe",
        "cs2_grenade_esp.exe", "cs2_loot_esp.exe", "cs2_radar_hack.exe",
        "cs2_radar.exe", "cs2_fullbright.exe", "cs2_no_fog.exe",
        "cs2_chams.exe", "cs2_glow_hack.exe", "cs2_model_hack.exe",
        "cs2_render_hack.exe", "cs2_draw_hack.exe", "cs2_xray.exe",
        "cs2_see_through.exe", "cs2_see_enemy.exe", "cs2_through_wall.exe",
        "cs2_through_wall_esp.exe", "wallhack_cs2.exe", "esp_cs2.exe",
        "wh_cs2.exe", "visual_cs2.exe", "glow_cs2.exe",
        "player_esp_cs2.exe", "enemy_esp_cs2.exe", "box_esp_cs2.exe",
        "skeleton_esp_cs2.exe", "health_esp_cs2.exe", "weapon_esp_cs2.exe",
        "radar_hack_cs2.exe", "fullbright_cs2.exe", "chams_cs2.exe",
        "xray_cs2.exe", "cs2_wallhack_v2.exe", "cs2_esp_v2.exe",
        "cs2_wh_v2.exe", "cs2_cheat.exe", "cs2_hack.exe",
        "cs2_visual_hack.exe", "cs2_render.exe", "cs2_draw.exe",
        "cs2_model.exe", "cs2_player_glow.exe", "cs2_enemy_glow.exe",
        "cs2_skeleton.exe", "cs2_box.exe", "cs2_health.exe",
        "cs2_weapon.exe", "cs2_bomb.exe", "cs2_grenade.exe",
        "cs2_loot.exe", "cs2_radar_esp.exe", "cs2_fullbright_v2.exe",
        "cs2_no_fog_v2.exe", "cs2_xray_v2.exe", "cs2_see_through_v2.exe",
        "cs2_loader_wh.exe", "cs2_injector_wh.exe", "cs2_external_wh.exe",
        "cs2_internal_wh.exe", "cs2_aimbot.exe", "cs2_triggerbot.exe",
    ];

    private static readonly string[] CS2WallhackDlls =
    [
        "cs2_wallhack.dll", "cs2_esp.dll", "cs2_wh.dll", "cs2_wall.dll",
        "cs2_visual.dll", "cs2_glow.dll", "cs2_player_esp.dll",
        "cs2_enemy_esp.dll", "cs2_box_esp.dll", "cs2_skeleton_esp.dll",
        "cs2_health_esp.dll", "cs2_weapon_esp.dll", "cs2_bomb_esp.dll",
        "cs2_grenade_esp.dll", "cs2_loot_esp.dll", "cs2_radar_hack.dll",
        "cs2_radar.dll", "cs2_fullbright.dll", "cs2_no_fog.dll",
        "cs2_chams.dll", "cs2_glow_hack.dll", "cs2_model_hack.dll",
        "cs2_render_hack.dll", "cs2_draw_hack.dll", "cs2_xray.dll",
        "cs2_see_through.dll", "cs2_through_wall.dll", "wallhack_cs2.dll",
        "esp_cs2.dll", "wh_cs2.dll", "visual_cs2.dll",
        "glow_cs2.dll", "player_esp_cs2.dll", "enemy_esp_cs2.dll",
        "box_esp_cs2.dll", "skeleton_esp_cs2.dll", "health_esp_cs2.dll",
        "weapon_esp_cs2.dll", "radar_hack_cs2.dll", "fullbright_cs2.dll",
        "chams_cs2.dll", "xray_cs2.dll", "cs2_wallhack_v2.dll",
        "cs2_esp_v2.dll", "cs2_wh_v2.dll", "cs2_cheat.dll",
        "cs2_hack.dll", "cs2_visual_hack.dll", "cs2_render.dll",
        "cs2_model.dll", "cs2_player_glow.dll", "cs2_enemy_glow.dll",
        "cs2_skeleton.dll", "cs2_box.dll", "cs2_health.dll",
        "cs2_weapon.dll", "cs2_bomb.dll",
    ];

    private static readonly string[] CS2WallhackConfigFiles =
    [
        "cs2_wh.cfg", "cs2_esp.cfg", "cs2_wallhack.json",
        "cs2_esp_config.json", "cs2_visual_config.json",
        "cs2_glow_config.json", "cs2_chams.json", "cs2_colors.json",
        "cs2_esp_settings.json", "esp_config.json", "wallhack_config.json",
        "cs2_radar_config.json", "cs2_xray.json", "cs2_bones.json",
        "cs2_skeleton.json", "cs2_healthbar.json", "cs2_fullbright.json",
        "cs2_cheat_config.json", "wh_config.json", "esp_settings.json",
    ];

    private static readonly string[] WallhackConfigKeywords =
    [
        "esp", "wallhack", "glow", "chams", "xray", "radar",
        "bones", "skeleton", "healthbar", "distance", "visible",
        "box_esp", "player_esp", "enemy_esp", "weapon_esp",
        "bomb_esp", "grenade_esp", "fullbright", "no_fog",
        "see_through", "through_wall", "render_enemies",
        "draw_enemies", "player_glow", "enemy_glow",
        "model_hack", "wireframe", "solid_color",
    ];

    private static readonly string[] SuspiciousCfgCommands =
    [
        "sv_cheats 1", "sv_cheats\"1", "sv_cheats 2",
        "cl_drawothermodels 2", "cl_drawothermodels 3",
        "r_drawothermodels 2", "r_drawothermodels 3",
        "mat_wireframe", "r_drawentities", "r_showtris",
        "sv_showlagcompensation", "cl_ent_absbox", "cl_ent_bbox",
        "cl_pdump", "r_drawopaque", "r_drawbrushmodels 0",
        "r_novis", "r_lockpvs", "r_3dsky 0",
        "r_shadowmaxrendered", "ent_fire !self",
        "wallhack", "cheat_on", "bind_cheat",
    ];

    private static readonly string[] CS2BanLogKeywords =
    [
        "you have been banned", "vac ban", "vac authentication error",
        "overwatch ban", "game ban", "trust factor low",
        "trust factor warning", "you are banned",
        "cheating detected", "account banned", "permanent ban",
        "prime status lost", "prime banned", "cooldown applied",
        "competitive cooldown", "suspicious activity",
        "cheat detected", "untrusted ban", "kernel cheat",
    ];

    private static readonly string[] CS2WorkshopSuspiciousFilenames =
    [
        "wallhack", "esp", "wh", "xray", "glow_hack", "chams",
        "see_through", "aimbot", "triggerbot", "radar_hack",
        "cheat", "hack", "bypass", "vac_bypass", "sv_cheats",
        "cs2_cheat", "cs2_hack", "cs2_esp", "cs2_wallhack",
    ];

    private static readonly string[] CS2WallhackDownloadArchives =
    [
        "cs2_wallhack.zip", "cs2_wallhack.rar", "cs2_wallhack.7z",
        "cs2_esp.zip", "cs2_esp.rar", "cs2_esp.7z",
        "cs2_wh.zip", "cs2_wh.rar", "cs2_wh.7z",
        "cs2_visual.zip", "cs2_visual.rar", "cs2_visual.7z",
        "cs2_glow.zip", "cs2_glow.rar", "cs2_glow.7z",
        "cs2_chams.zip", "cs2_chams.rar", "cs2_chams.7z",
        "cs2_xray.zip", "cs2_xray.rar", "cs2_xray.7z",
        "cs2_radar.zip", "cs2_radar.rar", "cs2_radar.7z",
        "cs2_fullbright.zip", "cs2_fullbright.rar", "cs2_fullbright.7z",
        "cs2_no_fog.zip", "cs2_no_fog.rar", "cs2_no_fog.7z",
        "wallhack_cs2.zip", "wallhack_cs2.rar", "wallhack_cs2.7z",
        "esp_cs2.zip", "esp_cs2.rar", "esp_cs2.7z",
        "wh_cs2.zip", "wh_cs2.rar", "wh_cs2.7z",
        "glow_cs2.zip", "glow_cs2.rar", "glow_cs2.7z",
        "chams_cs2.zip", "chams_cs2.rar", "chams_cs2.7z",
        "cs2_player_esp.zip", "cs2_player_esp.rar", "cs2_player_esp.7z",
        "cs2_enemy_esp.zip", "cs2_enemy_esp.rar", "cs2_enemy_esp.7z",
        "cs2_box_esp.zip", "cs2_box_esp.rar", "cs2_box_esp.7z",
        "cs2_skeleton_esp.zip", "cs2_skeleton_esp.rar", "cs2_skeleton_esp.7z",
        "cs2_cheat.zip", "cs2_cheat.rar", "cs2_cheat.7z",
        "cs2_hack.zip", "cs2_hack.rar", "cs2_hack.7z",
        "cs2_loader_wh.zip", "cs2_loader_wh.rar", "cs2_loader_wh.7z",
        "cs2_injector_wh.zip", "cs2_injector_wh.rar", "cs2_injector_wh.7z",
        "cs2_through_wall.zip", "cs2_through_wall.rar", "cs2_through_wall.7z",
        "cs2_see_through.zip", "cs2_see_through.rar", "cs2_see_through.7z",
        "cs2_model_hack.zip", "cs2_model_hack.rar", "cs2_model_hack.7z",
        "cs2_render_hack.zip", "cs2_render_hack.rar", "cs2_render_hack.7z",
        "cs2_external_wh.zip", "cs2_external_wh.rar", "cs2_external_wh.7z",
        "cs2_wallhack_v2.zip", "cs2_wallhack_v2.rar", "cs2_wallhack_v2.7z",
        "cs2_esp_v2.zip", "cs2_esp_v2.rar", "cs2_esp_v2.7z",
        "cs2_aimbot.zip", "cs2_aimbot.rar", "cs2_aimbot.7z",
        "cs2_triggerbot.zip", "cs2_triggerbot.rar", "cs2_triggerbot.7z",
    ];

    private static readonly string[] UserAssistWallhackNames =
    [
        "cs2_wallhack", "cs2_esp", "cs2_wh", "cs2_wall",
        "cs2_visual", "cs2_glow", "cs2_player_esp",
        "cs2_enemy_esp", "cs2_box_esp", "cs2_skeleton_esp",
        "cs2_health_esp", "cs2_weapon_esp", "cs2_bomb_esp",
        "cs2_radar_hack", "cs2_radar", "cs2_fullbright",
        "cs2_no_fog", "cs2_chams", "cs2_glow_hack",
        "cs2_model_hack", "cs2_xray", "cs2_see_through",
        "cs2_through_wall", "wallhack_cs2", "esp_cs2",
        "wh_cs2", "glow_cs2", "chams_cs2", "xray_cs2",
        "cs2_cheat", "cs2_hack", "cs2_loader_wh",
        "cs2_injector_wh", "cs2_external_wh", "cs2_aimbot",
        "cs2_triggerbot", "cs2_wallhack_v2", "cs2_esp_v2",
        "cs2_radar_esp", "cs2_render_hack", "cs2_draw_hack",
        "cs2_loot_esp", "cs2_see_enemy",
    ];

    private static readonly string[] MuiCacheWallhackNames =
    [
        "cs2_wallhack", "cs2_esp", "cs2_wh", "cs2_glow",
        "cs2_player_esp", "cs2_enemy_esp", "cs2_box_esp",
        "cs2_skeleton_esp", "cs2_radar_hack", "cs2_chams",
        "cs2_xray", "cs2_see_through", "cs2_through_wall",
        "wallhack_cs2", "esp_cs2", "wh_cs2", "glow_cs2",
        "chams_cs2", "xray_cs2", "cs2_cheat", "cs2_hack",
        "cs2_loader_wh", "cs2_injector_wh", "cs2_aimbot",
        "cs2_triggerbot", "cs2_wallhack_v2", "cs2_esp_v2",
        "cs2_model_hack", "cs2_render_hack", "cs2_fullbright",
        "cs2_no_fog", "cs2_radar", "cs2_loot_esp",
        "cs2_health_esp", "cs2_weapon_esp", "cs2_bomb_esp",
        "cs2_see_enemy", "cs2_draw_hack", "cs2_visual_hack",
    ];

    private static List<string> BuildCS2ScanPaths()
    {
        var paths = new List<string>();

        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        if (!string.IsNullOrEmpty(desktop)) paths.Add(desktop);

        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        paths.Add(downloads);

        var temp = Path.GetTempPath();
        paths.Add(temp);

        var localTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");
        paths.Add(localTemp);

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (!string.IsNullOrEmpty(appData)) paths.Add(appData);

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrEmpty(localAppData)) paths.Add(localAppData);

        foreach (var drive in new[] { @"C:\", @"D:\", @"E:\", @"F:\" })
        {
            paths.Add(Path.Combine(drive, "CS2"));
            paths.Add(Path.Combine(drive, "Counter-Strike 2"));
            paths.Add(Path.Combine(drive, "Games", "CS2"));
            paths.Add(Path.Combine(drive, "Games", "Counter-Strike 2"));
            paths.Add(Path.Combine(drive, "SteamLibrary", "steamapps", "common", "Counter-Strike Global Offensive"));
            paths.Add(Path.Combine(drive, "SteamLibrary", "steamapps", "common", "cs2"));
        }

        var steamPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Steam", "steamapps", "common", "Counter-Strike Global Offensive");
        paths.Add(steamPath);

        var steam64 = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Steam", "steamapps", "common", "Counter-Strike Global Offensive");
        paths.Add(steam64);

        return paths;
    }

    private static string? TryFindCS2InstallDir()
    {
        try
        {
            using var steamKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Valve\Steam", writable: false)
                ?? Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Valve\Steam", writable: false);

            var steamInstallPath = steamKey?.GetValue("InstallPath") as string;
            if (!string.IsNullOrEmpty(steamInstallPath))
            {
                var cs2Dir = Path.Combine(steamInstallPath, "steamapps", "common", "Counter-Strike Global Offensive");
                if (Directory.Exists(cs2Dir)) return cs2Dir;
                var cs2AltDir = Path.Combine(steamInstallPath, "steamapps", "common", "cs2");
                if (Directory.Exists(cs2AltDir)) return cs2AltDir;
            }
        }
        catch { }

        return null;
    }

    private static string? TryFindSteamInstallDir()
    {
        try
        {
            using var steamKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Valve\Steam", writable: false)
                ?? Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Valve\Steam", writable: false);
            return steamKey?.GetValue("InstallPath") as string;
        }
        catch { return null; }
    }

    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting CS2 wallhack & ESP forensic scan...");

        await Task.WhenAll(
            CheckCS2WallhackExecutables(ctx, ct),
            CheckCS2WallhackDlls(ctx, ct),
            CheckCS2ConfigFiles(ctx, ct),
            CheckCS2GameBanLogs(ctx, ct),
            CheckCS2CustomCfgFiles(ctx, ct),
            CheckCS2WorkshopItems(ctx, ct),
            CheckCS2DownloadArtifacts(ctx, ct),
            CheckRegistryForCS2Wallhack(ctx, ct)
        );

        ctx.Report(1.0, Name, "CS2 wallhack & ESP forensic scan complete.");
    }

    private Task CheckCS2WallhackExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanPaths = BuildCS2ScanPaths();
        var cs2InstallDir = TryFindCS2InstallDir();
        if (!string.IsNullOrEmpty(cs2InstallDir) && !scanPaths.Contains(cs2InstallDir))
            scanPaths.Add(cs2InstallDir);

        foreach (var dir in scanPaths)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.exe", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                var exactMatch = CS2WallhackExecutables.FirstOrDefault(c =>
                    fn.Equals(c, StringComparison.OrdinalIgnoreCase));

                if (exactMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 Wallhack Executable Found: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known CS2 wallhack/ESP cheat executable '{fn}' was found at '{file}'. " +
                                 $"This file matches known CS2 cheat artifact '{exactMatch}'. " +
                                 "This confirms wallhack or ESP cheat software targeting Counter-Strike 2 " +
                                 "was present on this system.",
                        Detail = $"File: {file} | Matched: {exactMatch}"
                    });
                    continue;
                }

                var fnLower = fn.ToLowerInvariant();
                bool hasCS2Ref = fnLower.Contains("cs2") || fnLower.Contains("csgo") ||
                                 fnLower.Contains("counterstrike") || fnLower.Contains("counter_strike") ||
                                 fnLower.Contains("counter-strike");
                bool hasWallhackRef = fnLower.Contains("wallhack") || fnLower.Contains("esp") ||
                                      fnLower.Contains("wh") && fnLower.Contains("cs") ||
                                      fnLower.Contains("glow") || fnLower.Contains("chams") ||
                                      fnLower.Contains("xray") || fnLower.Contains("see_through") ||
                                      fnLower.Contains("through_wall") || fnLower.Contains("radar") ||
                                      fnLower.Contains("fullbright") || fnLower.Contains("skeleton") ||
                                      fnLower.Contains("aimbot") || fnLower.Contains("triggerbot");

                if (hasCS2Ref && hasWallhackRef)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 Suspicious Wallhack/ESP Executable (Heuristic): {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Executable '{fn}' contains both a CS2/CSGO game reference and a wallhack/ESP " +
                                 "cheat keyword. This heuristic pattern strongly indicates cheat software " +
                                 "targeting Counter-Strike 2 with visual cheat capabilities.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckCS2WallhackDlls(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanPaths = BuildCS2ScanPaths();
        var cs2InstallDir = TryFindCS2InstallDir();
        if (!string.IsNullOrEmpty(cs2InstallDir) && !scanPaths.Contains(cs2InstallDir))
            scanPaths.Add(cs2InstallDir);

        foreach (var dir in scanPaths)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                var exactMatch = CS2WallhackDlls.FirstOrDefault(c =>
                    fn.Equals(c, StringComparison.OrdinalIgnoreCase));

                if (exactMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 Wallhack/ESP DLL Found: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known CS2 wallhack/ESP DLL '{fn}' was found at '{file}'. " +
                                 $"This matches known cheat artifact '{exactMatch}'. " +
                                 "CS2 wallhack DLLs are injected into the game process to render player " +
                                 "positions, bones, health, weapons, and other entities through walls.",
                        Detail = $"File: {file} | Matched: {exactMatch}"
                    });
                    continue;
                }

                var fnLower = fn.ToLowerInvariant();
                bool hasCS2Ref = fnLower.Contains("cs2") || fnLower.Contains("csgo") ||
                                 fnLower.Contains("counterstrike");
                bool hasWallhackDllRef = fnLower.Contains("wallhack") || fnLower.Contains("esp") ||
                                         fnLower.Contains("glow") || fnLower.Contains("chams") ||
                                         fnLower.Contains("xray") || fnLower.Contains("radar") ||
                                         fnLower.Contains("fullbright") || fnLower.Contains("skeleton") ||
                                         fnLower.Contains("aimbot") || fnLower.Contains("triggerbot") ||
                                         fnLower.Contains("see_through") || fnLower.Contains("through_wall");

                if (hasCS2Ref && hasWallhackDllRef)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 Suspicious Wallhack/ESP DLL (Heuristic): {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"DLL '{fn}' contains CS2/CSGO references combined with wallhack/ESP cheat keywords. " +
                                 "This heuristic pattern matches CS2 cheat DLLs used for injection-based " +
                                 "wallhacks, ESP overlays, glow hacks, and chams rendering.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckCS2ConfigFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanPaths = BuildCS2ScanPaths();
        var cs2InstallDir = TryFindCS2InstallDir();
        if (!string.IsNullOrEmpty(cs2InstallDir) && !scanPaths.Contains(cs2InstallDir))
            scanPaths.Add(cs2InstallDir);

        foreach (var dir in scanPaths)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            foreach (var configName in CS2WallhackConfigFiles)
            {
                var configPath = Path.Combine(dir, configName);
                if (!File.Exists(configPath)) continue;

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                var matchedKeyword = WallhackConfigKeywords.FirstOrDefault(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (matchedKeyword is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 Wallhack/ESP Config File Found: {configName}",
                        Risk = RiskLevel.Critical,
                        Location = configPath,
                        FileName = configName,
                        Reason = $"CS2 wallhack/ESP cheat configuration file '{configName}' was found at " +
                                 $"'{configPath}' and contains keyword '{matchedKeyword}'. " +
                                 "Wallhack config files store settings for ESP boxes, skeleton rendering, " +
                                 "glow colors, chams materials, radar settings, and other visual cheat features. " +
                                 "Their presence confirms active use of CS2 wallhack/ESP software.",
                        Detail = $"Config: {configPath} | Keyword: {matchedKeyword}"
                    });
                }
                else
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 Wallhack Config File Found (Name Match): {configName}",
                        Risk = RiskLevel.High,
                        Location = configPath,
                        FileName = configName,
                        Reason = $"CS2 wallhack/ESP configuration file '{configName}' found at '{configPath}'. " +
                                 "The filename exactly matches a known CS2 cheat configuration file pattern. " +
                                 "No cheat keywords were detected in the file content, but the file may be " +
                                 "encoded, obfuscated, or use a non-standard configuration format.",
                        Detail = $"Config: {configPath} | Content length: {content.Length}"
                    });
                }
            }

            string[] jsonFiles;
            try { jsonFiles = Directory.GetFiles(dir, "*.json", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var jsonFile in jsonFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fn = Path.GetFileName(jsonFile);
                var fnLower = fn.ToLowerInvariant();

                bool fileIsCheatConfig =
                    CS2WallhackConfigFiles.Any(c => c.Equals(fn, StringComparison.OrdinalIgnoreCase));
                if (fileIsCheatConfig) continue;

                bool hasCS2Ref = fnLower.Contains("cs2") || fnLower.Contains("csgo") || fnLower.Contains("cs_");
                bool hasWallhackRef = fnLower.Contains("wallhack") || fnLower.Contains("esp") ||
                                      fnLower.Contains("glow") || fnLower.Contains("chams") ||
                                      fnLower.Contains("xray") || fnLower.Contains("radar");

                if (!(hasCS2Ref && hasWallhackRef)) continue;

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(jsonFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                var matchedKw = WallhackConfigKeywords.FirstOrDefault(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));
                if (matchedKw is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"CS2 Wallhack Config (Heuristic): {fn}",
                    Risk = RiskLevel.High,
                    Location = jsonFile,
                    FileName = fn,
                    Reason = $"JSON file '{fn}' has CS2/CSGO references in its name and contains wallhack/ESP " +
                             $"keyword '{matchedKw}' in its content. This heuristic matches CS2 cheat " +
                             "configuration files used to configure ESP, glow, chams, and radar settings.",
                    Detail = $"Path: {jsonFile} | Keyword: {matchedKw}"
                });
            }
        }
    }, ct);

    private Task CheckCS2GameBanLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var steamInstallDir = TryFindSteamInstallDir();
        var logDirs = new List<string>();

        if (!string.IsNullOrEmpty(steamInstallDir))
        {
            logDirs.Add(Path.Combine(steamInstallDir, "logs"));

            var userdataDir = Path.Combine(steamInstallDir, "userdata");
            if (Directory.Exists(userdataDir))
            {
                string[] userIdDirs;
                try { userIdDirs = Directory.GetDirectories(userdataDir); }
                catch { userIdDirs = Array.Empty<string>(); }

                foreach (var userDir in userIdDirs)
                {
                    logDirs.Add(Path.Combine(userDir, "730", "remote"));
                    logDirs.Add(Path.Combine(userDir, "730", "local", "cfg"));
                    logDirs.Add(Path.Combine(userDir, "730"));
                }
            }

            var cs2LogDir = Path.Combine(steamInstallDir, "steamapps", "common",
                "Counter-Strike Global Offensive", "game", "csgo", "logs");
            logDirs.Add(cs2LogDir);

            var cs2LogDir2 = Path.Combine(steamInstallDir, "steamapps", "common",
                "Counter-Strike Global Offensive", "game", "core", "logs");
            logDirs.Add(cs2LogDir2);
        }

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        logDirs.Add(Path.Combine(localAppData, "Counter-Strike 2", "Logs"));
        logDirs.Add(Path.Combine(localAppData, "CS2", "Logs"));

        foreach (var logDir in logDirs)
        {
            if (!Directory.Exists(logDir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] logFiles;
            try
            {
                logFiles = Directory.GetFiles(logDir, "*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f).ToLowerInvariant();
                        return ext is ".log" or ".txt" or ".dat";
                    }).ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var logFile in logFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                var fn = Path.GetFileName(logFile);
                foreach (var keyword in CS2BanLogKeywords)
                {
                    if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 Ban/Detection Evidence in Log: {fn}",
                        Risk = RiskLevel.High,
                        Location = logFile,
                        FileName = fn,
                        Reason = $"CS2/Steam log file '{fn}' contains ban/detection keyword '{keyword}'. " +
                                 "Game and Steam logs record VAC ban events, Overwatch case records, trust factor " +
                                 "warnings, and cheat detection notifications. Log entries persist as forensic " +
                                 "evidence even after the cheat software has been removed.",
                        Detail = $"Log: {logFile} | Keyword: {keyword}"
                    });
                    break;
                }
            }
        }

        if (!string.IsNullOrEmpty(steamInstallDir))
        {
            var overwatchDir = Path.Combine(steamInstallDir, "userdata");
            if (Directory.Exists(overwatchDir))
            {
                string[] userDirs;
                try { userDirs = Directory.GetDirectories(overwatchDir); }
                catch { userDirs = Array.Empty<string>(); }

                foreach (var userDir in userDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    var owCaseDir = Path.Combine(userDir, "730", "remote");
                    if (!Directory.Exists(owCaseDir)) continue;

                    string[] owFiles;
                    try { owFiles = Directory.GetFiles(owCaseDir, "overwatch_*.dem"); }
                    catch { owFiles = Array.Empty<string>(); }

                    foreach (var owFile in owFiles)
                    {
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(owFile);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"CS2 Overwatch Case File Found: {fn}",
                            Risk = RiskLevel.Medium,
                            Location = owFile,
                            FileName = fn,
                            Reason = $"CS2 Overwatch case demo file '{fn}' found in Steam userdata. " +
                                     "Overwatch case files are demo recordings flagged by Valve's automated " +
                                     "detection systems for human review. Their presence indicates this account " +
                                     "was suspected of cheating and subjected to Overwatch review. " +
                                     "Wallhack behavior is one of the primary triggers for Overwatch cases.",
                            Detail = $"Path: {owFile}"
                        });
                    }

                    var vacBanFile = Path.Combine(userDir, "730", "remote", "ban_record.txt");
                    if (!File.Exists(vacBanFile)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "CS2 VAC Ban Record File Found",
                        Risk = RiskLevel.High,
                        Location = vacBanFile,
                        FileName = "ban_record.txt",
                        Reason = "A VAC/game ban record file was found in the CS2 Steam userdata directory. " +
                                 "This file is written by Steam when a VAC or game ban is issued and confirms " +
                                 "that this account received a ban on Counter-Strike 2, likely for wallhack " +
                                 "or other cheat software use.",
                        Detail = $"Path: {vacBanFile}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckCS2CustomCfgFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var cs2InstallDir = TryFindCS2InstallDir();
        var cfgDirs = new List<string>();

        if (!string.IsNullOrEmpty(cs2InstallDir))
        {
            cfgDirs.Add(Path.Combine(cs2InstallDir, "game", "csgo", "cfg"));
            cfgDirs.Add(Path.Combine(cs2InstallDir, "game", "core", "cfg"));
            cfgDirs.Add(Path.Combine(cs2InstallDir, "csgo", "cfg"));
        }

        var steamDir = TryFindSteamInstallDir();
        if (!string.IsNullOrEmpty(steamDir))
        {
            var userdataDir = Path.Combine(steamDir, "userdata");
            if (Directory.Exists(userdataDir))
            {
                string[] userIdDirs;
                try { userIdDirs = Directory.GetDirectories(userdataDir); }
                catch { userIdDirs = Array.Empty<string>(); }

                foreach (var userDir in userIdDirs)
                {
                    cfgDirs.Add(Path.Combine(userDir, "730", "local", "cfg"));
                }
            }
        }

        foreach (var cfgDir in cfgDirs)
        {
            if (!Directory.Exists(cfgDir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] cfgFiles;
            try { cfgFiles = Directory.GetFiles(cfgDir, "*.cfg", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var cfgFile in cfgFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(cfgFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                var fn = Path.GetFileName(cfgFile);
                var matchedCmd = SuspiciousCfgCommands.FirstOrDefault(cmd =>
                    content.Contains(cmd, StringComparison.OrdinalIgnoreCase));

                if (matchedCmd is null) continue;

                bool isSvCheats = matchedCmd.Contains("sv_cheats", StringComparison.OrdinalIgnoreCase);
                bool isWireframe = matchedCmd.Contains("wireframe", StringComparison.OrdinalIgnoreCase) ||
                                   matchedCmd.Contains("r_drawother", StringComparison.OrdinalIgnoreCase) ||
                                   matchedCmd.Contains("cl_drawother", StringComparison.OrdinalIgnoreCase);

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"CS2 Cfg Contains Wallhack Console Command: {fn}",
                    Risk = isWireframe ? RiskLevel.Critical : (isSvCheats ? RiskLevel.High : RiskLevel.Medium),
                    Location = cfgFile,
                    FileName = fn,
                    Reason = $"CS2 config file '{fn}' contains suspicious console command '{matchedCmd}'. " +
                             (isWireframe
                                 ? "The r_drawothermodels/cl_drawothermodels command renders all player models " +
                                   "through walls when set to 2 or 3, implementing a built-in wallhack in CS2. "
                                 : isSvCheats
                                     ? "The sv_cheats command enables cheat-protected console variables in CS2. "
                                     : "This console command may enable wallhack or cheat-mode rendering. ") +
                             "Finding this command in a config file confirms it was set to execute automatically, " +
                             "enabling wallhack capabilities without external software.",
                    Detail = $"Config: {cfgFile} | Command: {matchedCmd}"
                });
            }

            var autoexecPath = Path.Combine(cfgDir, "autoexec.cfg");
            if (File.Exists(autoexecPath))
            {
                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(autoexecPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                int suspiciousCmdCount = SuspiciousCfgCommands.Count(cmd =>
                    content.Contains(cmd, StringComparison.OrdinalIgnoreCase));

                if (suspiciousCmdCount >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "CS2 autoexec.cfg Contains Multiple Wallhack Commands",
                        Risk = RiskLevel.Critical,
                        Location = autoexecPath,
                        FileName = "autoexec.cfg",
                        Reason = $"CS2 autoexec.cfg contains {suspiciousCmdCount} suspicious wallhack-enabling " +
                                 "console commands. A high density of cheat-related commands in autoexec.cfg " +
                                 "indicates deliberate configuration of wallhack capabilities via the game's " +
                                 "built-in console command system. This file executes automatically on game start.",
                        Detail = $"Config: {autoexecPath} | Suspicious command count: {suspiciousCmdCount}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckCS2WorkshopItems(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var steamDir = TryFindSteamInstallDir();
        if (string.IsNullOrEmpty(steamDir)) return;

        const string cs2AppId = "730";
        var workshopDir = Path.Combine(steamDir, "steamapps", "workshop", "content", cs2AppId);
        if (!Directory.Exists(workshopDir)) return;

        string[] workshopItems;
        try { workshopItems = Directory.GetDirectories(workshopDir); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var itemDir in workshopItems)
        {
            ct.ThrowIfCancellationRequested();
            var itemId = Path.GetFileName(itemDir);

            string[] allFilesInItem;
            try { allFilesInItem = Directory.GetFiles(itemDir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in allFilesInItem)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);
                var ext = Path.GetExtension(fn).ToLowerInvariant();
                var fnLower = fn.ToLowerInvariant();

                if (ext is ".dll" or ".exe")
                {
                    var suspMatch = CS2WorkshopSuspiciousFilenames.FirstOrDefault(s =>
                        fnLower.Contains(s, StringComparison.OrdinalIgnoreCase));

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious Binary in CS2 Workshop Item: {fn}",
                        Risk = suspMatch is not null ? RiskLevel.Critical : RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"CS2 workshop item {itemId} contains a binary file '{fn}' ({ext}). " +
                                 "Workshop items for CS2 should not contain executable files. " +
                                 (suspMatch is not null
                                     ? $"The filename matches suspicious cheat-related pattern '{suspMatch}'. "
                                     : "") +
                                 "Attackers have distributed cheat loaders through Steam Workshop items " +
                                 "disguised as maps or other content.",
                        Detail = $"Workshop item: {itemId} | File: {file}"
                    });
                    continue;
                }

                if (ext is ".vdf")
                {
                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var suspKw = CS2WorkshopSuspiciousFilenames.FirstOrDefault(s =>
                        content.Contains(s, StringComparison.OrdinalIgnoreCase));
                    if (suspKw is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious VDF in CS2 Workshop Item: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"CS2 workshop item {itemId} VDF file '{fn}' contains suspicious keyword " +
                                 $"'{suspKw}'. Workshop VDF manifests with cheat-related keywords may indicate " +
                                 "the workshop item is a disguised cheat distribution package.",
                        Detail = $"Workshop item: {itemId} | Keyword: {suspKw}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckCS2DownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var downloadDirs = new List<string>
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        foreach (var dir in downloadDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                var exactMatch = CS2WallhackDownloadArchives.FirstOrDefault(a =>
                    fn.Equals(a, StringComparison.OrdinalIgnoreCase));

                if (exactMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 Wallhack Archive Found: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known CS2 wallhack/ESP cheat distribution archive '{fn}' was found in '{dir}'. " +
                                 $"This matches the known cheat package pattern '{exactMatch}'. " +
                                 "The presence of this archive confirms the user downloaded CS2 wallhack " +
                                 "or ESP cheat software from the internet.",
                        Detail = $"Path: {file} | Matched: {exactMatch}"
                    });
                    continue;
                }

                var fnLower = fn.ToLowerInvariant();
                var ext = Path.GetExtension(fn).ToLowerInvariant();
                if (ext is not (".zip" or ".rar" or ".7z" or ".tar" or ".gz")) continue;

                bool hasCS2Ref = fnLower.Contains("cs2") || fnLower.Contains("csgo") ||
                                 fnLower.Contains("counterstrike") || fnLower.Contains("counter_strike");
                bool hasWallhackRef = fnLower.Contains("wallhack") || fnLower.Contains("esp") ||
                                      fnLower.Contains("glow") || fnLower.Contains("chams") ||
                                      fnLower.Contains("xray") || fnLower.Contains("radar") ||
                                      fnLower.Contains("aimbot") || fnLower.Contains("triggerbot") ||
                                      fnLower.Contains("see_through") || fnLower.Contains("through_wall") ||
                                      fnLower.Contains("cheat") || fnLower.Contains("hack");

                if (hasCS2Ref && hasWallhackRef)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious CS2 Wallhack Archive: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Archive file '{fn}' contains both a CS2/CSGO game reference and a " +
                                 "wallhack/ESP/cheat keyword. This heuristic matches known CS2 cheat " +
                                 "package naming conventions used by wallhack and ESP distributors.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckRegistryForCS2Wallhack(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        CheckCS2UserAssist(ctx, ct);
        CheckCS2MuiCache(ctx, ct);
        CheckCS2RunKeys(ctx, ct);
        CheckCS2UninstallKeys(ctx, ct);
    }, ct);

    private void CheckCS2UserAssist(ScanContext ctx, CancellationToken ct)
    {
        const string userAssistBase =
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

        try
        {
            using var baseKey = Registry.CurrentUser.OpenSubKey(userAssistBase, writable: false);
            if (baseKey is null) return;

            foreach (var guidName in baseKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var countKey = baseKey.OpenSubKey($@"{guidName}\Count", writable: false);
                    if (countKey is null) continue;

                    foreach (var encodedName in countKey.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();

                        var decoded = Rot13Decode(encodedName);
                        var decodedLower = decoded.ToLowerInvariant();

                        var keyword = UserAssistWallhackNames.FirstOrDefault(k =>
                            decodedLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (keyword is null) continue;

                        int runCount = 0;
                        DateTime? lastRun = null;
                        try
                        {
                            var data = countKey.GetValue(encodedName) as byte[];
                            if (data is { Length: >= 16 })
                            {
                                runCount = BitConverter.ToInt32(data, 4);
                                var fileTime = BitConverter.ToInt64(data, 8);
                                if (fileTime > 0)
                                    lastRun = DateTime.FromFileTimeUtc(fileTime);
                            }
                        }
                        catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"UserAssist: CS2 Wallhack Tool Executed — {keyword}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason = $"Windows UserAssist forensic record shows execution of a CS2 wallhack/ESP " +
                                     $"tool matching keyword '{keyword}'. Decoded program path: '{decoded}'. " +
                                     $"Execution count: {runCount}. " +
                                     (lastRun.HasValue
                                         ? $"Last executed: {lastRun.Value:yyyy-MM-dd HH:mm} UTC. "
                                         : "") +
                                     "UserAssist entries are maintained by Windows Explorer and survive file " +
                                     "deletion, providing reliable forensic evidence of past cheat execution.",
                            Detail = $"Decoded: {decoded} | Runs: {runCount} | " +
                                     $"Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void CheckCS2MuiCache(ScanContext ctx, CancellationToken ct)
    {
        const string muiCacheKey =
            @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(muiCacheKey, writable: false);
            if (key is null) return;

            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                var path = valueName;
                var dotIdx = valueName.LastIndexOf('.');
                if (dotIdx > 0 && !valueName[dotIdx..].Contains('\\'))
                    path = valueName[..dotIdx];

                var friendlyName = key.GetValue(valueName) as string ?? "";
                var combined = path.ToLowerInvariant() + " " + friendlyName.ToLowerInvariant();

                var keyword = MuiCacheWallhackNames.FirstOrDefault(k =>
                    combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                if (keyword is null) continue;

                bool fileExists = File.Exists(path);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"MuiCache: CS2 Wallhack Tool Previously Executed: {Path.GetFileName(path)}",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{muiCacheKey}",
                    FileName = Path.GetFileName(path),
                    Reason = $"MuiCache forensic entry confirms execution of CS2 wallhack/ESP tool " +
                             $"'{Path.GetFileName(path)}' (keyword match: '{keyword}'). " +
                             (fileExists
                                 ? "The cheat file still exists on disk."
                                 : "The cheat file has been deleted but its execution is confirmed by MuiCache.") +
                             " MuiCache records program execution and persists even after program uninstallation " +
                             "or file deletion.",
                    Detail = $"Path: {path} | FriendlyName: {friendlyName} | Exists: {fileExists} | Matched: {keyword}"
                });
            }
        }
        catch { }
    }

    private void CheckCS2RunKeys(ScanContext ctx, CancellationToken ct)
    {
        var runKeyPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        var roots = new[] { Registry.CurrentUser, Registry.LocalMachine };

        foreach (var root in roots)
        {
            foreach (var keyPath in runKeyPaths)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var key = root.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();

                        var value = (key.GetValue(valueName) as string ?? "").ToLowerInvariant();
                        var nameLower = valueName.ToLowerInvariant();
                        var combined = nameLower + " " + value;

                        var cheatMatch = UserAssistWallhackNames.FirstOrDefault(c =>
                            combined.Contains(c, StringComparison.OrdinalIgnoreCase));

                        if (cheatMatch is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"CS2 Wallhack Loader in Run Key: {valueName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"{(root == Registry.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}\{valueName}",
                                FileName = valueName,
                                Reason = $"Registry Run key '{valueName}' references a known CS2 wallhack/ESP loader " +
                                         $"pattern '{cheatMatch}'. Launch command: '{value}'. " +
                                         "This persistence entry ensures the wallhack tool starts automatically " +
                                         "before or during Counter-Strike 2 gameplay.",
                                Detail = $"Key: {keyPath}\\{valueName} | Value: {value} | Matched: {cheatMatch}"
                            });
                            continue;
                        }

                        bool hasCS2Ref = value.Contains("cs2", StringComparison.OrdinalIgnoreCase) ||
                                         value.Contains("csgo", StringComparison.OrdinalIgnoreCase) ||
                                         value.Contains("counterstrike", StringComparison.OrdinalIgnoreCase);
                        bool hasWallhackRef = value.Contains("wallhack", StringComparison.OrdinalIgnoreCase) ||
                                              value.Contains("esp", StringComparison.OrdinalIgnoreCase) ||
                                              value.Contains("chams", StringComparison.OrdinalIgnoreCase) ||
                                              value.Contains("glow", StringComparison.OrdinalIgnoreCase) ||
                                              value.Contains("xray", StringComparison.OrdinalIgnoreCase) ||
                                              value.Contains("loader", StringComparison.OrdinalIgnoreCase) ||
                                              value.Contains("injector", StringComparison.OrdinalIgnoreCase) ||
                                              value.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                              value.Contains("hack", StringComparison.OrdinalIgnoreCase);

                        if (hasCS2Ref && hasWallhackRef)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious CS2 Wallhack Run Key: {valueName}",
                                Risk = RiskLevel.High,
                                Location = $@"{(root == Registry.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}\{valueName}",
                                FileName = valueName,
                                Reason = $"Registry Run key '{valueName}' references a CS2/CSGO executable combined " +
                                         "with wallhack/ESP/chams/glow/xray/loader/injector/cheat/hack keywords. " +
                                         $"Command: '{value}'. This is a strong indicator of CS2 wallhack persistence.",
                                Detail = $"Value: {value}"
                            });
                        }
                    }
                }
                catch { }
            }
        }
    }

    private void CheckCS2UninstallKeys(ScanContext ctx, CancellationToken ct)
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        var cs2WallhackUninstallKeywords = new[]
        {
            "cs2 wallhack", "cs2 esp", "cs2 wh", "cs2 glow",
            "cs2 chams", "cs2 xray", "cs2 radar", "cs2 aimbot",
            "cs2 triggerbot", "cs2 hack", "cs2 cheat",
            "csgo wallhack", "csgo esp", "csgo wh", "csgo glow",
            "csgo chams", "csgo hack", "csgo cheat",
            "counterstrike wallhack", "counterstrike esp",
            "wallhack cs2", "esp cs2", "wh cs2", "glow cs2",
            "chams cs2", "xray cs2", "radar cs2",
        };

        var roots = new[] { Registry.CurrentUser, Registry.LocalMachine };

        foreach (var root in roots)
        {
            foreach (var uninstPath in uninstallPaths)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var uninstKey = root.OpenSubKey(uninstPath, writable: false);
                    if (uninstKey is null) continue;

                    foreach (var appName in uninstKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var appKey = uninstKey.OpenSubKey(appName, writable: false);
                            if (appKey is null) continue;
                            ctx.IncrementRegistryKeys();

                            var displayName = (appKey.GetValue("DisplayName") as string ?? "").ToLowerInvariant();
                            var publisher = (appKey.GetValue("Publisher") as string ?? "").ToLowerInvariant();
                            var installLoc = (appKey.GetValue("InstallLocation") as string ?? "").ToLowerInvariant();
                            var combined = displayName + " " + publisher + " " + installLoc;

                            var matchedKeyword = cs2WallhackUninstallKeywords.FirstOrDefault(k =>
                                combined.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (matchedKeyword is null) continue;

                            var hiveStr = root == Registry.CurrentUser ? "HKCU" : "HKLM";
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"CS2 Wallhack Software Uninstall Record: {displayName}",
                                Risk = RiskLevel.High,
                                Location = $@"{hiveStr}\{uninstPath}\{appName}",
                                FileName = appName,
                                Reason = $"Windows Uninstall registry entry '{displayName}' (key: '{appName}') " +
                                         $"matches CS2 wallhack/ESP software pattern '{matchedKeyword}'. " +
                                         "This record proves the software was installed on this system. " +
                                         "Uninstall records persist as forensic evidence even after the software " +
                                         "has been removed, confirming prior CS2 wallhack software installation.",
                                Detail = $"DisplayName: {displayName} | Publisher: {publisher} | " +
                                         $"InstallLoc: {installLoc} | Matched: {matchedKeyword}"
                            });
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
    }

    private void CheckCS2VacBypassDriverRegistry(ScanContext ctx, CancellationToken ct)
    {
        var vacBypassDriverNames = new[]
        {
            "vac_bypass.sys", "vac_kill.sys", "vac_disable.sys",
            "steam_bypass.sys", "steamclient_bypass.sys", "cs2_bypass.sys",
            "csgo_bypass.sys", "vac_hook.sys", "vac_patch.sys",
            "cs2_kernel.sys", "vac_spoof.sys", "antivac_bypass.sys",
        };

        var driversDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");

        if (Directory.Exists(driversDir))
        {
            string[] driverFiles;
            try { driverFiles = Directory.GetFiles(driversDir, "*.sys"); }
            catch (UnauthorizedAccessException) { driverFiles = Array.Empty<string>(); }
            catch (IOException) { driverFiles = Array.Empty<string>(); }

            foreach (var file in driverFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);

                var matched = vacBypassDriverNames.FirstOrDefault(d =>
                    fn.Equals(d, StringComparison.OrdinalIgnoreCase));

                if (matched is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 VAC Bypass Driver Found: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known CS2 VAC bypass kernel driver '{fn}' found in the system drivers directory. " +
                                 "This driver is designed to intercept and neutralize Valve Anti-Cheat (VAC) " +
                                 "scanning in Counter-Strike 2, enabling wallhack and other cheat software to " +
                                 "operate undetected at kernel level. Pattern matched: " + matched,
                        Detail = $"Driver path: {file}"
                    });
                }

                var fnLower = fn.ToLowerInvariant();
                bool isVacBypass =
                    (fnLower.Contains("vac") || fnLower.Contains("steam")) &&
                    (fnLower.Contains("bypass") || fnLower.Contains("kill") || fnLower.Contains("disable") ||
                     fnLower.Contains("hook") || fnLower.Contains("patch") || fnLower.Contains("spoof"));
                bool isCS2Driver =
                    (fnLower.Contains("cs2") || fnLower.Contains("csgo")) &&
                    (fnLower.Contains("bypass") || fnLower.Contains("kernel") || fnLower.Contains("cheat") ||
                     fnLower.Contains("driver") || fnLower.Contains("hack"));

                if ((isVacBypass || isCS2Driver) && matched is null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious CS2/VAC-Targeting Driver (Heuristic): {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Kernel driver '{fn}' has a name indicating it targets VAC or CS2 " +
                                 "with bypass/kill/disable/hook operations. VAC bypass drivers operate at " +
                                 "kernel level to intercept VAC's memory scanning before it can detect " +
                                 "wallhack or other cheat DLLs injected into CS2.",
                        Detail = $"Driver: {file}"
                    });
                }
            }
        }

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services", writable: false);
            if (servicesKey is null) return;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                try
                {
                    using var svc = servicesKey.OpenSubKey(svcName, writable: false);
                    if (svc is null) continue;

                    var imgPath = (svc.GetValue("ImagePath") as string ?? "").ToLowerInvariant();
                    var type = svc.GetValue("Type") as int? ?? 0;
                    if (type != 1) continue;

                    var matched = vacBypassDriverNames.FirstOrDefault(d =>
                        imgPath.Contains(d, StringComparison.OrdinalIgnoreCase) ||
                        svcName.Contains(d.Replace(".sys", ""), StringComparison.OrdinalIgnoreCase));

                    if (matched is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 VAC Bypass Driver Service: {svcName}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        FileName = svcName,
                        Reason = $"Kernel driver service '{svcName}' matches a known CS2/VAC bypass driver " +
                                 $"pattern '{matched}'. ImagePath: '{imgPath}'. " +
                                 "This driver-level bypass intercepts VAC scanning before CS2 loads " +
                                 "to prevent detection of wallhack and ESP cheat software.",
                        Detail = $"Service: {svcName} | ImagePath: {imgPath} | Matched: {matched}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }

    private void CheckCS2IFEOHijack(ScanContext ctx, CancellationToken ct)
    {
        const string ifeoBase =
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

        var cs2Binaries = new[]
        {
            "cs2.exe", "csgo.exe", "steamservice.exe",
            "steam.exe", "gameoverlayui.exe", "steamwebhelper.exe",
        };

        foreach (var targetExe in cs2Binaries)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var ifeoKey = Registry.LocalMachine.OpenSubKey(
                    $@"{ifeoBase}\{targetExe}", writable: false);

                if (ifeoKey is null) continue;
                ctx.IncrementRegistryKeys();

                var debugger = ifeoKey.GetValue("Debugger") as string;
                var globalFlag = ifeoKey.GetValue("GlobalFlag") as int?;

                if (!string.IsNullOrEmpty(debugger))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"IFEO Hijack on CS2/Steam Binary: {targetExe}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{ifeoBase}\{targetExe}",
                        FileName = targetExe,
                        Reason = $"Image File Execution Options (IFEO) Debugger key is set for '{targetExe}'. " +
                                 $"Debugger value: '{debugger}'. " +
                                 "This causes Windows to launch the debugger binary instead of the legitimate " +
                                 $"'{targetExe}'. CS2 cheat developers use IFEO to intercept game or Steam " +
                                 "startup and redirect execution to a cheat loader, or to inject a wallhack " +
                                 "DLL before the game process is fully initialized.",
                        Detail = $"Debugger: {debugger} | GlobalFlag: {globalFlag}"
                    });
                }

                if (globalFlag.HasValue && globalFlag.Value != 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"IFEO GlobalFlag Set for CS2 Binary: {targetExe}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{ifeoBase}\{targetExe}",
                        FileName = targetExe,
                        Reason = $"IFEO GlobalFlag is non-zero ({globalFlag}) for '{targetExe}'. " +
                                 "Non-zero GlobalFlag values can interfere with CS2 or VAC process behavior " +
                                 "in ways exploited by cheat tools to prevent VAC scanning or to facilitate " +
                                 "wallhack injection.",
                        Detail = $"GlobalFlag: 0x{globalFlag:X8}"
                    });
                }
            }
            catch { }
        }
    }

    private void CheckCS2SuspiciousDllsInGameDir(ScanContext ctx, CancellationToken ct)
    {
        var cs2InstallDir = TryFindCS2InstallDir();
        if (string.IsNullOrEmpty(cs2InstallDir)) return;

        var cs2BinDirs = new List<string>
        {
            Path.Combine(cs2InstallDir, "game", "bin", "win64"),
            Path.Combine(cs2InstallDir, "game", "csgo", "bin", "win64"),
            Path.Combine(cs2InstallDir, "bin", "win64"),
        };

        var suspiciousProxyDlls = new[]
        {
            "d3d11.dll", "d3d12.dll", "dxgi.dll", "winmm.dll",
            "version.dll", "dinput8.dll", "xinput1_3.dll", "xinput1_4.dll",
            "wsock32.dll", "ws2_32.dll", "opengl32.dll", "d3dcompiler_47.dll",
            "tier0.dll", "vstdlib.dll", "filesystem_stdio.dll",
        };

        foreach (var binDir in cs2BinDirs)
        {
            if (!Directory.Exists(binDir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] dllFiles;
            try { dllFiles = Directory.GetFiles(binDir, "*.dll", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dllFile in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(dllFile);

                var cheatMatch = CS2WallhackDlls.FirstOrDefault(c =>
                    fn.Equals(c, StringComparison.OrdinalIgnoreCase));

                if (cheatMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"CS2 Wallhack DLL in Game Binaries: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = dllFile,
                        FileName = fn,
                        Reason = $"Known CS2 wallhack DLL '{fn}' was found inside the CS2 game binary directory. " +
                                 $"Pattern: '{cheatMatch}'. Cheat tools place DLLs in the game's executable " +
                                 "directory for DLL side-loading or hijacking attacks, allowing the wallhack " +
                                 "to be loaded by CS2 itself without traditional injection.",
                        Detail = $"Path: {dllFile}"
                    });
                    continue;
                }

                var matchedProxy = suspiciousProxyDlls.FirstOrDefault(d =>
                    fn.Equals(d, StringComparison.OrdinalIgnoreCase));

                if (matchedProxy is null) continue;

                try
                {
                    var fi = new FileInfo(dllFile);
                    if (fi.Length < 200 * 1024)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspiciously Small System DLL in CS2 Dir: {fn}",
                            Risk = RiskLevel.High,
                            Location = dllFile,
                            FileName = fn,
                            Reason = $"System DLL '{fn}' found in CS2 game directory is only {fi.Length} bytes. " +
                                     "Legitimate versions of this Windows system DLL are significantly larger. " +
                                     "Cheat tools place small proxy DLLs with system DLL names in the game " +
                                     "directory to intercept CS2's DLL loading and inject wallhack code before " +
                                     "VAC initializes. This is a classic DLL hijacking vector for CS2 cheats.",
                            Detail = $"Path: {dllFile} | Size: {fi.Length} bytes"
                        });
                    }
                }
                catch { }
            }
        }
    }

    private void CheckCS2VacTempArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var tempDirs = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
        };

        var cs2CheatTempPatterns = new[]
        {
            "cs2_wh", "cs2_esp", "cs2_wallhack", "cs2_glow", "cs2_chams",
            "cs2_xray", "cs2_radar", "cs2_aimbot", "cs2_triggerbot",
            "wallhack_cs2", "esp_cs2", "glow_cs2", "chams_cs2",
            "vac_bypass", "steam_bypass", "cs2_loader", "cs2_injector",
            "cs2_cheat", "cs2_hack", "csgo_cheat", "csgo_hack",
            "cs2_bypass", "cs2_external", "cs2_internal",
        };

        foreach (var tempDir in tempDirs)
        {
            if (!Directory.Exists(tempDir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] files;
            try { files = Directory.GetFiles(tempDir, "*", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileName(file);
                var fnLower = fn.ToLowerInvariant();
                var ext = Path.GetExtension(fn).ToLowerInvariant();

                if (ext is not (".exe" or ".dll" or ".sys" or ".dat" or ".log" or ".cfg" or ".ini" or ".zip" or ".rar" or ".7z"))
                    continue;

                var matchedPattern = cs2CheatTempPatterns.FirstOrDefault(p =>
                    fnLower.Contains(p, StringComparison.OrdinalIgnoreCase));

                if (matchedPattern is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"CS2 Wallhack Artifact in Temp Folder: {fn}",
                    Risk = ext is ".exe" or ".dll" or ".sys" ? RiskLevel.High : RiskLevel.Medium,
                    Location = file,
                    FileName = fn,
                    Reason = $"File '{fn}' in the system temp folder contains CS2 wallhack/cheat related " +
                             $"keywords (matched: '{matchedPattern}'). CS2 cheat tools commonly extract and " +
                             "run from temp directories to avoid persistent footprints in standard locations " +
                             "and to complicate forensic attribution. Temp artifacts are particularly " +
                             "common with loader-based wallhack distribution.",
                    Detail = $"Path: {file} | Pattern: {matchedPattern} | Extension: {ext}"
                });
            }
        }
    }
}
