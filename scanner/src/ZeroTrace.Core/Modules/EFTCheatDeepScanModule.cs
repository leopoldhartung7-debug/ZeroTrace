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

public sealed class EFTCheatDeepScanModule : IScanModule
{
    public string Name => "Escape From Tarkov Deep Cheat Forensic Scan";
    public double Weight => 4.0;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] EftCheatExecutables =
    [
        "eft_cheat.exe", "eft_hack.exe", "eft_esp.exe", "eft_aimbot.exe",
        "eft_radar.exe", "eft_wallhack.exe", "eft_norecoil.exe", "eft_nospread.exe",
        "eft_speedhack.exe", "eft_noclip.exe", "eft_teleport.exe", "eft_loot_esp.exe",
        "eft_item_esp.exe", "eft_player_esp.exe", "eft_enemy_esp.exe", "eft_scav_esp.exe",
        "eft_container_esp.exe", "eft_weapon_esp.exe", "eft_extract_esp.exe",
        "eft_map_hack.exe", "eft_map_esp.exe", "eft_full_bright.exe", "eft_no_fog.exe",
        "eft_silent_aim.exe", "eft_magic_bullet.exe", "eft_infinite_stamina.exe",
        "eft_no_fall_damage.exe", "eft_godmode.exe", "eft_infinite_ammo.exe",
        "eft_no_recoil.exe", "eft_no_spread.exe", "eft_unlock_all.exe",
        "eft_skill_hack.exe", "eft_ruble_hack.exe", "eft_money_hack.exe",
        "eft_stash_hack.exe", "tarkov_cheat.exe", "tarkov_hack.exe",
        "tarkov_esp.exe", "tarkov_aimbot.exe", "tarkov_radar.exe",
        "tarkov_wallhack.exe", "tarkov_loot.exe", "tarkov_norecoil.exe",
        "tarkov_nospread.exe", "tarkov_speedhack.exe", "tarkov_noclip.exe",
        "tarkov_teleport.exe", "eft_cheat_v2.exe", "eft_hack_v2.exe",
        "eft_esp_v2.exe", "eft_aimbot_v2.exe", "eft_radar_v2.exe",
        "escape_cheat.exe", "escape_hack.exe", "escape_esp.exe",
        "escape_aimbot.exe", "escape_radar.exe", "eft_loader.exe",
        "eft_injector.exe", "eft_bypass.exe", "eft_bsg_bypass.exe",
        "eft_anti_bypass.exe", "eft_eac_bypass.exe", "eft_bepinex.exe",
        "eft_mono.exe", "eft_unity_cheat.exe", "unity_hack_eft.exe",
        "eft_external.exe", "eft_internal.exe", "eft_trigger.exe",
        "eft_triggerbot.exe", "eft_spinbot.exe", "eft_fov_cheat.exe",
    ];

    private static readonly string[] EftCheatDlls =
    [
        "eft_cheat.dll", "eft_hack.dll", "eft_esp.dll", "eft_aimbot.dll",
        "eft_radar.dll", "eft_wallhack.dll", "eft_norecoil.dll", "eft_nospread.dll",
        "eft_speedhack.dll", "eft_noclip.dll", "eft_loot_esp.dll", "eft_item_esp.dll",
        "eft_player_esp.dll", "eft_enemy_esp.dll", "eft_scav_esp.dll",
        "eft_container_esp.dll", "eft_extract_esp.dll", "eft_map_hack.dll",
        "eft_godmode.dll", "eft_no_recoil.dll", "eft_no_spread.dll",
        "eft_silent_aim.dll", "eft_magic_bullet.dll", "tarkov_cheat.dll",
        "tarkov_hack.dll", "tarkov_esp.dll", "tarkov_aimbot.dll",
        "tarkov_radar.dll", "tarkov_wallhack.dll", "eft_bypass.dll",
        "eft_bsg_bypass.dll", "eft_eac_bypass.dll", "eft_mono_inject.dll",
        "eft_unity_inject.dll", "eft_bepinex_hack.dll",
        "Assembly-CSharp-patched.dll", "Assembly-CSharp-cheat.dll",
        "eft_cheat_v2.dll", "eft_hack_v2.dll", "eft_esp_v2.dll",
        "tarkov_cheat_v2.dll", "tarkov_hack_v2.dll", "eft_loader.dll",
        "eft_injector.dll", "eft_plugin.dll", "eft_mod.dll", "eft_patch.dll",
        "bsg_bypass.dll", "anti_bypass_eft.dll", "eft_unlock.dll",
        "eft_skill.dll", "eft_stash.dll", "eft_money.dll", "eft_ruble.dll",
        "full_bright_eft.dll", "eft_loot_filter.dll", "eft_triggerbot.dll",
        "eft_external.dll", "eft_internal.dll",
    ];

    private static readonly string[] BepInExSuspiciousKeywords =
    [
        "cheat", "hack", "esp", "aimbot", "radar", "wallhack",
        "norecoil", "loot", "godmode", "speedhack", "noclip",
        "teleport", "bypass", "unlock", "stash", "money", "ruble",
        "skill", "trigger", "silent", "magic", "bright", "fog",
    ];

    private static readonly string[] EftCheatConfigFiles =
    [
        "eft_config.json", "eft_settings.json", "eft_cheat.cfg", "eft_hack.cfg",
        "tarkov_config.json", "tarkov_settings.json", "eft_esp_config.json",
        "eft_aimbot_config.json", "eft_radar_config.json", "loot_filter.json",
        "item_esp.json", "player_esp.json", "eft_colors.json",
        "tarkov_loot.json", "eft_bones.json", "eft_fov.json",
        "eft_smooth.json", "eft_radar_config.cfg", "eft_hack_config.cfg",
    ];

    private static readonly string[] ConfigKeywords =
    [
        "fov", "bones", "smooth", "aimbot", "esp", "radar",
        "wallhack", "loot", "cheat", "norecoil", "godmode",
        "speedhack", "noclip", "teleport", "silent", "magic",
        "bright", "fog", "stash", "skill", "ruble", "money",
        "triggerbot", "unlock", "bypass", "bsg", "eac",
    ];

    private static readonly string[] EftOffsetFiles =
    [
        "eft_offsets.txt", "eft_offsets.json", "eft_addresses.txt",
        "eft_patterns.txt", "tarkov_offsets.txt", "tarkov_addresses.txt",
        "memory_offsets.txt", "eft_signatures.txt", "eft_offsets.ini",
        "tarkov_signatures.txt", "eft_sdk.txt", "eft_pointers.txt",
    ];

    private static readonly string[] OffsetKeywords =
    [
        "tarkov", "bsg", "eft", "escape from tarkov",
        "0x", "offset", "address", "pattern", "signature",
        "localplayer", "playercontroller", "world",
    ];

    private static readonly string[] GameLogCheatPatterns =
    [
        "cheat detected", "hack detected", "esp detected",
        "aimbot detected", "wallhack detected", "radar detected",
        "macro detected", "speed hack detected", "noclip detected",
        "bypass detected", "bsg ban", "anti-cheat ban", "eac ban",
        "cheating detected", "suspicious activity", "unauthorized modification",
        "modified game files", "integrity check failed", "memory tampered",
        "game tampered", "client tampered", "injection detected",
        "hook detected", "dll injection", "memory read", "memory write",
        "cheat engine", "godmode active", "teleport detected",
        "speed violation", "loot esp", "radar hack",
        "silent aim", "magic bullet", "no recoil hack",
        "stash hack", "skill hack", "item esp",
        "noclip violation", "fly hack detected", "item dupe",
    ];

    private static readonly string[] EftCheatDownloadArchives =
    [
        "eft_cheat.zip", "eft_cheat.rar", "eft_cheat.7z",
        "eft_hack.zip", "eft_hack.rar", "eft_hack.7z",
        "eft_esp.zip", "eft_esp.rar", "eft_esp.7z",
        "eft_aimbot.zip", "eft_aimbot.rar", "eft_aimbot.7z",
        "eft_radar.zip", "eft_radar.rar", "eft_radar.7z",
        "eft_wallhack.zip", "eft_wallhack.rar", "eft_wallhack.7z",
        "tarkov_cheat.zip", "tarkov_cheat.rar", "tarkov_cheat.7z",
        "tarkov_hack.zip", "tarkov_hack.rar", "tarkov_hack.7z",
        "tarkov_esp.zip", "tarkov_esp.rar", "tarkov_esp.7z",
        "tarkov_aimbot.zip", "tarkov_aimbot.rar", "tarkov_aimbot.7z",
        "tarkov_radar.zip", "tarkov_radar.rar", "tarkov_radar.7z",
        "tarkov_loot.zip", "tarkov_loot.rar", "tarkov_loot.7z",
        "eft_loot_esp.zip", "eft_loot_esp.rar", "eft_loot_esp.7z",
        "eft_bypass.zip", "eft_bypass.rar", "eft_bypass.7z",
        "eac_bypass.zip", "eac_bypass.rar", "eac_bypass.7z",
        "eft_loader.zip", "eft_loader.rar", "eft_loader.7z",
        "eft_injector.zip", "eft_injector.rar", "eft_injector.7z",
        "escape_cheat.zip", "escape_cheat.rar", "escape_cheat.7z",
        "escape_hack.zip", "escape_hack.rar", "escape_hack.7z",
        "escape_esp.zip", "escape_esp.rar", "escape_esp.7z",
        "escape_aimbot.zip", "escape_aimbot.rar", "escape_aimbot.7z",
        "eft_bepinex_hack.zip", "eft_bepinex_hack.rar", "eft_bepinex_hack.7z",
        "eft_unity_cheat.zip", "eft_unity_cheat.rar", "eft_unity_cheat.7z",
        "bsg_bypass.zip", "bsg_bypass.rar", "bsg_bypass.7z",
        "eft_stash_hack.zip", "eft_stash_hack.rar", "eft_stash_hack.7z",
        "eft_skill_hack.zip", "eft_skill_hack.rar", "eft_skill_hack.7z",
        "eft_money_hack.zip", "eft_money_hack.rar", "eft_money_hack.7z",
        "eft_cheat_v2.zip", "eft_cheat_v2.rar", "eft_cheat_v2.7z",
        "tarkov_cheat_v2.zip", "tarkov_cheat_v2.rar", "tarkov_cheat_v2.7z",
        "full_bright_eft.zip", "full_bright_eft.rar", "full_bright_eft.7z",
        "eft_external.zip", "eft_external.rar", "eft_external.7z",
        "eft_internal.zip", "eft_internal.rar", "eft_internal.7z",
        "eft_triggerbot.zip", "eft_triggerbot.rar", "eft_triggerbot.7z",
        "eft_norecoil.zip", "eft_norecoil.rar", "eft_norecoil.7z",
        "tarkov_norecoil.zip", "tarkov_norecoil.rar", "tarkov_norecoil.7z",
    ];

    private static readonly string[] UserAssistCheatNames =
    [
        "eft_cheat", "eft_hack", "eft_esp", "eft_aimbot", "eft_radar",
        "eft_wallhack", "eft_norecoil", "eft_nospread", "eft_speedhack",
        "eft_noclip", "eft_teleport", "eft_loot_esp", "eft_item_esp",
        "eft_player_esp", "eft_enemy_esp", "eft_scav_esp", "eft_container_esp",
        "eft_weapon_esp", "eft_extract_esp", "eft_map_hack", "eft_map_esp",
        "eft_full_bright", "eft_no_fog", "eft_silent_aim", "eft_magic_bullet",
        "eft_godmode", "eft_infinite_ammo", "eft_no_recoil", "eft_no_spread",
        "eft_unlock_all", "eft_skill_hack", "eft_ruble_hack", "eft_money_hack",
        "eft_stash_hack", "tarkov_cheat", "tarkov_hack", "tarkov_esp",
        "tarkov_aimbot", "tarkov_radar", "tarkov_wallhack", "tarkov_loot",
        "escape_cheat", "escape_hack", "eft_loader", "eft_injector",
        "eft_bypass", "eft_bsg_bypass", "eft_eac_bypass", "eft_bepinex",
        "eft_unity_cheat", "unity_hack_eft", "eft_external", "eft_internal",
    ];

    private static readonly string[] MuiCacheCheatNames =
    [
        "eft_cheat", "eft_hack", "eft_esp", "eft_aimbot", "eft_radar",
        "eft_wallhack", "eft_loot_esp", "eft_item_esp", "eft_player_esp",
        "eft_godmode", "eft_teleport", "tarkov_cheat", "tarkov_hack",
        "tarkov_esp", "tarkov_aimbot", "tarkov_radar", "tarkov_loot",
        "escape_cheat", "eft_loader", "eft_injector", "eft_bypass",
        "eft_bsg_bypass", "eft_eac_bypass", "eft_unity_cheat",
        "eft_stash_hack", "eft_skill_hack", "eft_money_hack",
        "eft_norecoil", "eft_no_recoil", "eft_noclip", "eft_speedhack",
        "eft_silent_aim", "eft_magic_bullet", "eft_external", "eft_internal",
        "eft_cheat_v2", "tarkov_cheat_v2", "bsg_bypass",
    ];

    private static readonly string[] EftRegistrySoftwareKeys =
    [
        "EFT Cheat", "EFT Hack", "EFT ESP", "EFT Aimbot", "EFT Radar",
        "Tarkov Cheat", "Tarkov Hack", "Tarkov ESP", "Tarkov Aimbot",
        "Tarkov Radar", "EFT Bypass", "BSG Bypass", "EAC Bypass",
        "EFT Loader", "EFT Injector", "EFT Loot ESP", "EFT Silent Aim",
        "EFT Godmode", "EFT Stash Hack", "EFT Skill Hack",
        "Escape Cheat", "Escape Hack", "Escape ESP",
    ];

    private static readonly string[] EftUninstallKeywords =
    [
        "eft cheat", "eft hack", "eft esp", "eft aimbot", "eft radar",
        "tarkov cheat", "tarkov hack", "tarkov esp", "tarkov aimbot",
        "eft bypass", "bsg bypass", "eac bypass", "eft loader",
        "eft loot esp", "escape cheat", "eft godmode", "eft stash",
        "eft radar hack", "eft silent aim", "unity hack eft",
    ];

    private static List<string> BuildEftScanPaths()
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

        var bsgAppData = Path.Combine(appData, "Battlestate Games");
        paths.Add(bsgAppData);

        var bsgLocalAppData = Path.Combine(localAppData, "Battlestate Games");
        paths.Add(bsgLocalAppData);

        foreach (var drive in new[] { @"C:\", @"D:\", @"E:\", @"F:\" })
        {
            paths.Add(Path.Combine(drive, "EscapeFromTarkov"));
            paths.Add(Path.Combine(drive, "Escape From Tarkov"));
            paths.Add(Path.Combine(drive, "EFT"));
            paths.Add(Path.Combine(drive, "Tarkov"));
            paths.Add(Path.Combine(drive, "Games", "EscapeFromTarkov"));
            paths.Add(Path.Combine(drive, "Games", "Escape From Tarkov"));
            paths.Add(Path.Combine(drive, "Games", "EFT"));
        }

        paths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Battlestate Games"));
        paths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Battlestate Games"));

        return paths;
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
        ctx.Report(0.0, Name, "Starting EFT deep cheat forensic scan...");

        await Task.WhenAll(
            CheckEFTCheatExecutables(ctx, ct),
            CheckEFTCheatDlls(ctx, ct),
            CheckEFTBepInExArtifacts(ctx, ct),
            CheckEFTConfigFiles(ctx, ct),
            CheckEFTOffsetFiles(ctx, ct),
            CheckEFTGameLogForCheats(ctx, ct),
            CheckEFTDownloadArtifacts(ctx, ct),
            CheckRegistryForEFTCheats(ctx, ct)
        );

        ctx.Report(1.0, Name, "EFT deep cheat forensic scan complete.");
    }

    private Task CheckEFTCheatExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanPaths = BuildEftScanPaths();
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

                var exactMatch = EftCheatExecutables.FirstOrDefault(c =>
                    fn.Equals(c, StringComparison.OrdinalIgnoreCase));

                if (exactMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"EFT Cheat Executable Found: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known Escape From Tarkov cheat executable '{fn}' was found at '{file}'. " +
                                 $"This file matches the known EFT cheat artifact '{exactMatch}'. " +
                                 "This confirms cheat software targeting EFT was present on this system.",
                        Detail = $"File: {file} | Matched: {exactMatch}"
                    });
                    continue;
                }

                var fnLower = fn.ToLowerInvariant();
                bool hasEftCheatKeyword =
                    (fnLower.Contains("eft") || fnLower.Contains("tarkov") || fnLower.Contains("escape")) &&
                    (fnLower.Contains("cheat") || fnLower.Contains("hack") || fnLower.Contains("esp") ||
                     fnLower.Contains("aimbot") || fnLower.Contains("radar") || fnLower.Contains("wallhack") ||
                     fnLower.Contains("loot") || fnLower.Contains("bypass") || fnLower.Contains("loader") ||
                     fnLower.Contains("injector") || fnLower.Contains("godmode") || fnLower.Contains("noclip") ||
                     fnLower.Contains("teleport") || fnLower.Contains("norecoil") || fnLower.Contains("triggerbot"));

                if (hasEftCheatKeyword)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"EFT Suspicious Executable (Heuristic): {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Executable '{fn}' contains both an EFT/Tarkov game reference and a cheat-related " +
                                 "keyword in its filename. This is a strong heuristic indicator of cheat software " +
                                 "targeting Escape From Tarkov.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckEFTCheatDlls(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanPaths = BuildEftScanPaths();
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

                var exactMatch = EftCheatDlls.FirstOrDefault(c =>
                    fn.Equals(c, StringComparison.OrdinalIgnoreCase));

                if (exactMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"EFT Cheat DLL Found: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known Escape From Tarkov cheat DLL '{fn}' was found at '{file}'. " +
                                 $"This file matches known cheat artifact '{exactMatch}'. " +
                                 "EFT cheat DLLs are injected into the game process to enable wallhacks, " +
                                 "ESP, aimbot, radar, or bypass EAC/BSG anti-cheat.",
                        Detail = $"File: {file} | Matched: {exactMatch}"
                    });
                    continue;
                }

                var fnLower = fn.ToLowerInvariant();
                bool hasEftDllKeyword =
                    (fnLower.Contains("eft") || fnLower.Contains("tarkov") || fnLower.Contains("bsg") ||
                     fnLower.Contains("escape")) &&
                    (fnLower.Contains("cheat") || fnLower.Contains("hack") || fnLower.Contains("esp") ||
                     fnLower.Contains("aimbot") || fnLower.Contains("radar") || fnLower.Contains("bypass") ||
                     fnLower.Contains("inject") || fnLower.Contains("loot") || fnLower.Contains("godmode") ||
                     fnLower.Contains("norecoil") || fnLower.Contains("wallhack") || fnLower.Contains("loader") ||
                     fnLower.Contains("patch") || fnLower.Contains("plugin"));

                if (hasEftDllKeyword)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"EFT Suspicious DLL (Heuristic): {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"DLL '{fn}' contains Escape From Tarkov game references combined with cheat-related " +
                                 "keywords. This heuristic pattern matches EFT cheat DLLs used for injection, " +
                                 "ESP overlays, bypass, or radar functionality.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckEFTBepInExArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var bepInExSearchRoots = new List<string>();

        var bsgAppData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Battlestate Games");
        bepInExSearchRoots.Add(bsgAppData);

        var bsgLocalAppData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Battlestate Games");
        bepInExSearchRoots.Add(bsgLocalAppData);

        foreach (var drive in new[] { @"C:\", @"D:\", @"E:\", @"F:\" })
        {
            bepInExSearchRoots.Add(Path.Combine(drive, "EscapeFromTarkov"));
            bepInExSearchRoots.Add(Path.Combine(drive, "Escape From Tarkov"));
            bepInExSearchRoots.Add(Path.Combine(drive, "EFT"));
            bepInExSearchRoots.Add(Path.Combine(drive, "Games", "EscapeFromTarkov"));
        }

        bepInExSearchRoots.Add(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Battlestate Games"));
        bepInExSearchRoots.Add(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Battlestate Games"));

        foreach (var root in bepInExSearchRoots)
        {
            if (!Directory.Exists(root)) continue;
            ct.ThrowIfCancellationRequested();

            var bepInExDir = Path.Combine(root, "BepInEx");
            if (!Directory.Exists(bepInExDir)) continue;

            var pluginsDir = Path.Combine(bepInExDir, "plugins");
            if (Directory.Exists(pluginsDir))
            {
                string[] pluginFiles;
                try { pluginFiles = Directory.GetFiles(pluginsDir, "*.dll", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { pluginFiles = Array.Empty<string>(); }
                catch (IOException) { pluginFiles = Array.Empty<string>(); }

                foreach (var pluginFile in pluginFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(pluginFile);
                    var fnLower = fn.ToLowerInvariant();

                    var matchedKeyword = BepInExSuspiciousKeywords.FirstOrDefault(k =>
                        fnLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (matchedKeyword is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious BepInEx Plugin in EFT: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = pluginFile,
                            FileName = fn,
                            Reason = $"BepInEx plugin '{fn}' found in the EFT BepInEx/plugins directory " +
                                     $"contains suspicious keyword '{matchedKeyword}'. " +
                                     "BepInEx is a Unity modding framework. Cheat developers exploit it to " +
                                     "load cheat plugins into Escape From Tarkov bypassing standard injection, " +
                                     "enabling ESP, loot filters, radar, aimbot, and EAC bypass functionality.",
                            Detail = $"Plugin: {pluginFile} | Keyword: {matchedKeyword} | BepInEx root: {bepInExDir}"
                        });
                    }
                }
            }

            var bepInExLogFile = Path.Combine(bepInExDir, "LogOutput.log");
            if (File.Exists(bepInExLogFile))
            {
                ctx.IncrementFiles();
                try
                {
                    string logContent;
                    using var fs = new FileStream(bepInExLogFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    logContent = await sr.ReadToEndAsync(ct);

                    foreach (var keyword in BepInExSuspiciousKeywords)
                    {
                        if (!logContent.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"EFT BepInEx Log Shows Cheat Plugin Loading",
                            Risk = RiskLevel.High,
                            Location = bepInExLogFile,
                            FileName = "LogOutput.log",
                            Reason = $"BepInEx log file for EFT contains suspicious keyword '{keyword}' " +
                                     "consistent with cheat plugin loading. The BepInEx log records all plugin " +
                                     "loads, including cheat mods. Even if the plugins have been deleted, the " +
                                     "log retains forensic evidence of their use.",
                            Detail = $"Log: {bepInExLogFile} | Keyword: {keyword}"
                        });
                        break;
                    }
                }
                catch (IOException) { }
            }

            var bepInExPatchersDir = Path.Combine(bepInExDir, "patchers");
            if (Directory.Exists(bepInExPatchersDir))
            {
                string[] patcherFiles;
                try { patcherFiles = Directory.GetFiles(bepInExPatchersDir, "*.dll", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { patcherFiles = Array.Empty<string>(); }
                catch (IOException) { patcherFiles = Array.Empty<string>(); }

                foreach (var pFile in patcherFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(pFile);
                    var fnLower = fn.ToLowerInvariant();

                    if (fnLower.Contains("assembly-csharp", StringComparison.OrdinalIgnoreCase) ||
                        BepInExSuspiciousKeywords.Any(k => fnLower.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious BepInEx Patcher DLL in EFT: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = pFile,
                            FileName = fn,
                            Reason = $"Suspicious BepInEx patcher DLL '{fn}' found in EFT BepInEx/patchers. " +
                                     "Patcher DLLs run before the game loads and can modify Assembly-CSharp.dll " +
                                     "in memory to inject cheat code directly into the game assembly, bypassing " +
                                     "BSG file integrity checks entirely.",
                            Detail = $"Path: {pFile}"
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckEFTConfigFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanPaths = BuildEftScanPaths();
        foreach (var dir in scanPaths)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            foreach (var configName in EftCheatConfigFiles)
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

                var matchedKeyword = ConfigKeywords.FirstOrDefault(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (matchedKeyword is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"EFT Cheat Config File Found: {configName}",
                        Risk = RiskLevel.Critical,
                        Location = configPath,
                        FileName = configName,
                        Reason = $"Escape From Tarkov cheat configuration file '{configName}' was found at " +
                                 $"'{configPath}' and contains keyword '{matchedKeyword}'. " +
                                 "Cheat configuration files store settings for ESP, aimbot, radar, loot filters " +
                                 "and other cheat features. Their presence confirms active use of cheat software.",
                        Detail = $"Config: {configPath} | Keyword: {matchedKeyword}"
                    });
                }
                else
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"EFT Cheat Config File Found (Name Match): {configName}",
                        Risk = RiskLevel.High,
                        Location = configPath,
                        FileName = configName,
                        Reason = $"Escape From Tarkov cheat configuration file '{configName}' was found at " +
                                 $"'{configPath}'. The filename exactly matches a known EFT cheat configuration " +
                                 "file pattern. No cheat keywords were detected in the content, but the file " +
                                 "may be encoded or the config format may differ.",
                        Detail = $"Config: {configPath} | Content length: {content.Length}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckEFTOffsetFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanPaths = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var dir in scanPaths)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();

            foreach (var offsetFileName in EftOffsetFiles)
            {
                var offsetPath = Path.Combine(dir, offsetFileName);
                if (!File.Exists(offsetPath)) continue;

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(offsetPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                bool hasHexPattern = content.Contains("0x", StringComparison.OrdinalIgnoreCase) ||
                    System.Text.RegularExpressions.Regex.IsMatch(content, @"[0-9A-Fa-f]{4,}");
                bool hasEftKeyword = OffsetKeywords.Any(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (hasHexPattern && hasEftKeyword)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"EFT Cheat Offset/Pattern File Found: {offsetFileName}",
                        Risk = RiskLevel.Critical,
                        Location = offsetPath,
                        FileName = offsetFileName,
                        Reason = $"EFT cheat offset file '{offsetFileName}' was found at '{offsetPath}'. " +
                                 "The file contains hexadecimal memory offsets/addresses along with EFT/Tarkov/BSG " +
                                 "game references. Offset files are used by cheat tools to locate game objects " +
                                 "in memory (players, loot, items) for ESP, radar, and aimbot functionality. " +
                                 "These files are updated with each EFT patch to keep cheats functional.",
                        Detail = $"Path: {offsetPath} | Has hex patterns: {hasHexPattern} | Has EFT keywords: {hasEftKeyword}"
                    });
                }
                else if (hasEftKeyword || hasHexPattern)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious EFT Offset File (Partial Match): {offsetFileName}",
                        Risk = RiskLevel.High,
                        Location = offsetPath,
                        FileName = offsetFileName,
                        Reason = $"File '{offsetFileName}' at '{offsetPath}' matches a known EFT offset filename " +
                                 "pattern and contains some matching content. This may be a cheat offset/pattern " +
                                 "file used to locate EFT game structures in memory.",
                        Detail = $"Path: {offsetPath} | Has hex: {hasHexPattern} | Has EFT ref: {hasEftKeyword}"
                    });
                }
            }

            string[] allFiles;
            try { allFiles = Directory.GetFiles(dir, "*.txt", SearchOption.TopDirectoryOnly); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in allFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fn = Path.GetFileName(file);
                var fnLower = fn.ToLowerInvariant();

                if (!fnLower.Contains("offset") && !fnLower.Contains("address") &&
                    !fnLower.Contains("pattern") && !fnLower.Contains("signature"))
                    continue;

                if (!fnLower.Contains("eft") && !fnLower.Contains("tarkov") &&
                    !fnLower.Contains("bsg") && !fnLower.Contains("escape"))
                    continue;

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                if (content.Contains("0x", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"EFT Memory Offset File (Heuristic): {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Text file '{fn}' has both EFT/Tarkov game references and offset/address/pattern " +
                                 "in its name, and contains hexadecimal values. This matches the profile of an " +
                                 "EFT cheat offset file used to locate game memory structures for cheat purposes.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckEFTGameLogForCheats(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logDirs = new List<string>
        {
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Battlestate Games", "Logs"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Battlestate Games"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Battlestate Games"),
        };

        foreach (var drive in new[] { @"C:\", @"D:\", @"E:\", @"F:\" })
        {
            logDirs.Add(Path.Combine(drive, "EscapeFromTarkov", "Logs"));
            logDirs.Add(Path.Combine(drive, "Escape From Tarkov", "Logs"));
            logDirs.Add(Path.Combine(drive, "EFT", "Logs"));
        }

        foreach (var logDir in logDirs)
        {
            if (!Directory.Exists(logDir)) continue;
            ct.ThrowIfCancellationRequested();

            string[] logFiles;
            try
            {
                logFiles = Directory.GetFiles(logDir, "*.log", SearchOption.AllDirectories);
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
                foreach (var pattern in GameLogCheatPatterns)
                {
                    if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious Pattern in EFT Log: {fn}",
                        Risk = RiskLevel.High,
                        Location = logFile,
                        FileName = fn,
                        Reason = $"EFT game log '{fn}' contains suspicious keyword '{pattern}'. " +
                                 "Game logs may record cheat detection events, anti-cheat ban messages, " +
                                 "integrity check failures, or debug output from cheat tools interfering " +
                                 "with the game. Even if cheats have been removed, log entries persist " +
                                 "as forensic evidence of past cheat activity.",
                        Detail = $"Log: {logFile} | Pattern: {pattern}"
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckEFTDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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

                var exactMatch = EftCheatDownloadArchives.FirstOrDefault(a =>
                    fn.Equals(a, StringComparison.OrdinalIgnoreCase));

                if (exactMatch is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"EFT Cheat Archive Found: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known EFT cheat distribution archive '{fn}' was found in '{dir}'. " +
                                 $"This archive matches the known cheat package pattern '{exactMatch}'. " +
                                 "Cheat archives confirm the user downloaded EFT cheat software from the internet.",
                        Detail = $"Path: {file} | Matched: {exactMatch}"
                    });
                    continue;
                }

                var fnLower = fn.ToLowerInvariant();
                var ext = Path.GetExtension(fn).ToLowerInvariant();
                if (ext is not (".zip" or ".rar" or ".7z" or ".tar" or ".gz")) continue;

                bool hasEftRef = fnLower.Contains("eft") || fnLower.Contains("tarkov") ||
                                 fnLower.Contains("escape") || fnLower.Contains("bsg");
                bool hasCheatRef = fnLower.Contains("cheat") || fnLower.Contains("hack") ||
                                   fnLower.Contains("esp") || fnLower.Contains("aimbot") ||
                                   fnLower.Contains("radar") || fnLower.Contains("wallhack") ||
                                   fnLower.Contains("loot") || fnLower.Contains("bypass") ||
                                   fnLower.Contains("loader") || fnLower.Contains("injector") ||
                                   fnLower.Contains("godmode") || fnLower.Contains("noclip") ||
                                   fnLower.Contains("teleport") || fnLower.Contains("norecoil");

                if (hasEftRef && hasCheatRef)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious EFT Cheat Archive: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Archive file '{fn}' contains both an EFT/Tarkov game reference and a " +
                                 "cheat-related keyword. This heuristic matches known EFT cheat package " +
                                 "naming conventions used by cheat distributors.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckRegistryForEFTCheats(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        CheckEFTUserAssist(ctx, ct);
        CheckEFTMuiCache(ctx, ct);
        CheckEFTRunKeys(ctx, ct);
        CheckEFTSoftwareKeys(ctx, ct);
        CheckEFTUninstallKeys(ctx, ct);
    }, ct);

    private void CheckEFTUserAssist(ScanContext ctx, CancellationToken ct)
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

                        var keyword = UserAssistCheatNames.FirstOrDefault(k =>
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
                            Title = $"UserAssist: EFT Cheat Tool Executed — {keyword}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason = $"Windows UserAssist forensic record shows execution of an EFT cheat tool " +
                                     $"matching keyword '{keyword}'. Decoded program path: '{decoded}'. " +
                                     $"Execution count: {runCount}. " +
                                     (lastRun.HasValue
                                         ? $"Last executed: {lastRun.Value:yyyy-MM-dd HH:mm} UTC. "
                                         : "") +
                                     "UserAssist entries are maintained by Windows Explorer and survive file deletion, " +
                                     "providing reliable forensic evidence of past cheat tool execution.",
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

    private void CheckEFTMuiCache(ScanContext ctx, CancellationToken ct)
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

                var keyword = MuiCacheCheatNames.FirstOrDefault(k =>
                    combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                if (keyword is null) continue;

                bool fileExists = File.Exists(path);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"MuiCache: EFT Cheat Tool Previously Executed: {Path.GetFileName(path)}",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{muiCacheKey}",
                    FileName = Path.GetFileName(path),
                    Reason = $"MuiCache forensic entry confirms execution of EFT cheat tool '{Path.GetFileName(path)}' " +
                             $"(keyword match: '{keyword}'). " +
                             (fileExists
                                 ? "The cheat file still exists on disk."
                                 : "The cheat file has been deleted but its execution is forensically confirmed by MuiCache.") +
                             " MuiCache records program execution and persists even after uninstallation.",
                    Detail = $"Path: {path} | FriendlyName: {friendlyName} | Exists: {fileExists} | Matched: {keyword}"
                });
            }
        }
        catch { }
    }

    private void CheckEFTRunKeys(ScanContext ctx, CancellationToken ct)
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

                        var cheatMatch = UserAssistCheatNames.FirstOrDefault(c =>
                            combined.Contains(c, StringComparison.OrdinalIgnoreCase));

                        if (cheatMatch is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"EFT Cheat Loader in Run Key: {valueName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"{(root == Registry.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}\{valueName}",
                                FileName = valueName,
                                Reason = $"Registry Run key '{valueName}' references a known EFT cheat loader pattern " +
                                         $"'{cheatMatch}'. Launch command: '{value}'. " +
                                         "This persistence entry ensures the cheat tool starts automatically " +
                                         "before or during Escape From Tarkov gameplay.",
                                Detail = $"Key: {keyPath}\\{valueName} | Value: {value} | Matched: {cheatMatch}"
                            });
                            continue;
                        }

                        bool hasEftRef = value.Contains("eft", StringComparison.OrdinalIgnoreCase) ||
                                         value.Contains("tarkov", StringComparison.OrdinalIgnoreCase) ||
                                         value.Contains("bsg", StringComparison.OrdinalIgnoreCase);
                        bool hasCheatRef = value.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                                           value.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                                           value.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                           value.Contains("loader", StringComparison.OrdinalIgnoreCase) ||
                                           value.Contains("injector", StringComparison.OrdinalIgnoreCase) ||
                                           value.Contains("esp", StringComparison.OrdinalIgnoreCase);

                        if (hasEftRef && hasCheatRef)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious EFT Run Key Entry: {valueName}",
                                Risk = RiskLevel.High,
                                Location = $@"{(root == Registry.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}\{valueName}",
                                FileName = valueName,
                                Reason = $"Registry Run key '{valueName}' references an EFT/Tarkov/BSG-related " +
                                         "executable with cheat/hack/bypass/loader/injector/esp keywords. " +
                                         $"Command: '{value}'. This is a strong indicator of EFT cheat persistence.",
                                Detail = $"Value: {value}"
                            });
                        }
                    }
                }
                catch { }
            }
        }
    }

    private void CheckEFTSoftwareKeys(ScanContext ctx, CancellationToken ct)
    {
        var softwareRoots = new[]
        {
            (Registry.CurrentUser, @"SOFTWARE"),
            (Registry.LocalMachine, @"SOFTWARE"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node"),
        };

        foreach (var (hive, softPath) in softwareRoots)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var softKey = hive.OpenSubKey(softPath, writable: false);
                if (softKey is null) continue;

                foreach (var subName in softKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    var subLower = subName.ToLowerInvariant();

                    var matched = EftRegistrySoftwareKeys.FirstOrDefault(k =>
                        subLower.Contains(k.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));

                    if (matched is null) continue;

                    bool hasEftRef = subLower.Contains("eft") || subLower.Contains("tarkov") ||
                                     subLower.Contains("bsg") || subLower.Contains("escape");
                    bool hasCheatRef = subLower.Contains("cheat") || subLower.Contains("hack") ||
                                       subLower.Contains("esp") || subLower.Contains("aimbot") ||
                                       subLower.Contains("bypass") || subLower.Contains("loader") ||
                                       subLower.Contains("radar") || subLower.Contains("loot");

                    if (!hasEftRef && !hasCheatRef) continue;

                    var hiveStr = hive == Registry.CurrentUser ? "HKCU" : "HKLM";
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"EFT Cheat Software Registry Key: {subName}",
                        Risk = RiskLevel.High,
                        Location = $@"{hiveStr}\{softPath}\{subName}",
                        FileName = subName,
                        Reason = $"Registry Software key '{subName}' matches EFT cheat software pattern '{matched}'. " +
                                 "Cheat tools often create registry keys under HKCU/HKLM\\Software for " +
                                 "configuration, licensing, or update persistence. This key confirms installation " +
                                 "of EFT cheat software.",
                        Detail = $"Key: {softPath}\\{subName} | Hive: {hiveStr}"
                    });
                }
            }
            catch { }
        }
    }

    private void CheckEFTUninstallKeys(ScanContext ctx, CancellationToken ct)
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
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

                            var matchedKeyword = EftUninstallKeywords.FirstOrDefault(k =>
                                combined.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (matchedKeyword is null) continue;

                            var hiveStr = root == Registry.CurrentUser ? "HKCU" : "HKLM";
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"EFT Cheat Software Uninstall Record: {displayName}",
                                Risk = RiskLevel.High,
                                Location = $@"{hiveStr}\{uninstPath}\{appName}",
                                FileName = appName,
                                Reason = $"Windows Uninstall registry entry '{displayName}' (key: '{appName}') " +
                                         $"matches EFT cheat software pattern '{matchedKeyword}'. " +
                                         "Uninstall records prove the software was installed even if it has " +
                                         "since been removed. The record persists after uninstallation as " +
                                         "forensic evidence of prior EFT cheat software installation.",
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
}
