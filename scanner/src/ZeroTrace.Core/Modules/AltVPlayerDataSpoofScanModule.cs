using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AltVPlayerDataSpoofScanModule : IScanModule
{
    public string Name => "alt:V Player Data & Stats Spoof Forensic Scan";
    public double Weight => 4.0;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

    private static readonly string[] AltVBaseDirs =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "altv"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "alt-v"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "alt-v"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "alt_v"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "alt_v"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "altv"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "alt-v"),
    ];

    private static readonly string[] PlayerDataSpoofExecutables =
    [
        "altv_stat_spoof.exe",
        "altv_stats_spoof.exe",
        "altv_data_spoof.exe",
        "altv_player_spoof.exe",
        "altv_level_spoof.exe",
        "altv_xp_spoof.exe",
        "altv_score_spoof.exe",
        "altv_rank_spoof.exe",
        "altv_reputation_spoof.exe",
        "altv_skill_spoof.exe",
        "altv_stat_hack.exe",
        "altv_stats_hack.exe",
        "altv_data_hack.exe",
        "altv_player_hack.exe",
        "altv_level_hack.exe",
        "altv_xp_hack.exe",
        "altv_score_hack.exe",
        "altv_rank_hack.exe",
        "altv_reputation_hack.exe",
        "altv_skill_hack.exe",
        "stat_spoof_altv.exe",
        "stats_spoof_altv.exe",
        "data_spoof_altv.exe",
        "player_spoof_altv.exe",
        "level_spoof_altv.exe",
        "xp_spoof_altv.exe",
        "score_spoof_altv.exe",
        "rank_spoof_altv.exe",
        "reputation_spoof_altv.exe",
        "skill_spoof_altv.exe",
        "stat_hack_altv.exe",
        "stats_hack_altv.exe",
        "data_hack_altv.exe",
        "player_hack_altv.exe",
        "level_hack_altv.exe",
        "xp_hack_altv.exe",
        "score_hack_altv.exe",
        "rank_hack_altv.exe",
        "reputation_hack_altv.exe",
        "skill_hack_altv.exe",
        "alt_stat_spoof.exe",
        "alt_data_spoof.exe",
        "alt_player_spoof.exe",
        "alt_level_spoof.exe",
        "alt_rank_spoof.exe",
        "altv_sync_spoof.exe",
        "altv_position_spoof.exe",
        "altv_health_spoof.exe",
        "altv_armor_spoof.exe",
        "altv_weapon_spoof.exe",
        "altv_vehicle_spoof.exe",
        "altv_money_spoof.exe",
        "altv_name_spoof.exe",
        "altv_tag_spoof.exe",
        "altv_ping_spoof.exe",
        "altv_latency_spoof.exe",
        "altv_data_modify.exe",
        "altv_stat_modify.exe",
        "altv_player_modify.exe",
        "altv_data_cheat.exe",
        "altv_stat_cheat.exe",
        "altv_player_cheat.exe",
        "altv_spoof_v2.exe",
        "stat_spoof_v2.exe",
        "data_spoof_v2.exe",
        "player_spoof_v2.exe",
        "altv_spoof_tool.exe",
        "altv_data_editor.exe",
    ];

    private static readonly string[] PlayerDataSpoofDlls =
    [
        "altv_stat_spoof.dll",
        "altv_stats_spoof.dll",
        "altv_data_spoof.dll",
        "altv_player_spoof.dll",
        "altv_level_spoof.dll",
        "altv_xp_spoof.dll",
        "altv_score_spoof.dll",
        "altv_rank_spoof.dll",
        "altv_reputation_spoof.dll",
        "altv_skill_spoof.dll",
        "altv_stat_hack.dll",
        "altv_data_hack.dll",
        "altv_player_hack.dll",
        "stat_spoof_altv.dll",
        "data_spoof_altv.dll",
        "player_spoof_altv.dll",
        "level_spoof_altv.dll",
        "rank_spoof_altv.dll",
        "altv_sync_spoof.dll",
        "altv_position_spoof.dll",
        "altv_health_spoof.dll",
        "altv_armor_spoof.dll",
        "altv_weapon_spoof.dll",
        "altv_vehicle_spoof.dll",
        "altv_money_spoof.dll",
        "altv_name_spoof.dll",
        "altv_ping_spoof.dll",
        "altv_data_modify.dll",
        "altv_stat_modify.dll",
        "altv_player_modify.dll",
        "altv_data_cheat.dll",
        "altv_stat_cheat.dll",
        "altv_player_cheat.dll",
        "altv_spoof_v2.dll",
        "stat_spoof_v2.dll",
        "data_spoof_v2.dll",
        "player_spoof_v2.dll",
        "altv_stat_bypass.dll",
        "altv_data_bypass.dll",
        "altv_spoof_hook.dll",
        "altv_data_hook.dll",
        "stat_bypass_altv.dll",
        "data_bypass_altv.dll",
        "altv_fake_stats.dll",
    ];

    private static readonly string[] PlayerDataSpoofScriptPatterns =
    [
        "alt.Player.local",
        "alt.setStat",
        "alt.setMeta",
        "alt.setLocalMeta",
        "alt.emitServer",
        "setHealth",
        "setArmour",
        "setPosition",
        "setRotation",
        "setVelocity",
        "setWeaponTint",
        "setCurrentWeapon",
        "setStat",
        "setSkillLevel",
        "setLevel",
        "setXP",
        "setScore",
        "setRank",
        "setReputation",
        "setMoney",
        "setSyncedMeta",
        "setStreamSyncedMeta",
        "spoof",
        "fake",
        "modify",
        "hack",
        "cheat",
        "bypass_check",
        "bypass_anticheat",
        "bypass_detection",
        "fake_stat",
        "fake_data",
        "fake_player",
        "fake_level",
        "fake_rank",
        "fake_health",
        "fake_armor",
        "position_spoof",
        "sync_spoof",
        "data_spoof",
        "stat_spoof",
        "player_spoof",
    ];

    private static readonly string[] PlayerDataSpoofClientLogPatterns =
    [
        "stat spoof detected",
        "data spoof detected",
        "player spoof detected",
        "level spoof detected",
        "rank spoof detected",
        "health spoof detected",
        "armor spoof detected",
        "position spoof detected",
        "sync spoof detected",
        "weapon spoof detected",
        "vehicle spoof detected",
        "name spoof detected",
        "money spoof detected",
        "ping spoof detected",
        "anti-cheat: spoof",
        "ac: stat",
        "ac: data",
        "ac: player",
        "ban for stat spoofing",
        "ban for data spoofing",
        "kick for spoofing",
        "suspicious stat value",
        "suspicious data value",
        "suspicious player value",
        "suspicious health",
        "suspicious armor",
        "suspicious position",
        "suspicious sync",
        "sync mismatch",
        "data mismatch",
        "stat mismatch",
        "position mismatch",
        "stat manipulation",
        "data manipulation",
        "player data manipulation",
        "invalid stat",
        "invalid player data",
        "anticheat: stat",
        "anticheat: data",
        "anticheat: player",
        "ban reason: spoof",
        "kick reason: spoof",
        "detected spoof",
        "spoof detected",
        "fake stat detected",
    ];

    private static readonly string[] PlayerDataSpoofServerLogPatterns =
    [
        "stat spoof detected",
        "data spoof detected",
        "player spoof detected",
        "level spoof detected",
        "rank spoof detected",
        "health spoof detected",
        "armor spoof detected",
        "position spoof detected",
        "sync spoof detected",
        "weapon spoof detected",
        "vehicle spoof detected",
        "name spoof detected",
        "money spoof detected",
        "ping spoof detected",
        "suspicious stat value",
        "suspicious data value",
        "suspicious player value",
        "suspicious health value",
        "suspicious armor value",
        "suspicious position value",
        "sync mismatch",
        "data mismatch",
        "stat mismatch",
        "position mismatch",
        "stat manipulation",
        "data manipulation",
        "player data manipulation",
        "invalid stat",
        "invalid player data",
        "ban for stat spoofing",
        "ban for data spoofing",
        "kick for spoofing",
        "ban reason: spoof",
        "kick reason: spoof",
        "detected spoof",
        "spoof detected",
        "fake stat detected",
        "fake data detected",
        "fake player detected",
        "fake level detected",
        "fake rank detected",
        "fake health detected",
        "illegal stat modification",
        "illegal data modification",
        "unauthorized stat change",
        "unauthorized data change",
    ];

    private static readonly string[] PlayerDataSpoofResourceFolderNames =
    [
        "stat-spoof",
        "stat_spoof",
        "stats-spoof",
        "stats_spoof",
        "data-spoof",
        "data_spoof",
        "player-spoof",
        "player_spoof",
        "level-spoof",
        "level_spoof",
        "xp-spoof",
        "xp_spoof",
        "score-spoof",
        "score_spoof",
        "rank-spoof",
        "rank_spoof",
        "reputation-spoof",
        "reputation_spoof",
        "skill-spoof",
        "skill_spoof",
        "stat-hack",
        "stat_hack",
        "data-hack",
        "data_hack",
        "player-hack",
        "player_hack",
        "sync-spoof",
        "sync_spoof",
        "position-spoof",
        "position_spoof",
        "health-spoof",
        "health_spoof",
        "armor-spoof",
        "armor_spoof",
        "weapon-spoof",
        "weapon_spoof",
        "vehicle-spoof",
        "vehicle_spoof",
        "money-spoof",
        "money_spoof",
        "name-spoof",
        "name_spoof",
        "ping-spoof",
        "ping_spoof",
        "data-modify",
        "data_modify",
        "stat-modify",
        "stat_modify",
        "fake-stats",
        "fake_stats",
    ];

    private static readonly string[] PlayerDataSpoofDownloadArtifacts =
    [
        "altv_stat_spoof.zip",
        "altv_stat_spoof.rar",
        "altv_stat_spoof.7z",
        "altv_stats_spoof.zip",
        "altv_stats_spoof.rar",
        "altv_data_spoof.zip",
        "altv_data_spoof.rar",
        "altv_data_spoof.7z",
        "altv_player_spoof.zip",
        "altv_player_spoof.rar",
        "altv_level_spoof.zip",
        "altv_level_spoof.rar",
        "altv_rank_spoof.zip",
        "altv_rank_spoof.rar",
        "altv_xp_spoof.zip",
        "altv_xp_spoof.rar",
        "altv_score_spoof.zip",
        "altv_score_spoof.rar",
        "altv_reputation_spoof.zip",
        "altv_skill_spoof.zip",
        "stat_spoof_altv.zip",
        "stat_spoof_altv.rar",
        "data_spoof_altv.zip",
        "data_spoof_altv.rar",
        "player_spoof_altv.zip",
        "player_spoof_altv.rar",
        "altv_sync_spoof.zip",
        "altv_sync_spoof.rar",
        "altv_health_spoof.zip",
        "altv_armor_spoof.zip",
        "altv_position_spoof.zip",
        "altv_money_spoof.zip",
        "altv_money_spoof.rar",
        "altv_stat_spoof_setup.exe",
        "altv_data_spoof_setup.exe",
        "altv_player_spoof_setup.exe",
        "altv_stats_hack_setup.exe",
        "altv_spoof_v2.zip",
        "altv_spoof_v2.rar",
        "stat_spoof_v2.zip",
        "stat_spoof_v2.rar",
        "data_spoof_v2.zip",
        "data_spoof_v2.rar",
        "altv_stat_cheat.zip",
        "altv_stat_cheat.rar",
        "altv_data_cheat.zip",
        "altv_player_cheat.zip",
        "altv_spoof_tool.zip",
        "altv_spoof_tool.rar",
    ];

    private static readonly string[] PlayerDataSpoofUserAssistNames =
    [
        "altv_stat_spoof",
        "altv_stats_spoof",
        "altv_data_spoof",
        "altv_player_spoof",
        "altv_level_spoof",
        "altv_xp_spoof",
        "altv_score_spoof",
        "altv_rank_spoof",
        "altv_reputation_spoof",
        "altv_skill_spoof",
        "altv_stat_hack",
        "altv_data_hack",
        "altv_player_hack",
        "stat_spoof_altv",
        "data_spoof_altv",
        "player_spoof_altv",
        "altv_sync_spoof",
        "altv_position_spoof",
        "altv_health_spoof",
        "altv_armor_spoof",
        "altv_money_spoof",
        "altv_name_spoof",
        "altv_ping_spoof",
        "altv_data_modify",
        "altv_stat_modify",
        "altv_player_modify",
        "altv_data_cheat",
        "altv_stat_cheat",
        "altv_player_cheat",
        "altv_spoof_v2",
        "stat_spoof_v2",
        "data_spoof_v2",
        "player_spoof_v2",
        "altv_spoof_tool",
        "altv_data_editor",
    ];

    private static readonly string[] PlayerDataSpoofConfigFiles =
    [
        "altv_stat_spoof_config.json",
        "altv_stats_spoof_config.json",
        "altv_data_spoof_config.json",
        "altv_player_spoof_config.json",
        "altv_level_spoof_config.json",
        "altv_rank_spoof_config.json",
        "altv_spoof_settings.json",
        "altv_stat_hack_config.json",
        "altv_data_hack_config.json",
        "altv_player_hack_config.json",
        "stat_spoof_altv_config.json",
        "data_spoof_altv_config.json",
        "altv_sync_spoof_config.json",
        "altv_health_spoof_config.json",
        "altv_armor_spoof_config.json",
        "altv_position_spoof_config.json",
        "altv_money_spoof_config.json",
        "altv_name_spoof_config.json",
        "altv_ping_spoof_config.json",
        "altv_stat_offsets.json",
        "altv_stat_offsets.txt",
        "altv_data_offsets.json",
        "altv_data_offsets.txt",
        "altv_player_offsets.json",
        "altv_player_offsets.txt",
        "altv_stat_addresses.txt",
        "altv_data_addresses.txt",
        "altv_fake_stats.json",
        "altv_fake_data.json",
        "altv_spoof_v2_config.json",
    ];

    private static readonly string[] PlayerDataSpoofRecentDocPatterns =
    [
        "altv_stat_spoof",
        "altv_stats_spoof",
        "altv_data_spoof",
        "altv_player_spoof",
        "altv_level_spoof",
        "altv_rank_spoof",
        "altv_xp_spoof",
        "altv_score_spoof",
        "stat_spoof_altv",
        "data_spoof_altv",
        "player_spoof_altv",
        "altv_sync_spoof",
        "altv_health_spoof",
        "altv_armor_spoof",
        "altv_money_spoof",
        "altv_name_spoof",
        "altv_ping_spoof",
        "altv_stat_hack",
        "altv_data_hack",
        "altv_spoof_v2",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckPlayerDataSpoofExecutables(ctx, ct),
            CheckPlayerDataSpoofDlls(ctx, ct),
            CheckPlayerDataSpoofScriptFiles(ctx, ct),
            CheckPlayerDataSpoofClientLogs(ctx, ct),
            CheckPlayerDataSpoofServerLogs(ctx, ct),
            CheckPlayerDataSpoofResourceFolders(ctx, ct),
            CheckPlayerDataSpoofDownloadArtifacts(ctx, ct),
            CheckRegistryForPlayerDataSpoof(ctx, ct),
            CheckPlayerDataSpoofConfigFiles(ctx, ct),
            CheckPlayerDataSpoofCacheArtifacts(ctx, ct),
            CheckPlayerDataSpoofRecentDocuments(ctx, ct)
        );
    }

    private Task CheckPlayerDataSpoofExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(AltVBaseDirs)
        {
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(LocalAppData, "Temp"),
            AppData,
            LocalAppData,
            Path.Combine(UserProfile, "Documents"),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (PlayerDataSpoofExecutables.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V player data/stats spoof executable detected",
                            Risk = RiskLevel.Critical,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known alt:V player data/stats spoof executable '{fn}' found on disk. These tools manipulate player statistics, experience points, levels, ranks, health, armor, position, and other synchronized player data in the alt:V multiplayer framework for GTA:V to gain unfair advantages.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckPlayerDataSpoofDlls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(AltVBaseDirs)
        {
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(LocalAppData, "Temp"),
            AppData,
            LocalAppData,
            Path.Combine(UserProfile, "Documents"),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (PlayerDataSpoofDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V player data/stats spoof DLL detected",
                            Risk = RiskLevel.Critical,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known alt:V player data/stats spoof DLL '{fn}' found on disk. Spoof DLLs are injected into the alt:V process or GTA:V to hook stat and data synchronization functions, enabling manipulation of player levels, health, position, and other server-validated values.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckPlayerDataSpoofScriptFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var altVDir in AltVBaseDirs)
        {
            var resourcesDir = Path.Combine(altVDir, "resources");
            var clientPackagesDir = Path.Combine(altVDir, "client_packages");

            foreach (var searchRoot in new[] { resourcesDir, clientPackagesDir })
            {
                if (!Directory.Exists(searchRoot)) continue;
                try
                {
                    var scriptFiles = Directory.EnumerateFiles(searchRoot, "*.js", SearchOption.AllDirectories)
                        .Concat(Directory.EnumerateFiles(searchRoot, "*.mjs", SearchOption.AllDirectories))
                        .Concat(Directory.EnumerateFiles(searchRoot, "*.cjs", SearchOption.AllDirectories))
                        .Concat(Directory.EnumerateFiles(searchRoot, "*.ts", SearchOption.AllDirectories));

                    foreach (var scriptFile in scriptFiles)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            int hits = 0;
                            string firstMatch = string.Empty;
                            foreach (var pattern in PlayerDataSpoofScriptPatterns)
                            {
                                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                {
                                    hits++;
                                    if (firstMatch.Length == 0) firstMatch = pattern;
                                }
                            }
                            if (hits >= 4)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "alt:V resource script with player data spoof patterns",
                                    Risk = RiskLevel.Critical,
                                    Location = Path.GetDirectoryName(scriptFile) ?? searchRoot,
                                    FileName = Path.GetFileName(scriptFile),
                                    Reason = $"alt:V resource script file contains {hits} player data/stats spoof-related patterns (first match: '{firstMatch}'). Scripts loaded into the alt:V client can manipulate synchronized player data including stats, health, position, rank, and level by abusing the alt:V JavaScript API.",
                                    Detail = $"File: {scriptFile}, pattern hits: {hits}, first match: '{firstMatch}'"
                                });
                            }
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }

        var altVInstallDirs = new[]
        {
            @"C:\Program Files\altv",
            @"C:\Program Files (x86)\altv",
            @"C:\altv",
            Path.Combine(UserProfile, "altv"),
        };

        foreach (var installDir in altVInstallDirs)
        {
            var resourcesDir = Path.Combine(installDir, "resources");
            if (!Directory.Exists(resourcesDir)) continue;
            try
            {
                var scriptFiles = Directory.EnumerateFiles(resourcesDir, "*.js", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(resourcesDir, "*.mjs", SearchOption.AllDirectories))
                    .Concat(Directory.EnumerateFiles(resourcesDir, "*.cjs", SearchOption.AllDirectories))
                    .Concat(Directory.EnumerateFiles(resourcesDir, "*.ts", SearchOption.AllDirectories));

                foreach (var scriptFile in scriptFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        int hits = 0;
                        string firstMatch = string.Empty;
                        foreach (var pattern in PlayerDataSpoofScriptPatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                hits++;
                                if (firstMatch.Length == 0) firstMatch = pattern;
                            }
                        }
                        if (hits >= 4)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V install resource script with player data spoof patterns",
                                Risk = RiskLevel.Critical,
                                Location = Path.GetDirectoryName(scriptFile) ?? resourcesDir,
                                FileName = Path.GetFileName(scriptFile),
                                Reason = $"alt:V installed resource script file contains {hits} player data/stats spoof-related patterns (first match: '{firstMatch}'). This script was found inside an alt:V installation directory and may be a cheat resource loaded automatically by the client.",
                                Detail = $"File: {scriptFile}, pattern hits: {hits}, first match: '{firstMatch}'"
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckPlayerDataSpoofClientLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var allLogDirs = new List<string>(AltVBaseDirs);
        allLogDirs.AddRange(new[]
        {
            Path.Combine(AppData, "altv"),
            Path.Combine(LocalAppData, "altv"),
            Path.Combine(AppData, "alt-v"),
            Path.Combine(LocalAppData, "alt-v"),
        });

        foreach (var altVDir in allLogDirs)
        {
            if (!Directory.Exists(altVDir)) continue;
            try
            {
                var logFiles = Directory.EnumerateFiles(altVDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(altVDir, "*.txt", SearchOption.AllDirectories));

                foreach (var logFile in logFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        foreach (var pattern in PlayerDataSpoofClientLogPatterns)
                        {
                            if (lower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "alt:V client log: player data spoof artifact",
                                    Risk = RiskLevel.High,
                                    Location = Path.GetDirectoryName(logFile) ?? altVDir,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"alt:V client log contains player data/stats spoof pattern: '{pattern}'. Client logs may record spoof tool startup messages, stat manipulation confirmations, anticheat responses to spoofing attempts, or ban/kick notifications related to data spoofing.",
                                    Detail = $"Log file: {logFile}, matched pattern: '{pattern}'"
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckPlayerDataSpoofServerLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var serverLogDirs = new[]
        {
            Path.Combine(UserProfile, "altv-server", "logs"),
            Path.Combine(UserProfile, "alt-v-server", "logs"),
            Path.Combine(UserProfile, "altv_server", "logs"),
            Path.Combine(UserProfile, "Documents", "altv-server", "logs"),
            Path.Combine(UserProfile, "Documents", "alt-v-server", "logs"),
            @"C:\altv-server\logs",
            @"C:\altv_server\logs",
            @"C:\alt-v-server\logs",
            @"C:\altv\server\logs",
            Path.Combine(UserProfile, "altv-server"),
            Path.Combine(UserProfile, "alt-v-server"),
        };

        foreach (var logDir in serverLogDirs)
        {
            if (!Directory.Exists(logDir)) continue;
            try
            {
                var logFiles = Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(logDir, "*.txt", SearchOption.AllDirectories));

                foreach (var logFile in logFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        foreach (var pattern in PlayerDataSpoofServerLogPatterns)
                        {
                            if (lower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "alt:V server log: player data spoof detection record",
                                    Risk = RiskLevel.High,
                                    Location = logDir,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"alt:V server log contains player data/stats spoof detection record: '{pattern}'. Server logs record detected spoofing events, data validation failures, bans, and anticheat triggers that indicate the user attempted to manipulate player data on this machine.",
                                    Detail = $"Log file: {logFile}, matched pattern: '{pattern}'"
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckPlayerDataSpoofResourceFolders(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var altVDir in AltVBaseDirs)
        {
            var resourcesDir = Path.Combine(altVDir, "resources");
            var clientPackagesDir = Path.Combine(altVDir, "client_packages");

            foreach (var searchRoot in new[] { resourcesDir, clientPackagesDir })
            {
                if (!Directory.Exists(searchRoot)) continue;
                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(searchRoot, "*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        var folderName = Path.GetFileName(dir);
                        if (PlayerDataSpoofResourceFolderNames.Any(k =>
                            folderName.Equals(k, StringComparison.OrdinalIgnoreCase) ||
                            folderName.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Suspicious alt:V player data/stats spoof resource folder",
                                Risk = RiskLevel.High,
                                Location = searchRoot,
                                FileName = folderName,
                                Reason = $"alt:V resource folder '{folderName}' has a player data/stats spoof-related name. Spoof resources placed in the alt:V resources or client_packages directories are loaded automatically by the client and can manipulate synchronized player statistics, position, health, armor, and other server-validated data.",
                                Detail = $"Folder path: {dir}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }

        var altVInstallResourceDirs = new[]
        {
            @"C:\altv\resources",
            @"C:\Program Files\altv\resources",
            @"C:\Program Files (x86)\altv\resources",
            Path.Combine(UserProfile, "altv", "resources"),
        };

        foreach (var resourcesDir in altVInstallResourceDirs)
        {
            if (!Directory.Exists(resourcesDir)) continue;
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(resourcesDir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var folderName = Path.GetFileName(dir);
                    if (PlayerDataSpoofResourceFolderNames.Any(k =>
                        folderName.Equals(k, StringComparison.OrdinalIgnoreCase) ||
                        folderName.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Suspicious alt:V player data/stats spoof resource in install dir",
                            Risk = RiskLevel.High,
                            Location = resourcesDir,
                            FileName = folderName,
                            Reason = $"alt:V installation resources folder contains directory '{folderName}' matching player data/stats spoof naming patterns. Cheat resources installed in the server resources directory indicate persistent deployment of stat spoofing functionality.",
                            Detail = $"Folder path: {dir}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var downloadsDir = Path.Combine(UserProfile, "Downloads");
        if (Directory.Exists(downloadsDir))
        {
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(downloadsDir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var folderName = Path.GetFileName(dir);
                    bool isSuspicious = PlayerDataSpoofResourceFolderNames.Any(k =>
                        folderName.Equals(k, StringComparison.OrdinalIgnoreCase) ||
                        folderName.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (!isSuspicious)
                    {
                        var lower = folderName.ToLowerInvariant();
                        isSuspicious = (lower.Contains("altv") || lower.Contains("alt_v") || lower.Contains("alt-v")) &&
                                       (lower.Contains("spoof") || lower.Contains("stat") || lower.Contains("data") ||
                                        lower.Contains("player") || lower.Contains("hack") || lower.Contains("cheat") ||
                                        lower.Contains("modify") || lower.Contains("fake"));
                    }
                    if (isSuspicious)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Suspicious alt:V player data spoof folder in Downloads",
                            Risk = RiskLevel.High,
                            Location = downloadsDir,
                            FileName = folderName,
                            Reason = $"Downloads folder contains a directory '{folderName}' matching known alt:V player data/stats spoof naming patterns. Downloaded spoof folders indicate prior acquisition of data manipulation tools for alt:V.",
                            Detail = $"Folder path: {dir}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckPlayerDataSpoofDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new[]
        {
            Path.Combine(UserProfile, "Downloads"),
            Desktop,
            Path.Combine(UserProfile, "Documents"),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (PlayerDataSpoofDownloadArtifacts.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V player data/stats spoof download artifact",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"alt:V player data/stats spoof archive or installer '{fn}' found in {dir}. Downloaded spoof packages indicate prior acquisition of tools designed to manipulate player statistics, experience, levels, ranks, health, and other synchronized data in alt:V.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRegistryForPlayerDataSpoof(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        CheckUserAssistForPlayerDataSpoof(ctx, ct);
        CheckMuiCacheForPlayerDataSpoof(ctx, ct);
        CheckRunKeysForPlayerDataSpoof(ctx, ct);
        CheckUninstallKeysForPlayerDataSpoof(ctx, ct);
    }, ct);

    private void CheckUserAssistForPlayerDataSpoof(ScanContext ctx, CancellationToken ct)
    {
        const string uaPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        try
        {
            using var ua = Registry.CurrentUser.OpenSubKey(uaPath);
            if (ua == null) return;
            foreach (var guidName in ua.GetSubKeyNames())
            {
                try
                {
                    using var count = Registry.CurrentUser.OpenSubKey($@"{uaPath}\{guidName}\Count");
                    if (count == null) continue;
                    foreach (var valName in count.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();
                        var decoded = Rot13Decode(valName);
                        var lower = decoded.ToLowerInvariant();
                        bool isSpoof = PlayerDataSpoofUserAssistNames.Any(k =>
                                lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                            || (lower.Contains("altv") && lower.Contains("spoof"))
                            || (lower.Contains("altv") && lower.Contains("stat") && lower.Contains("hack"))
                            || (lower.Contains("altv") && lower.Contains("data") && lower.Contains("hack"))
                            || (lower.Contains("altv") && lower.Contains("player") && lower.Contains("hack"))
                            || (lower.Contains("alt") && lower.Contains("stat") && lower.Contains("spoof"))
                            || (lower.Contains("alt") && lower.Contains("data") && lower.Contains("spoof"));
                        if (isSpoof)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V player data/stats spoof execution (UserAssist)",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{uaPath}\{guidName}\Count",
                                FileName = decoded,
                                Reason = $"Windows UserAssist registry records execution of an alt:V player data/stats spoof tool: '{decoded}'. UserAssist tracks every GUI program launched by the user and is a reliable forensic indicator of prior execution even after file deletion.",
                                Detail = $"Decoded entry: {decoded}"
                            });
                        }
                    }
                }
                catch (Exception) { }
            }
        }
        catch (Exception) { }
    }

    private void CheckMuiCacheForPlayerDataSpoof(ScanContext ctx, CancellationToken ct)
    {
        var muiPaths = new[]
        {
            @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            @"SOFTWARE\Microsoft\Windows\ShellNoRoam\MUICache",
        };

        foreach (var muiPath in muiPaths)
        {
            try
            {
                using var mui = Registry.CurrentUser.OpenSubKey(muiPath);
                if (mui == null) continue;
                foreach (var valName in mui.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    var lower = valName.ToLowerInvariant();
                    bool isSpoof = PlayerDataSpoofExecutables.Any(k =>
                            lower.Contains(k.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase), StringComparison.OrdinalIgnoreCase))
                        || (lower.Contains("altv") && lower.Contains("spoof"))
                        || (lower.Contains("altv") && lower.Contains("stat") && lower.Contains("hack"))
                        || (lower.Contains("altv") && lower.Contains("data") && lower.Contains("hack"))
                        || (lower.Contains("stat_spoof") || lower.Contains("stat spoof") && lower.Contains("alt"))
                        || (lower.Contains("data_spoof") || lower.Contains("data spoof") && lower.Contains("alt"));
                    if (isSpoof)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V player data/stats spoof execution (MUICache)",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\" + muiPath,
                            FileName = Path.GetFileName(valName),
                            Reason = $"Windows MUICache records an alt:V player data/stats spoof executable was run: '{valName}'. MUICache stores the friendly name of every EXE ever executed and persists even after the file is deleted, providing strong forensic evidence of prior spoof tool execution.",
                            Detail = $"MUICache entry: {valName}"
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }

    private void CheckRunKeysForPlayerDataSpoof(ScanContext ctx, CancellationToken ct)
    {
        var runKeyPaths = new[]
        {
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine, "HKLM"),
        };

        foreach (var (keyPath, hive, hiveName) in runKeyPaths)
        {
            try
            {
                ctx.IncrementRegistryKeys();
                using var run = hive.OpenSubKey(keyPath);
                if (run == null) continue;
                foreach (var val in run.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var data = run.GetValue(val)?.ToString() ?? string.Empty;
                    var lower = data.ToLowerInvariant();
                    bool isSpoof = PlayerDataSpoofExecutables.Any(k =>
                            lower.Contains(k.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase), StringComparison.OrdinalIgnoreCase))
                        || (lower.Contains("altv") && lower.Contains("spoof"))
                        || (lower.Contains("altv") && lower.Contains("stat") && lower.Contains("hack"))
                        || (lower.Contains("altv") && lower.Contains("data") && lower.Contains("cheat"))
                        || (lower.Contains("stat_spoof") || lower.Contains("stat spoof") && lower.Contains("alt"))
                        || (lower.Contains("data_spoof") || lower.Contains("data spoof") && lower.Contains("alt"));
                    if (isSpoof)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V player data/stats spoof autostart (Run key)",
                            Risk = RiskLevel.High,
                            Location = $@"{hiveName}\{keyPath}",
                            FileName = val,
                            Reason = $"alt:V player data/stats spoof tool configured to auto-start via Windows Run registry key. Value '{val}' points to: '{data}'. Auto-start entries indicate persistent spoof tool installation targeting alt:V player data synchronization.",
                            Detail = $"Value: {val} = {data}"
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }

    private void CheckUninstallKeysForPlayerDataSpoof(ScanContext ctx, CancellationToken ct)
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (var uninstallPath in uninstallPaths)
        {
            try
            {
                using var uninst = Registry.LocalMachine.OpenSubKey(uninstallPath);
                if (uninst == null) continue;
                foreach (var subKeyName in uninst.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var sub = uninst.OpenSubKey(subKeyName);
                        var displayName = sub?.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        var installLocation = sub?.GetValue("InstallLocation")?.ToString() ?? string.Empty;
                        var lower = displayName.ToLowerInvariant();
                        var locLower = installLocation.ToLowerInvariant();
                        bool isSpoof = (lower.Contains("altv") && lower.Contains("spoof"))
                            || (lower.Contains("altv") && lower.Contains("stat") && lower.Contains("hack"))
                            || (lower.Contains("altv") && lower.Contains("data") && lower.Contains("hack"))
                            || (lower.Contains("alt") && lower.Contains("stat spoof"))
                            || (lower.Contains("alt") && lower.Contains("data spoof"))
                            || (locLower.Contains("altv") && locLower.Contains("spoof"))
                            || (locLower.Contains("stat_spoof") && locLower.Contains("alt"))
                            || (locLower.Contains("data_spoof") && locLower.Contains("alt"));
                        if (isSpoof)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V player data/stats spoof installer record",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                FileName = displayName,
                                Reason = $"Uninstall registry record found for alt:V player data/stats spoof software: '{displayName}'. This indicates a stat/data spoof tool was formally installed on this system.",
                                Detail = $"Key: {subKeyName}, DisplayName: {displayName}, Location: {installLocation}"
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
            catch (Exception) { }
        }

        var userUninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        try
        {
            using var uninst = Registry.CurrentUser.OpenSubKey(userUninstallPath);
            if (uninst != null)
            {
                foreach (var subKeyName in uninst.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var sub = uninst.OpenSubKey(subKeyName);
                        var displayName = sub?.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        var lower = displayName.ToLowerInvariant();
                        bool isSpoof = (lower.Contains("altv") && lower.Contains("spoof"))
                            || (lower.Contains("altv") && lower.Contains("stat") && lower.Contains("hack"))
                            || lower.Contains("stat spoof altv")
                            || lower.Contains("data spoof altv")
                            || lower.Contains("player spoof altv");
                        if (isSpoof)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V player data/stats spoof installer record (HKCU)",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{userUninstallPath}\{subKeyName}",
                                FileName = displayName,
                                Reason = $"User-level uninstall registry record found for alt:V player data/stats spoof software: '{displayName}'. User-level installation indicates the spoof tool was installed without administrator privileges.",
                                Detail = $"Key: {subKeyName}, DisplayName: {displayName}"
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
        }
        catch (Exception) { }

        var softwareKeys = new[]
        {
            (@"SOFTWARE\AltVStatSpoof", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\AltVDataSpoof", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\AltVPlayerSpoof", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\AltVStatHack", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\AltVDataHack", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\StatSpoofAltV", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\DataSpoofAltV", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\PlayerSpoofAltV", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\AltVStatSpoof", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\AltVDataSpoof", Registry.LocalMachine, "HKLM"),
        };

        foreach (var (keyPath, hive, hiveName) in softwareKeys)
        {
            try
            {
                ctx.IncrementRegistryKeys();
                using var key = hive.OpenSubKey(keyPath);
                if (key != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V player data/stats spoof registry key",
                        Risk = RiskLevel.High,
                        Location = $@"{hiveName}\{keyPath}",
                        FileName = string.Empty,
                        Reason = $"Registry key '{keyPath}' was left behind by an alt:V player data/stats spoof tool installation or configuration. These keys are typically written by spoof tool loaders to store settings, license data, or target stat configuration.",
                        Detail = $"Key: {hiveName}\\{keyPath}"
                    });
                }
            }
            catch (Exception) { }
        }
    }

    private Task CheckPlayerDataSpoofConfigFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(AltVBaseDirs)
        {
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(LocalAppData, "Temp"),
            AppData,
            LocalAppData,
            Path.Combine(UserProfile, "Documents"),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (PlayerDataSpoofConfigFiles.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V player data/stats spoof configuration file",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"alt:V player data/stats spoof configuration or offset file '{fn}' found on disk. These files contain stat manipulation settings, memory offsets for player data structures, fake stat values, or configuration for spoofing tools targeting the alt:V synchronization layer.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckPlayerDataSpoofCacheArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var altVDir in AltVBaseDirs)
        {
            var cacheDirs = new[]
            {
                Path.Combine(altVDir, "cache"),
                Path.Combine(altVDir, "data"),
                Path.Combine(altVDir, "temp"),
                Path.Combine(altVDir, "bin"),
                Path.Combine(altVDir, "logs"),
            };

            foreach (var cacheDir in cacheDirs)
            {
                if (!Directory.Exists(cacheDir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(cacheDir, "*.dll", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        if (PlayerDataSpoofDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Player data spoof DLL inside alt:V cache/data folder",
                                Risk = RiskLevel.Critical,
                                Location = Path.GetDirectoryName(file) ?? cacheDir,
                                FileName = fn,
                                Reason = $"Known alt:V player data/stats spoof DLL '{fn}' found inside the alt:V application cache or data folder. Spoof tools sometimes store their DLLs inside the game framework directory to evade detection, persist across sessions, and enable auto-loading when the alt:V client initializes.",
                                Detail = $"Full path: {file}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }

                try
                {
                    foreach (var file in Directory.EnumerateFiles(cacheDir, "*.exe", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        if (PlayerDataSpoofExecutables.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Player data spoof executable inside alt:V cache/data folder",
                                Risk = RiskLevel.Critical,
                                Location = Path.GetDirectoryName(file) ?? cacheDir,
                                FileName = fn,
                                Reason = $"Known alt:V player data/stats spoof executable '{fn}' found inside the alt:V application cache or data directory. Storing spoof tools inside the framework directory is a common evasion technique used to avoid detection by anticheat scans.",
                                Detail = $"Full path: {file}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }

        var altVInstallCacheDirs = new[]
        {
            @"C:\altv\cache",
            @"C:\altv\data",
            @"C:\Program Files\altv\cache",
            Path.Combine(UserProfile, "altv", "cache"),
        };

        foreach (var cacheDir in altVInstallCacheDirs)
        {
            if (!Directory.Exists(cacheDir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(cacheDir, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (PlayerDataSpoofDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Player data spoof DLL inside alt:V installation cache",
                            Risk = RiskLevel.Critical,
                            Location = Path.GetDirectoryName(file) ?? cacheDir,
                            FileName = fn,
                            Reason = $"Known alt:V player data/stats spoof DLL '{fn}' found inside the alt:V installation cache directory. This indicates a spoof tool was deliberately placed within the alt:V installation to enable persistent stat manipulation.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckPlayerDataSpoofRecentDocuments(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var recentDir = Path.Combine(AppData, "Microsoft", "Windows", "Recent");
        if (!Directory.Exists(recentDir)) return;
        try
        {
            foreach (var lnk in Directory.EnumerateFiles(recentDir, "*.lnk", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileNameWithoutExtension(lnk).ToLowerInvariant();
                bool isSpoofArtifact = PlayerDataSpoofRecentDocPatterns.Any(k =>
                    fn.Contains(k, StringComparison.OrdinalIgnoreCase))
                    || PlayerDataSpoofDownloadArtifacts.Any(k =>
                        fn.Contains(k.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase)
                            .Replace(".zip", string.Empty, StringComparison.OrdinalIgnoreCase)
                            .Replace(".rar", string.Empty, StringComparison.OrdinalIgnoreCase)
                            .Replace(".7z", string.Empty, StringComparison.OrdinalIgnoreCase),
                            StringComparison.OrdinalIgnoreCase));
                if (isSpoofArtifact)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V player data/stats spoof recent document artifact",
                        Risk = RiskLevel.Medium,
                        Location = recentDir,
                        FileName = Path.GetFileName(lnk),
                        Reason = $"Windows Recent Documents folder contains a shortcut referencing an alt:V player data/stats spoof file: '{fn}'. Recent Documents tracks files opened or accessed by the user and provides forensic evidence of interaction with stat spoof tools even after file deletion.",
                        Detail = $"Shortcut: {lnk}"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        var automaticDestDir = Path.Combine(AppData, "Microsoft", "Windows", "Recent", "AutomaticDestinations");
        if (!Directory.Exists(automaticDestDir)) return;
        try
        {
            foreach (var jumpFile in Directory.EnumerateFiles(automaticDestDir, "*.automaticDestinations-ms", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jumpFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, System.Text.Encoding.Unicode, detectEncodingFromByteOrderMarks: true);
                    string content = sr.ReadToEnd();
                    bool hasSpoofArtifact = PlayerDataSpoofRecentDocPatterns.Any(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        || PlayerDataSpoofExecutables.Any(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hasSpoofArtifact)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V player data/stats spoof jump list artifact",
                            Risk = RiskLevel.Medium,
                            Location = automaticDestDir,
                            FileName = Path.GetFileName(jumpFile),
                            Reason = $"Windows Jump List (AutomaticDestinations) file contains a reference to an alt:V player data/stats spoof tool. Jump lists record recently accessed files and applications and persist as forensic artifacts even after spoof tool removal.",
                            Detail = $"Jump list file: {jumpFile}"
                        });
                    }
                }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private static string Rot13Decode(string s)
    {
        return new string(s.Select(c =>
            c >= 'a' && c <= 'z' ? (char)('a' + (c - 'a' + 13) % 26) :
            c >= 'A' && c <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) : c).ToArray());
    }
}
