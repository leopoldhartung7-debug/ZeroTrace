using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMSpeedHackForensicScanModule : IScanModule
{
    public string Name => "FiveM Speed Hack Forensic Scan";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string TempDir =
        Path.Combine(LocalAppData, "Temp");

    private static readonly string FiveMRoot =
        Path.Combine(LocalAppData, @"FiveM\FiveM.app");

    private static readonly string[] FiveMScanRoots =
    [
        Path.Combine(LocalAppData, @"FiveM\FiveM.app"),
        Path.Combine(LocalAppData, @"FiveM\FiveM.app\plugins"),
        Path.Combine(LocalAppData, @"FiveM\FiveM.app\mods"),
        Path.Combine(LocalAppData, @"FiveM\FiveM.app\resources"),
        Path.Combine(LocalAppData, @"FiveM\FiveM.app\citizen"),
        Path.Combine(LocalAppData, @"FiveM\FiveM.app\data"),
        Path.Combine(LocalAppData, @"FiveM\FiveM.app\cache"),
    ];

    private static readonly string[] KnownSpeedHackExecutables =
    [
        "SpeedHack.exe",
        "speedhack.exe",
        "GameSpeedChanger.exe",
        "gamespeedchanger.exe",
        "SpeedMultiplier.exe",
        "speedmultiplier.exe",
        "CheatEngineSpeedHack.exe",
        "cheatenginespeadhack.exe",
        "SpeedMod.exe",
        "speedmod.exe",
        "GameSpeed.exe",
        "gamespeed.exe",
        "SpeedCheat.exe",
        "speedcheat.exe",
        "FiveMSpeedHack.exe",
        "fivemspeedhack.exe",
        "FiveMSpeed.exe",
        "fivemspeed.exe",
        "SpeedMultiplierFiveM.exe",
        "speedmultiplierfivem.exe",
        "SpeedHackFiveM.exe",
        "speedhackfivem.exe",
        "GtaSpeedHack.exe",
        "gtaspeedhack.exe",
        "GtaSpeedMod.exe",
        "gtaspeedmod.exe",
        "SpeedBoost.exe",
        "speedboost.exe",
        "SpeedBoot.exe",
        "speedboot.exe",
        "GameSpeedMod.exe",
        "gamespeedmod.exe",
        "SpeedHackTool.exe",
        "speedhacktool.exe",
        "FiveMSpeedMod.exe",
        "fivemspeedmod.exe",
        "EntitySpeedHack.exe",
        "entityspeedhack.exe",
        "VehicleSpeedHack.exe",
        "vehiclespeedhack.exe",
        "PlayerSpeedHack.exe",
        "playerspeedhack.exe",
        "SpeedChanger.exe",
        "speedchanger.exe",
        "SuperSpeed.exe",
        "superspeed.exe",
        "SpeedHackPro.exe",
        "speedhackpro.exe",
    ];

    private static readonly string[] KnownSpeedHackDlls =
    [
        "speedhack.dll",
        "speed_hack.dll",
        "gamespeed.dll",
        "game_speed.dll",
        "speedmod.dll",
        "speed_mod.dll",
        "speedmultiplier.dll",
        "speed_multiplier.dll",
        "speedcheat.dll",
        "speed_cheat.dll",
        "fivemspeed.dll",
        "fivem_speed.dll",
        "fivemspeedhack.dll",
        "fivem_speedhack.dll",
        "gtaspeed.dll",
        "gta_speed.dll",
        "gtaspeedhack.dll",
        "gta_speedhack.dll",
        "speedboost.dll",
        "speed_boost.dll",
        "speedhookdll.dll",
        "speed_hook.dll",
        "gamespeedhook.dll",
        "game_speed_hook.dll",
        "entityspeed.dll",
        "entity_speed.dll",
        "vehiclespeed.dll",
        "vehicle_speed.dll",
        "playerSpeed.dll",
        "player_speed.dll",
        "speedhacktimer.dll",
        "speed_hack_timer.dll",
        "cegamespeed.dll",
        "ce_speed.dll",
        "superspeed.dll",
        "super_speed.dll",
        "speedpatch.dll",
        "speed_patch.dll",
        "speedbypass.dll",
        "speed_bypass.dll",
        "speedinjector.dll",
        "speed_injector.dll",
    ];

    private static readonly string[] SpeedHackFileNameKeywords =
    [
        "speedhack",
        "speed_hack",
        "speedmult",
        "speed_mult",
        "gamespeed",
        "game_speed",
        "speedmod",
        "speed_mod",
        "speedcheat",
        "speed_cheat",
        "speedboost",
        "speed_boost",
        "fivemspeed",
        "fivem_speed",
        "speedchanger",
        "speed_changer",
        "superspeed",
        "super_speed",
        "speedpatch",
        "speed_patch",
        "speedbypass",
        "speed_bypass",
        "speedinjector",
        "speed_injector",
        "SpeedMultiplier",
        "speedmultiplier",
        "entityspeed",
        "vehiclespeed",
        "playerspeed",
    ];

    private static readonly string[] CheatEngineSpeedTableKeywords =
    [
        "speedhack",
        "speed hack",
        "game speed",
        "gamespeed",
        "speed multiplier",
        "speedmultiplier",
        "speed mod",
        "speedmod",
        "fivem speed",
        "fivemspeed",
        "SetGameSpeed",
        "setEntityMaxSpeed",
        "speedMultiplier",
        "speed cheat",
        "speedcheat",
        "timescale",
        "TimeScale",
        "GAMEPLAY_GET_TIME_SCALE",
        "GAMEPLAY_SET_TIME_SCALE",
        "gta speed",
        "entity speed",
        "vehicle speed",
        "player speed",
        "SetEntityMaxSpeed",
        "speed exploit",
    ];

    private static readonly string[] FiveMConfigSpeedPatterns =
    [
        "SetGameSpeed",
        "setEntitySpeed",
        "speedMultiplier",
        "speed_multiplier",
        "SpeedMultiplier",
        "GameSpeed",
        "game_speed",
        "timescale",
        "TimeScale",
        "SetEntityMaxSpeed",
        "speed_hack",
        "speedhack",
        "GAMEPLAY_SET_TIME_SCALE",
        "TIMESCALE",
        "SetPedMoveRateOverride",
        "SET_PED_MOVE_RATE_OVERRIDE",
        "NETWORK_OVERRIDE_CLOCK_TIME",
    ];

    private static readonly string[] LuaSpeedHackPatterns =
    [
        "SetGameSpeed",
        "SetEntityMaxSpeed",
        "SetPedMoveRateOverride",
        "GAMEPLAY_SET_TIME_SCALE",
        "speedMultiplier",
        "speed_multiplier",
        "speed_hack",
        "speedhack",
        "timescale",
        "TimeScale",
        "SET_TIMESCALE",
        "NETWORK_OVERRIDE_CLOCK_TIME",
        "SetPedMaxSpeed",
        "speedboost",
        "superspeed",
        "SuperSpeed",
        "speed bypass",
        "speedbypass",
        "speed cheat",
        "speedcheat",
        "GameSpeed",
        "game_speed",
        "entityspeed",
        "vehiclespeed",
        "SetVehicleMaxSpeed",
        "SET_VEHICLE_MAX_SPEED",
        "speed exploit",
        "WarpPlayer",
    ];

    private static readonly string[] LogFileSpeedHackPatterns =
    [
        "speed hack",
        "game speed",
        "speed multiplier",
        "speedhack detected",
        "speed cheat",
        "speedhack",
        "speedmultiplier",
        "gamespeed",
        "speed mod",
        "speed boost",
        "speed bypass",
        "timescale abuse",
        "speed exploit",
        "speed manipulation",
        "abnormal speed",
        "speed violation",
        "speed ban",
        "speed kick",
        "ban for speed",
        "kick for speed",
        "speed detected",
        "detected speedhack",
        "detected speed cheat",
        "speed anomaly",
        "speed too high",
        "speed limit exceeded",
        "fivem speed hack",
        "gta speed hack",
        "entity speed abuse",
        "vehicle speed abuse",
        "player speed abuse",
    ];

    private static readonly string[] DiscordSpeedHackKeywords =
    [
        "fivem speed hack",
        "speed multiplier fivem",
        "speed cheat",
        "game speed fivem",
        "speedhack",
        "speed hack",
        "speedmultiplier",
        "gamespeed cheat",
        "fivem speedhack",
        "speed mod fivem",
        "speed boost fivem",
        "speed bypass fivem",
        "superspeed fivem",
        "speed exploit",
        "speed griefing",
        "timescale hack",
        "timescale exploit",
        "fivem speed exploit",
        "gta speed hack",
        "vehicle speed hack",
        "entity speed hack",
    ];

    private static readonly string[] PrefetchSpeedHackKeywords =
    [
        "SPEEDHACK",
        "SPEED_HACK",
        "GAMESPEED",
        "GAME_SPEED",
        "SPEEDMULT",
        "SPEED_MULT",
        "SPEEDMOD",
        "SPEED_MOD",
        "SPEEDCHEAT",
        "SPEED_CHEAT",
        "SPEEDBOOST",
        "SPEED_BOOST",
        "FIVEMSPEED",
        "FIVEM_SPEED",
        "SUPERSPEED",
        "SUPER_SPEED",
        "SPEEDCHANGER",
        "CHEATENGINESPED",
        "SPEEDHACKTOOL",
    ];

    private static readonly string[] UserAssistSpeedHackKeywords =
    [
        "speedhack",
        "speed hack",
        "speed_hack",
        "gamespeed",
        "game speed",
        "game_speed",
        "speedmultiplier",
        "speedmult",
        "speed_mult",
        "speedmod",
        "speed_mod",
        "speedcheat",
        "speed_cheat",
        "speedboost",
        "speed_boost",
        "fivemspeed",
        "fivem speed",
        "fivem_speed",
        "superspeed",
        "super_speed",
        "speedchanger",
        "speedhacktool",
        "gamespeedchanger",
    ];

    private static readonly string[] CheatEngineCtTableKeywords =
    [
        "speedhack",
        "speed hack",
        "game speed",
        "gamespeed",
        "speed multiplier",
        "speedmultiplier",
        "timescale",
        "TimeScale",
        "time scale",
        "SetGameSpeed",
        "speed cheat",
        "speedcheat",
        "fivem speed",
        "fivemspeed",
        "gta speed",
        "entity speed",
        "vehicle speed",
        "speed boost",
        "speedboost",
        "speed bypass",
        "speedbypass",
        "speed exploit",
        "GAMEPLAY_SET_TIME_SCALE",
        "TIMESCALE",
        "speed mod",
        "speedmod",
        "speed patch",
        "speedpatch",
    ];

    private static readonly string[] FiveMScriptDirsToScan =
    [
        @"FiveM.app\plugins",
        @"FiveM.app\mods",
        @"FiveM.app\resources",
        @"FiveM.app\citizen\scripting",
        @"FiveM.app\citizen\scripting\lua",
        @"FiveM.app\citizen\scripting\v8",
        @"FiveM.app\data\cache\scripthookv",
        @"FiveM.app\scripts",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckKnownSpeedHackExecutables(ctx, ct),
            CheckKnownSpeedHackDlls(ctx, ct),
            CheckFiveMCacheAndConfigForSpeedPatterns(ctx, ct),
            CheckLuaFilesForSpeedHackPatterns(ctx, ct),
            CheckLogFilesForSpeedHackKeywords(ctx, ct),
            CheckRegistryForSpeedHackArtifacts(ctx, ct),
            CheckUserAssistForSpeedHackTools(ctx, ct),
            CheckTempAndAppDataForSpeedHackArtifacts(ctx, ct),
            CheckDiscordCacheForSpeedHackKeywords(ctx, ct),
            CheckCheatEngineCtTables(ctx, ct),
            CheckPrefetchForSpeedHackExecutables(ctx, ct),
            CheckFiveMScriptDirsForSpeedKeywords(ctx, ct)
        );

        ctx.Report(1.0, Name, "FiveM speed hack forensic scan complete");
    }

    private Task CheckKnownSpeedHackExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>
        {
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            TempDir,
            AppData,
            LocalAppData,
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (KnownSpeedHackExecutables.Any(k =>
                            fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Known FiveM speed hack executable: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known FiveM speed hack or game-speed manipulation tool '{fn}' found on disk. " +
                                     "These tools manipulate the game's time scale or entity movement speed to gain an unfair advantage " +
                                     "on FiveM servers, allowing players to move faster than the server expects.",
                            Detail = $"Full path: {file}",
                        });
                        continue;
                    }

                    foreach (var keyword in SpeedHackFileNameKeywords)
                    {
                        if (fn.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious speed hack executable name: {fn}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = fn,
                                Reason = $"Executable '{fn}' contains speed-hack keyword '{keyword}'. " +
                                         "This naming pattern is associated with FiveM speed manipulation tools or game-speed changers.",
                                Detail = $"Matched keyword: {keyword} | Path: {file}",
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckKnownSpeedHackDlls(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>(FiveMScanRoots)
        {
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            TempDir,
            AppData,
            LocalAppData,
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (KnownSpeedHackDlls.Any(k =>
                            fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Known speed hack DLL: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known speed hack DLL '{fn}' found on disk. " +
                                     "Speed hack DLLs are injected into FiveM or GTA V to manipulate the game engine's " +
                                     "time scale, entity movement speed, or physics constants at runtime. " +
                                     "Cheat Engine speed tables commonly deploy these DLL payloads.",
                            Detail = $"Full path: {file}",
                        });
                        continue;
                    }

                    foreach (var keyword in SpeedHackFileNameKeywords)
                    {
                        if (fn.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious speed hack DLL name: {fn}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = fn,
                                Reason = $"DLL file '{fn}' contains speed-hack keyword '{keyword}'. " +
                                         "This DLL may be an injected speed manipulation component for FiveM or GTA V.",
                                Detail = $"Matched keyword: {keyword} | Path: {file}",
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMCacheAndConfigForSpeedPatterns(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var configExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".cfg", ".json", ".ini", ".xml", ".lua", ".js", ".txt", ".yaml", ".yml",
        };

        foreach (var root in FiveMScanRoots)
        {
            if (!Directory.Exists(root)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    if (!configExtensions.Contains(ext)) continue;

                    ctx.IncrementFiles();

                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length > 2 * 1024 * 1024) continue;

                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);

                        var matches = FiveMConfigSpeedPatterns
                            .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matches.Count == 0) continue;

                        bool hasHighMultiplier = false;
                        var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                        foreach (var line in lines)
                        {
                            if (line.Contains("speedMultiplier", StringComparison.OrdinalIgnoreCase) ||
                                line.Contains("speed_multiplier", StringComparison.OrdinalIgnoreCase))
                            {
                                foreach (var part in line.Split(new[] { '=', ':', ' ', '\t', ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                                {
                                    if (double.TryParse(part, System.Globalization.NumberStyles.Float,
                                            System.Globalization.CultureInfo.InvariantCulture, out double val)
                                        && val > 1.5)
                                    {
                                        hasHighMultiplier = true;
                                        break;
                                    }
                                }
                            }
                            if (hasHighMultiplier) break;
                        }

                        var risk = hasHighMultiplier ? RiskLevel.High : RiskLevel.Medium;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM cache/config with speed manipulation settings: {Path.GetFileName(file)}",
                            Risk = risk,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"FiveM cache or config file '{Path.GetFileName(file)}' contains {matches.Count} speed-related pattern(s): " +
                                     string.Join(", ", matches.Take(4).Select(m => $"'{m}'")) +
                                     (matches.Count > 4 ? " ..." : "") +
                                     (hasHighMultiplier
                                         ? " A speed multiplier value exceeding 1.5 was detected, indicating above-normal speed modification."
                                         : "") +
                                     ". These settings indicate speed hack configuration or remnant speed-manipulation artifacts in FiveM.",
                            Detail = $"Patterns ({matches.Count}): {string.Join(", ", matches.Take(6))} | " +
                                     $"High multiplier: {hasHighMultiplier}",
                        });
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckLuaFilesForSpeedHackPatterns(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var luaDirs = new List<string>(FiveMScanRoots)
        {
            AppData,
            LocalAppData,
        };

        foreach (var dir in luaDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length > 2 * 1024 * 1024) continue;

                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);

                        var matches = LuaSpeedHackPatterns
                            .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matches.Count == 0) continue;

                        bool nameHit = SpeedHackFileNameKeywords.Any(k =>
                            fn.Contains(k, StringComparison.OrdinalIgnoreCase));

                        var risk = (nameHit || matches.Count >= 3) ? RiskLevel.High
                                 : matches.Count >= 2 ? RiskLevel.High
                                 : RiskLevel.Medium;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Lua file with speed hack patterns: {fn}",
                            Risk = risk,
                            Location = file,
                            FileName = fn,
                            Reason = $"Lua script '{fn}' contains {matches.Count} speed-hack native call(s): " +
                                     string.Join(", ", matches.Take(4).Select(m => $"'{m}'")) +
                                     (matches.Count > 4 ? " ..." : "") + ". " +
                                     "These FiveM/GTA V natives are used by speed hack scripts to manipulate game time scale, " +
                                     "entity movement speed, or vehicle maximum speed beyond server-permitted limits.",
                            Detail = $"Patterns ({matches.Count}): {string.Join(", ", matches.Take(6))} | " +
                                     $"Suspicious file name: {nameHit}",
                        });
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckLogFilesForSpeedHackKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logDirs = new List<string>(FiveMScanRoots)
        {
            AppData,
            LocalAppData,
            TempDir,
            Path.Combine(UserProfile, "Downloads"),
        };

        var logExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".log", ".txt", ".json",
        };

        foreach (var dir in logDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    if (!logExtensions.Contains(ext)) continue;

                    ctx.IncrementFiles();

                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length > 4 * 1024 * 1024) continue;

                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);

                        var matches = LogFileSpeedHackPatterns
                            .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matches.Count == 0) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Log file containing speed hack references: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Log file '{Path.GetFileName(file)}' contains {matches.Count} speed-hack reference(s): " +
                                     string.Join(", ", matches.Take(4).Select(m => $"'{m}'")) +
                                     (matches.Count > 4 ? " ..." : "") + ". " +
                                     "These log entries indicate prior speed hack activity, speed ban/kick events, " +
                                     "or speed-related anti-cheat detections on FiveM.",
                            Detail = $"Matched patterns ({matches.Count}): {string.Join(", ", matches.Take(6))}",
                        });
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckRegistryForSpeedHackArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var hkcuPaths = new[]
        {
            @"Software\SpeedHack",
            @"Software\FiveM\SpeedMod",
            @"Software\FiveM\SpeedHack",
            @"Software\GameSpeedChanger",
            @"Software\GameSpeed",
            @"Software\SpeedMultiplier",
            @"Software\SpeedMod",
            @"Software\SpeedCheat",
            @"Software\SpeedBoost",
            @"Software\FiveMSpeedHack",
            @"Software\FiveMSpeed",
            @"Software\SpeedHackPro",
            @"Software\SuperSpeed",
            @"Software\SpeedChanger",
            @"Software\SpeedHackTool",
            @"Software\EntitySpeedHack",
            @"Software\VehicleSpeedHack",
            @"Software\PlayerSpeedHack",
        };

        foreach (var regPath in hkcuPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Registry key for FiveM speed hack tool: HKCU\\{regPath}",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{regPath}",
                    Reason = $"Registry key 'HKCU\\{regPath}' found. " +
                             "This key is created by known FiveM speed hack or game-speed manipulation tools. " +
                             "Its presence is forensic evidence of speed hack software installation or execution on this system.",
                    Detail = $"Registry path: HKCU\\{regPath} | Values: {string.Join(", ", key.GetValueNames().Take(5))}",
                });
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var hklmPaths = new[]
        {
            @"Software\SpeedHack",
            @"Software\GameSpeedChanger",
            @"Software\GameSpeed",
            @"Software\SpeedMultiplier",
            @"Software\SpeedMod",
            @"Software\FiveMSpeedHack",
            @"Software\SuperSpeed",
        };

        foreach (var regPath in hklmPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"HKLM registry key for speed hack tool: HKLM\\{regPath}",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{regPath}",
                    Reason = $"Machine-level registry key 'HKLM\\{regPath}' found. " +
                             "This key indicates a speed hack tool was installed system-wide. " +
                             "Machine-level installation is consistent with persistent speed hack loaders that survive reboots.",
                    Detail = $"Registry path: HKLM\\{regPath}",
                });
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var ceSpeedPaths = new[]
        {
            @"Software\Cheat Engine",
            @"Software\CheatEngine",
        };

        foreach (var regPath in ceSpeedPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();
                var valueNames = key.GetValueNames();
                var speedValues = valueNames
                    .Where(v => v.Contains("speed", StringComparison.OrdinalIgnoreCase) ||
                                v.Contains("timescale", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (speedValues.Count == 0) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat Engine registry: speed-related settings — HKCU\\{regPath}",
                    Risk = RiskLevel.Medium,
                    Location = $@"HKCU\{regPath}",
                    Reason = $"Cheat Engine registry key 'HKCU\\{regPath}' contains speed-related value(s): " +
                             string.Join(", ", speedValues.Take(4).Select(v => $"'{v}'")) + ". " +
                             "Cheat Engine is commonly used to manipulate FiveM/GTA V game speed through its built-in speed hack feature. " +
                             "Speed-related registry values indicate Cheat Engine speed hack configuration.",
                    Detail = $"Speed values: {string.Join(", ", speedValues.Take(6))}",
                });
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckUserAssistForSpeedHackTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string UserAssistBase =
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

        try
        {
            using var baseKey = Registry.CurrentUser.OpenSubKey(UserAssistBase, writable: false);
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

                        var hit = UserAssistSpeedHackKeywords.FirstOrDefault(k =>
                            decoded.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hit is null) continue;

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
                            Title = $"UserAssist: speed hack tool executed — {hit}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{UserAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason = $"Windows UserAssist entry shows execution of speed hack tool '{Path.GetFileName(decoded)}' " +
                                     $"({runCount} time(s) executed" +
                                     (lastRun.HasValue ? $", last seen {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                     $"). Matched keyword: '{hit}'. " +
                                     "UserAssist entries remain in the registry even after the binary has been deleted, " +
                                     "providing persistent forensic evidence of speed hack tool usage.",
                            Detail = $"Decoded: {decoded} | Executions: {runCount} | " +
                                     $"Last run: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}",
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }, ct);

    private Task CheckTempAndAppDataForSpeedHackArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var artifactDirs = new[]
        {
            TempDir,
            AppData,
            LocalAppData,
            Path.Combine(UserProfile, "Downloads"),
            Desktop,
        };

        var interestingExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".zip", ".rar", ".7z", ".bat", ".ps1", ".lua", ".js", ".txt", ".ct",
        };

        foreach (var dir in artifactDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    if (!interestingExtensions.Contains(ext)) continue;

                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    foreach (var keyword in SpeedHackFileNameKeywords)
                    {
                        if (fn.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Speed hack artifact in temp/AppData: {fn}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = fn,
                                Reason = $"File '{fn}' in '{dir}' contains speed-hack keyword '{keyword}'. " +
                                         "Speed hack tools leave temporary artifacts in AppData or Temp directories " +
                                         "when downloading, extracting, or configuring game-speed manipulation tools for FiveM.",
                                Detail = $"Matched keyword: {keyword} | Path: {file}",
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDiscordCacheForSpeedHackKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var discordClients = new[] { "discord", "discordptb", "discordcanary" };

        foreach (var client in discordClients)
        {
            ct.ThrowIfCancellationRequested();
            var root = Path.Combine(AppData, client);
            if (!Directory.Exists(root)) continue;

            var cacheDirs = new[]
            {
                Path.Combine(root, "Cache"),
                Path.Combine(root, "Code Cache"),
                Path.Combine(root, "Local Storage"),
                Path.Combine(root, "GPUCache"),
            };

            foreach (var cacheDir in cacheDirs)
            {
                if (!Directory.Exists(cacheDir)) continue;
                ct.ThrowIfCancellationRequested();
                try
                {
                    foreach (var file in Directory.EnumerateFiles(cacheDir, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fi = new FileInfo(file);
                        if (fi.Length > 512 * 1024) continue;
                        if (fi.Length == 0) continue;

                        ctx.IncrementFiles();

                        try
                        {
                            string content;
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                            content = await sr.ReadToEndAsync(ct);

                            var matches = DiscordSpeedHackKeywords
                                .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                                .ToList();

                            if (matches.Count == 0) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Discord cache: FiveM speed hack references in {client}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Discord client '{client}' cache file contains {matches.Count} FiveM speed-hack keyword(s): " +
                                         string.Join(", ", matches.Take(4).Select(m => $"'{m}'")) +
                                         (matches.Count > 4 ? " ..." : "") + ". " +
                                         "This indicates potential membership in or communication about FiveM speed hack communities " +
                                         "or cheat distribution channels providing speed multiplier tools.",
                                Detail = $"Discord client: {client} | Cache file: {file} | " +
                                         $"Keywords ({matches.Count}): {string.Join(", ", matches.Take(6))}",
                            });
                        }
                        catch (IOException) { }
                        catch (UnauthorizedAccessException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckCheatEngineCtTables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var ctScanDirs = new[]
        {
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(UserProfile, "Documents"),
            AppData,
            LocalAppData,
            TempDir,
        };

        foreach (var dir in ctScanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.ct", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    bool nameHit = SpeedHackFileNameKeywords.Any(k =>
                        fn.Contains(k, StringComparison.OrdinalIgnoreCase));

                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length > 4 * 1024 * 1024) continue;

                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                        content = await sr.ReadToEndAsync(ct);

                        var matches = CheatEngineCtTableKeywords
                            .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matches.Count == 0 && !nameHit) continue;

                        var risk = (nameHit && matches.Count >= 2) ? RiskLevel.High
                                 : nameHit ? RiskLevel.Medium
                                 : matches.Count >= 3 ? RiskLevel.High
                                 : RiskLevel.Medium;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat Engine .CT table with speed hack configuration: {fn}",
                            Risk = risk,
                            Location = file,
                            FileName = fn,
                            Reason = $"Cheat Engine table file '{fn}' " +
                                     (nameHit ? "has a speed-hack related name and " : "") +
                                     (matches.Count > 0
                                         ? $"contains {matches.Count} speed-hack related entry/entries: " +
                                           string.Join(", ", matches.Take(4).Select(m => $"'{m}'")) +
                                           (matches.Count > 4 ? " ..." : "") + ". "
                                         : ". ") +
                                     "Cheat Engine .CT tables are used to configure and automate speed hack injection into " +
                                     "FiveM or GTA V processes, targeting time scale values, entity speed caps, or physics constants.",
                            Detail = $"File: {file} | Name hit: {nameHit} | " +
                                     $"Content matches ({matches.Count}): {string.Join(", ", matches.Take(6))}",
                        });
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        foreach (var dir in ctScanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.cetrainer", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    bool nameHit = SpeedHackFileNameKeywords.Any(k =>
                        fn.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (!nameHit) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Cheat Engine trainer with speed hack name: {fn}",
                        Risk = RiskLevel.Medium,
                        Location = file,
                        FileName = fn,
                        Reason = $"Cheat Engine trainer file '{fn}' has a speed-hack related name. " +
                                 "CE trainers automate speed manipulation injection and are a common vector for " +
                                 "deploying speed hack configurations into FiveM sessions.",
                        Detail = $"Path: {file}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckPrefetchForSpeedHackExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string PrefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(PrefetchDir)) return;

        string[] pfFiles;
        try
        {
            pfFiles = Directory.GetFiles(PrefetchDir, "*.pf");
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in pfFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var pfName = Path.GetFileNameWithoutExtension(file);
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            var hit = PrefetchSpeedHackKeywords.FirstOrDefault(k =>
                exeName.Contains(k, StringComparison.OrdinalIgnoreCase));
            if (hit is null) continue;

            DateTime? lastWrite = null;
            try { lastWrite = File.GetLastWriteTimeUtc(file); } catch { }

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Prefetch: speed hack executable executed — {exeName}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = exeName + ".exe",
                Reason = $"Windows Prefetch file indicates execution of FiveM speed hack tool '{exeName}.exe'. " +
                         $"Matched keyword: '{hit}'. " +
                         "Prefetch entries persist even after the executable has been deleted, " +
                         "providing durable forensic evidence of prior speed hack tool execution on this system.",
                Detail = $"Prefetch file: {file} | Executable: {exeName}.exe | " +
                         $"Last prefetch update: {(lastWrite.HasValue ? lastWrite.Value.ToString("yyyy-MM-dd HH:mm:ss") + " UTC" : "unknown")}",
            });
        }
    }, ct);

    private Task CheckFiveMScriptDirsForSpeedKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scriptExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".lua", ".js", ".ts", ".cfg", ".json",
        };

        foreach (var subDir in FiveMScriptDirsToScan)
        {
            var fullPath = Path.Combine(LocalAppData, subDir);
            if (!Directory.Exists(fullPath)) continue;
            ct.ThrowIfCancellationRequested();

            try
            {
                foreach (var file in Directory.EnumerateFiles(fullPath, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    if (!scriptExtensions.Contains(ext)) continue;

                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    bool nameHit = SpeedHackFileNameKeywords.Any(k =>
                        fn.Contains(k, StringComparison.OrdinalIgnoreCase));

                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length > 2 * 1024 * 1024) continue;

                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);

                        var luaMatches = LuaSpeedHackPatterns
                            .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        var configMatches = FiveMConfigSpeedPatterns
                            .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                            .Except(luaMatches, StringComparer.OrdinalIgnoreCase)
                            .ToList();

                        var allMatches = luaMatches.Concat(configMatches).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

                        if (allMatches.Count == 0 && !nameHit) continue;

                        bool hasBypass = content.Contains("speedMultiplier bypass", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains("speed_hack", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains("speed bypass", StringComparison.OrdinalIgnoreCase);

                        var risk = hasBypass ? RiskLevel.High
                                 : (nameHit && allMatches.Count >= 1) ? RiskLevel.High
                                 : allMatches.Count >= 3 ? RiskLevel.High
                                 : allMatches.Count >= 1 ? RiskLevel.Medium
                                 : RiskLevel.Low;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM script with speed hack keywords: {fn}",
                            Risk = risk,
                            Location = file,
                            FileName = fn,
                            Reason = $"FiveM client script '{fn}' in '{subDir}' " +
                                     (nameHit ? "has a speed-hack related file name and " : "") +
                                     (allMatches.Count > 0
                                         ? $"contains {allMatches.Count} speed-manipulation native(s): " +
                                           string.Join(", ", allMatches.Take(4).Select(m => $"'{m}'")) +
                                           (allMatches.Count > 4 ? " ..." : "") + ". "
                                         : ". ") +
                                     (hasBypass ? "File explicitly references speed multiplier bypass — a strong cheat indicator. " : "") +
                                     "FiveM client scripts using SetEntityMaxSpeed, SetGameSpeed, or time scale natives without " +
                                     "server authorization indicate speed hack cheat resources.",
                            Detail = $"Script dir: {subDir} | " +
                                     $"Matches ({allMatches.Count}): {string.Join(", ", allMatches.Take(6))} | " +
                                     $"Bypass reference: {hasBypass} | Name hit: {nameHit}",
                        });
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (c >= 'A' && c <= 'Z')
                sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z')
                sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else
                sb.Append(c);
        }
        return sb.ToString();
    }
}
