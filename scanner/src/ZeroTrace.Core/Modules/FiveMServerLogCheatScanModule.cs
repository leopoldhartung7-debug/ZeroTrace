using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMServerLogCheatScanModule : IScanModule
{
    public string Name => "FiveM Server Log Cheat Forensic Scan";
    public double Weight => 4.3;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] FiveMClientLogPatterns =
    [
        "natives::", "nativeInvoke", "Native.InvokeInternal", "citizen:invokeNative",
        "NetworkRequestControlOfEntity", "SetEntityCoords", "SetEntityHealth",
        "SetPedArmour", "GiveWeaponToPed", "AddExplosion", "NetworkExplodeVehicle",
        "CreateVehicle", "SpawnVehicle", "SetVehicleEngineOn",
        "SET_PED_COMPONENT_VARIATION", "SET_PLAYER_VISIBLE_LOCALLY",
        "NetworkRequestControlOf", "TaskGoToEntity", "SetEntityVisible",
        "SET_ENTITY_INVINCIBLE", "SET_ENTITY_AS_MISSION_ENTITY",
        "TELEPORT_TO_COORDS", "cheat menu", "mod menu", "executor", "bypass",
        "noclip", "godmode", "speedhack", "aimbot", "esp", "wallhack",
        "crash", "crasher", "freeze", "kick player", "spectate", "spectating",
        "player crash", "vehicle spawn menu", "weapon menu", "money drop",
        "resource injection", "resource exploit", "lua injection", "js injection",
        "event leak", "net event spam", "triggerEvent spam", "network event spam",
        "invalid event", "event blocked", "exploited resource", "cheat resource",
        "blocked teleport", "blocked spawn", "invalid native", "illegal native",
        "resource timeout", "resource crash", "lua error: cheat", "script error: exploit",
        "citizen_game", "citizen_wait bypass", "wait bypass", "illegal wait",
        "citizen_tick exploit", "tick exploit", "thread exploit",
    ];

    private static readonly string[] FiveMServerConsoleCrashPatterns =
    [
        "citizen crash", "cfx crash", "client crash", "fivem crash",
        "player disconnected: crash", "kernel crash", "exception in script",
        "script error detected", "resource error", "resource crash detected",
        "native error", "invalid native called", "memory access violation",
        "access violation in", "unhandled exception in cfx", "fivem exception",
        "cfx exception", "invalid resource state", "resource abuse",
        "kick reason: cheat", "ban reason: cheat", "detected cheat",
        "cheat detected", "ban for exploit", "exploit detected",
        "god mode detected", "speedhack detected", "teleport detected",
        "aimbot detected", "wallhack detected", "banned for cheating",
    ];

    private static readonly string[] CheatResourceKeywords =
    [
        "executor", "bypass", "injector", "cheatmenu", "modmenu", "trainer",
        "godmode", "noclip", "speedhack", "aimbot", "esp", "wallhack",
        "moneymod", "cashmod", "money_drop", "weapon_menu", "vehicle_menu",
        "teleport_menu", "fly_hack", "crash_menu", "kick_all", "freeze_all",
        "spectate_bypass", "anticheat_bypass", "evader", "bypassed",
        "lua_exec", "js_exec", "native_exec", "resource_inject",
        "fivem_cheat", "cfx_bypass", "citizen_bypass",
    ];

    private static readonly string[] SuspiciousResourceFolderNames =
    [
        "executor", "bypass", "injector", "cheat", "hack", "menu",
        "godmode", "noclip", "speedhack", "aimbot", "esp",
        "moneymod", "money_drop", "weapon_give", "vehicle_spawn",
        "teleport", "fly", "crasher", "kick", "freeze",
        "spectate", "anticheat_bypass", "evader",
        "lua_exec", "js_exec", "native_exec",
        "fivem_cheat", "cfx_bypass", "citizen_bypass",
        "lua_injection", "js_injection", "resource_injection",
    ];

    private static readonly string[] FiveMClientLogKeywords =
    [
        "cheat.dll", "cheat.exe", "hack.dll", "bypass.dll", "injector.exe",
        "aimbot", "wallhack", "godmode", "speedhack", "noclip",
        "modmenu", "trainer", "moneymod", "money_drop",
        "teleport", "fly hack", "crasher", "kick player", "freeze player",
        "spectate", "anticheat bypass", "evader", "bypass anticheat",
        "lua exec", "js exec", "native exec", "resource inject",
        "fivem cheat", "cfx bypass", "citizen bypass",
        "exploit", "lua injection", "js injection",
        "spawn vehicle", "give weapon", "set health", "set armour",
    ];

    private static readonly string[] FiveMCrashDumpKeywords =
    [
        "fivem cheat", "cfx cheat", "citizen cheat", "fivem exploit",
        "cheat.dll", "bypass.dll", "hack.dll", "injector.exe",
        "godmode", "speedhack", "noclip", "aimbot", "esp",
        "lua exec", "native exec", "resource inject",
        "fivem_hack", "cfx_hack", "gta5_cheat",
    ];

    private static readonly string[] FiveMEventSpamPatterns =
    [
        "triggerNetworkEvent spam", "triggerServerEvent spam", "event rate limit",
        "event flood", "rate limit exceeded", "too many events", "network event spam",
        "event blacklisted", "blocked event", "disallowed event",
        "net_framework", "network_framework cheat", "network bypass",
        "net_event exploit", "server event exploit",
    ];

    private static readonly string[] FiveMOffsetArtifactFiles =
    [
        "fivem_offsets.txt", "fivem_offsets.json", "fivem_addresses.txt",
        "fivem_addresses.json", "fivem_patterns.txt", "cfx_offsets.txt",
        "gta5_offsets.txt", "fivem_natives.json", "fivem_native_list.txt",
        "fivem_rpc.json", "cfx_rpc.txt", "fivem_functions.json",
        "fivem_structs.txt", "gta5_structs.json", "fivem_class_list.txt",
        "citizen_offsets.json", "citizen_natives.txt",
    ];

    private static readonly string[] FiveMDownloadCheatArtifacts =
    [
        "fivem_cheat.zip", "fivem_hack.zip", "fivem_menu.zip", "fivem_mod.zip",
        "fivem_cheat.rar", "fivem_hack.rar", "fivem_menu.rar", "fivem_mod.rar",
        "fivem_cheat.7z", "fivem_hack.7z", "cfx_cheat.zip", "cfx_hack.zip",
        "fivem_cheat_setup.exe", "fivem_hack_setup.exe", "fivem_menu_setup.exe",
        "fivem_bypass_setup.exe", "fivem_injector_setup.exe",
        "cfx_bypass_setup.exe", "citizen_hack_setup.exe",
        "fivem_cheat_v2.exe", "fivem_cheat_v3.exe", "fivem_hack_v2.exe",
        "fivem_menu_v2.exe", "fivem_modmenu.exe", "fivem_trainer.exe",
    ];

    private static readonly string[] FiveMDataFolderPaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FiveM"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "FiveM Application Data"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM Application Data"),
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckFiveMClientLogs(ctx, ct),
            CheckFiveMCrashDumps(ctx, ct),
            CheckFiveMResourceFolders(ctx, ct),
            CheckFiveMCacheForCheatArtifacts(ctx, ct),
            CheckFiveMOffsetArtifactFiles(ctx, ct),
            CheckFiveMDownloadArtifacts(ctx, ct),
            CheckFiveMEventSpamLogs(ctx, ct),
            CheckFiveMServerConsoleLogs(ctx, ct),
            CheckFiveMCitizenLogs(ctx, ct),
            CheckFiveMScriptHookArtifacts(ctx, ct),
            CheckRegistryUserAssist(ctx, ct),
            CheckRegistryMuiCache(ctx, ct),
            CheckFiveMNetworkLogs(ctx, ct),
            CheckFiveMInstallerArtifacts(ctx, ct),
            CheckFiveMRecentDocuments(ctx, ct)
        );
    }

    private Task CheckFiveMClientLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var fivemDir in FiveMDataFolderPaths)
        {
            if (!Directory.Exists(fivemDir)) continue;
            try
            {
                foreach (var logFile in Directory.EnumerateFiles(fivemDir, "*.log", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        foreach (var pattern in FiveMClientLogKeywords)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "FiveM client log contains cheat artifact",
                                    Risk = Risk.High,
                                    Location = Path.GetDirectoryName(logFile) ?? fivemDir,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"Client log contains cheat pattern: '{pattern}'",
                                    Detail = $"Log: {logFile}"
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

    private Task CheckFiveMCrashDumps(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var fivemDir in FiveMDataFolderPaths)
        {
            var dumpDirs = new[]
            {
                Path.Combine(fivemDir, "crashes"),
                Path.Combine(fivemDir, "logs", "crashes"),
                Path.Combine(fivemDir, "dump"),
            };
            foreach (var dumpDir in dumpDirs)
            {
                if (!Directory.Exists(dumpDir)) continue;
                try
                {
                    foreach (var dumpFile in Directory.EnumerateFiles(dumpDir, "*.txt", SearchOption.TopDirectoryOnly)
                        .Concat(Directory.EnumerateFiles(dumpDir, "*.log", SearchOption.TopDirectoryOnly)))
                    {
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(dumpFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            var lower = content.ToLowerInvariant();
                            foreach (var kw in FiveMCrashDumpKeywords)
                            {
                                if (lower.Contains(kw.ToLowerInvariant()))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "FiveM crash dump references cheat",
                                        Risk = Risk.Medium,
                                        Location = dumpDir,
                                        FileName = Path.GetFileName(dumpFile),
                                        Reason = $"Crash dump mentions cheat keyword: '{kw}'",
                                        Detail = $"File: {dumpFile}"
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
        }
    }, ct);

    private Task CheckFiveMResourceFolders(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var fivemDir in FiveMDataFolderPaths)
        {
            var resourceDir = Path.Combine(fivemDir, "resources");
            if (!Directory.Exists(resourceDir)) continue;
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(resourceDir, "*", SearchOption.TopDirectoryOnly))
                {
                    var folderName = Path.GetFileName(dir).ToLowerInvariant();
                    if (SuspiciousResourceFolderNames.Any(k => folderName.Contains(k.ToLowerInvariant())))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Suspicious FiveM resource folder",
                            Risk = Risk.High,
                            Location = resourceDir,
                            FileName = Path.GetFileName(dir),
                            Reason = $"FiveM resource folder has cheat-related name: '{Path.GetFileName(dir)}'",
                            Detail = $"Path: {dir}"
                        });
                    }

                    // Check for lua/js files with cheat patterns inside the resource
                    try
                    {
                        foreach (var script in Directory.EnumerateFiles(dir, "*.lua", SearchOption.AllDirectories)
                            .Concat(Directory.EnumerateFiles(dir, "*.js", SearchOption.AllDirectories)))
                        {
                            ctx.IncrementFiles();
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckFiveMCacheForCheatArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var fivemDir in FiveMDataFolderPaths)
        {
            var cacheDir = Path.Combine(fivemDir, "cache");
            if (!Directory.Exists(cacheDir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(cacheDir, "*.dll", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (CheatResourceKeywords.Any(k => fn.ToLowerInvariant().Contains(k.ToLowerInvariant())))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat DLL artifact in FiveM cache",
                            Risk = Risk.Critical,
                            Location = Path.GetDirectoryName(file) ?? cacheDir,
                            FileName = fn,
                            Reason = "Cheat-named DLL found in FiveM cache directory",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckFiveMOffsetArtifactFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanPaths = new List<string>(FiveMDataFolderPaths)
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };
        foreach (var dir in scanPaths)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (FiveMOffsetArtifactFiles.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM cheat offset/pattern file",
                            Risk = Risk.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = "Offset or address file used by FiveM cheat tools found",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckFiveMDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)),
        };
        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (FiveMDownloadCheatArtifacts.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM cheat download artifact",
                            Risk = Risk.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = "FiveM cheat package or installer found in downloads/desktop",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckFiveMEventSpamLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var fivemDir in FiveMDataFolderPaths)
        {
            if (!Directory.Exists(fivemDir)) continue;
            try
            {
                foreach (var logFile in Directory.EnumerateFiles(fivemDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(fivemDir, "*.txt", SearchOption.AllDirectories)))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        foreach (var pattern in FiveMEventSpamPatterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "FiveM event spam/exploit log",
                                    Risk = Risk.High,
                                    Location = Path.GetDirectoryName(logFile) ?? fivemDir,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"Log references event exploit pattern: '{pattern}'",
                                    Detail = $"Log: {logFile}"
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

    private Task CheckFiveMServerConsoleLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var serverLogPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "FiveM Server", "logs"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "FXServer", "logs"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "cfx-server", "logs"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FXServer"),
            @"C:\FXServer\logs",
            @"C:\FiveMServer\logs",
            @"C:\cfx-server-data\logs",
        };
        foreach (var logDir in serverLogPaths)
        {
            if (!Directory.Exists(logDir)) continue;
            try
            {
                foreach (var logFile in Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(logDir, "*.txt", SearchOption.AllDirectories)))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        int hitCount = 0;
                        foreach (var pattern in FiveMServerConsoleCrashPatterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                hitCount++;
                                if (hitCount == 1)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "FiveM server log: cheat activity detected",
                                        Risk = Risk.High,
                                        Location = logDir,
                                        FileName = Path.GetFileName(logFile),
                                        Reason = $"Server log records cheat detection or crash exploit: '{pattern}'",
                                        Detail = $"Log: {logFile}"
                                    });
                                }
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

    private Task CheckFiveMCitizenLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var fivemDir in FiveMDataFolderPaths)
        {
            var citizenDir = Path.Combine(fivemDir, "cache", "game");
            if (!Directory.Exists(citizenDir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(citizenDir, "*.log", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        foreach (var pattern in FiveMClientLogPatterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "FiveM citizen game log cheat pattern",
                                    Risk = Risk.High,
                                    Location = Path.GetDirectoryName(file) ?? citizenDir,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Game log contains cheat/exploit pattern: '{pattern}'",
                                    Detail = $"File: {file}"
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

    private Task CheckFiveMScriptHookArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var fivemDir in FiveMDataFolderPaths)
        {
            if (!Directory.Exists(fivemDir)) continue;
            try
            {
                var scriptHookFiles = new[] { "ScriptHookV.dll", "ScriptHookVDotNet.dll", "ScriptHookVDotNet2.dll", "ScriptHookVDotNet3.dll", "dinput8.dll", "dsound.dll", "bink2w64.dll" };
                foreach (var file in Directory.EnumerateFiles(fivemDir, "*.dll", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (scriptHookFiles.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "ScriptHook DLL in FiveM directory",
                            Risk = Risk.High,
                            Location = Path.GetDirectoryName(file) ?? fivemDir,
                            FileName = fn,
                            Reason = "ScriptHookV or proxy DLL found inside FiveM directory — used for native script execution bypass",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRegistryUserAssist(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                        ctx.IncrementRegistryKeys();
                        var decoded = Rot13Decode(valName).ToLowerInvariant();
                        bool isCheat = FiveMDownloadCheatArtifacts.Any(k => decoded.Contains(k.ToLowerInvariant().Replace(".zip", "").Replace(".rar", "").Replace(".7z", "")))
                            || decoded.Contains("fivem cheat") || decoded.Contains("fivem hack")
                            || decoded.Contains("cfx bypass") || decoded.Contains("fivem bypass")
                            || decoded.Contains("fivem modmenu") || decoded.Contains("fivem trainer")
                            || decoded.Contains("fivem injector") || decoded.Contains("fivem exploit");
                        if (isCheat)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM cheat execution (UserAssist)",
                                Risk = Risk.High,
                                Location = $@"HKCU\{uaPath}\{guidName}\Count",
                                FileName = decoded,
                                Reason = "UserAssist records execution of FiveM cheat-related tool",
                                Detail = $"Decoded: {decoded}"
                            });
                        }
                    }
                }
                catch (Exception) { }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckRegistryMuiCache(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                    ctx.IncrementRegistryKeys();
                    var lower = valName.ToLowerInvariant();
                    bool isCheat = lower.Contains("fivem cheat") || lower.Contains("fivem hack")
                        || lower.Contains("fivem bypass") || lower.Contains("fivem injector")
                        || lower.Contains("fivem modmenu") || lower.Contains("fivem trainer")
                        || lower.Contains("cfx bypass") || lower.Contains("cfx cheat")
                        || FiveMDownloadCheatArtifacts.Any(k => lower.Contains(k.ToLowerInvariant().Replace(".exe", "").Replace(".zip", "")));
                    if (isCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM cheat execution (MUICache)",
                            Risk = Risk.High,
                            Location = @"HKCU\" + muiPath,
                            FileName = Path.GetFileName(valName),
                            Reason = "MUICache records execution of FiveM cheat or bypass tool",
                            Detail = $"Entry: {valName}"
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckFiveMNetworkLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var fivemDir in FiveMDataFolderPaths)
        {
            var netLogDir = Path.Combine(fivemDir, "logs", "network");
            if (!Directory.Exists(netLogDir)) continue;
            try
            {
                foreach (var logFile in Directory.EnumerateFiles(netLogDir, "*", SearchOption.TopDirectoryOnly))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        foreach (var pattern in FiveMEventSpamPatterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "FiveM network log: exploit pattern",
                                    Risk = Risk.High,
                                    Location = netLogDir,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"Network log contains exploit pattern: '{pattern}'",
                                    Detail = $"File: {logFile}"
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

    private Task CheckFiveMInstallerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string uninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        try
        {
            using var uninst = Registry.CurrentUser.OpenSubKey(uninstallPath);
            if (uninst != null)
            {
                foreach (var subKeyName in uninst.GetSubKeyNames())
                {
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var sub = uninst.OpenSubKey(subKeyName);
                        var displayName = sub?.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        var lower = displayName.ToLowerInvariant();
                        if (lower.Contains("fivem cheat") || lower.Contains("fivem hack") || lower.Contains("fivem bypass")
                            || lower.Contains("cfx cheat") || lower.Contains("fivem modmenu")
                            || lower.Contains("fivem trainer") || lower.Contains("fivem injector"))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM cheat installer record",
                                Risk = Risk.High,
                                Location = $@"HKCU\{uninstallPath}\{subKeyName}",
                                FileName = displayName,
                                Reason = "Uninstall record found for FiveM cheat software",
                                Detail = $"Key: {subKeyName}, Name: {displayName}"
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckFiveMRecentDocuments(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var recentDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft", "Windows", "Recent");
        if (!Directory.Exists(recentDir)) return;
        try
        {
            foreach (var lnk in Directory.EnumerateFiles(recentDir, "*.lnk", SearchOption.TopDirectoryOnly))
            {
                ctx.IncrementFiles();
                var fn = Path.GetFileNameWithoutExtension(lnk).ToLowerInvariant();
                bool isFiveMCheat = fn.Contains("fivem cheat") || fn.Contains("fivem hack") || fn.Contains("fivem bypass")
                    || fn.Contains("cfx cheat") || fn.Contains("fivem modmenu") || fn.Contains("fivem trainer")
                    || fn.Contains("fivem injector") || fn.Contains("fivem menu")
                    || FiveMDownloadCheatArtifacts.Any(k => fn.Contains(k.ToLowerInvariant().Replace(".exe", "").Replace(".zip", "").Replace(".rar", "").Replace(".7z", "")));
                if (isFiveMCheat)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM cheat recent document",
                        Risk = Risk.Medium,
                        Location = recentDir,
                        FileName = Path.GetFileName(lnk),
                        Reason = "Windows Recent Documents contains link to FiveM cheat file",
                        Detail = $"Shortcut: {lnk}"
                    });
                }
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
