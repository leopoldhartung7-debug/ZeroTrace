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

public sealed class AltVDeepCheatForensicScanModule : IScanModule
{
    public string Name => "alt:V Deep Cheat Forensic Scan";
    public double Weight => 4.2;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] AltVCheatExecutables =
    [
        "altv_cheat.exe", "altv_hack.exe", "altv_menu.exe", "altv_modmenu.exe",
        "altv_trainer.exe", "altv_injector.exe", "altv_bypass.exe", "altv_exploit.exe",
        "altv_esp.exe", "altv_aimbot.exe", "altv_wallhack.exe", "altv_godmode.exe",
        "altv_noclip.exe", "altv_speedhack.exe", "altv_teleport.exe", "altv_fly.exe",
        "altv_moneymod.exe", "altv_money.exe", "altv_cash.exe", "altv_rp.exe",
        "altv_vehicle.exe", "altv_weapon.exe", "altv_spawnmenu.exe",
        "altv_internal.exe", "altv_external.exe", "altv_recovery.exe",
        "altv_crasher.exe", "altv_kick.exe", "altv_freeze.exe",
        "altv_spectate.exe", "altv_anticheat_bypass.exe", "altv_evader.exe",
        "altv_lua_exec.exe", "altv_js_exec.exe", "altv_native_exec.exe",
        "gta5_altv_cheat.exe", "gta_altv_hack.exe", "altvcheats.exe", "altv_chts.exe",
    ];

    private static readonly string[] AltVCheatDlls =
    [
        "altv_cheat.dll", "altv_hack.dll", "altv_bypass.dll", "altv_inject.dll",
        "altv_esp.dll", "altv_aimbot.dll", "altv_wallhack.dll", "altv_godmode.dll",
        "altv_noclip.dll", "altv_speed.dll", "altv_teleport.dll", "altv_fly.dll",
        "altv_money.dll", "altv_vehicle.dll", "altv_weapon.dll", "altv_crash.dll",
        "altv_native.dll", "altv_lua.dll", "altv_js.dll", "altv_script.dll",
        "altv_internal.dll", "altv_external.dll", "altv_hook.dll", "altv_d3d.dll",
        "altv_overlay.dll", "altv_radar.dll", "altv_maphack.dll",
        "altv_anticheat_bypass.dll", "altv_evader.dll", "altv_bypasser.dll",
    ];

    private static readonly string[] AltVResourceCheatNames =
    [
        "altv-cheat", "altv-hack", "altv-menu", "altv-modmenu", "altv-trainer",
        "altv-godmode", "altv-noclip", "altv-speedhack", "altv-aimbot", "altv-esp",
        "altv-teleport", "altv-fly", "altv-money", "altv-vehicle", "altv-weapon",
        "altv-crasher", "altv-kick", "altv-freeze", "altv-spectate",
        "altv-anticheat-bypass", "altv-evader", "altv-bypass",
        "altv-lua-exec", "altv-js-exec", "altv-native-exec",
        "altv-inject", "altv-exploit", "altv-recovery",
        "cheat", "hack", "modmenu", "trainer", "godmode", "noclip", "speedhack",
        "aimbot", "esp", "wallhack", "crasher", "exploiter", "bypass", "evader",
        "money_drop", "weapon_give", "vehicle_spawn", "teleport_menu", "fly_hack",
    ];

    private static readonly string[] AltVServerLogCheatPatterns =
    [
        "cheat detected", "hack detected", "exploit detected", "godmode detected",
        "speedhack detected", "teleport detected", "aimbot detected", "esp detected",
        "noclip detected", "vehicle spawn spam", "weapon spawn spam", "money cheat",
        "invalid native", "native blocked", "illegal native call", "native exploit",
        "resource exploit", "lua exploit", "js exploit", "script exploit",
        "event exploit", "event spam", "event flood", "event rate limit",
        "client crash", "player crash", "crash exploit", "crash cheat",
        "ban for cheating", "kick for cheating", "ban reason: cheat",
        "kick reason: cheat", "detected cheat", "banned cheater",
        "resource injection", "injected resource", "unauthorized resource",
        "resource blacklisted", "resource blocked",
    ];

    private static readonly string[] AltVClientLogCheatPatterns =
    [
        "altv cheat", "altv hack", "altv bypass", "altv exploit",
        "cheat menu", "mod menu", "godmode enabled", "noclip enabled",
        "speedhack enabled", "aimbot enabled", "esp enabled",
        "teleport", "fly hack", "money cheat", "vehicle spam",
        "native exec", "lua exec", "js exec", "native bypass",
        "anticheat bypass", "evader", "bypass anticheat",
        "crash player", "kick player", "freeze player", "spectate",
        "resource inject", "lua inject", "js inject",
    ];

    private static readonly string[] AltVOffsetFiles =
    [
        "altv_offsets.txt", "altv_offsets.json", "altv_addresses.txt",
        "altv_addresses.json", "altv_patterns.txt", "altv_natives.json",
        "altv_native_list.txt", "altv_rpc.json", "altv_functions.json",
        "altv_structs.txt", "altv_class_list.txt", "altv_sdk_offsets.txt",
        "gta5_altv_offsets.txt", "gta5_altv_addresses.json",
    ];

    private static readonly string[] AltVJsCheatPatterns =
    [
        "native.invoke", "alt.natives", "game.getEntityFromHandle", "mp.players.list",
        "alt.emit('cheat'", "alt.emit('hack'", "alt.emit('godmode'", "alt.emit('noclip'",
        "executeNative", "invokeNative", "bypassAnticheat", "disableAnticheat",
        "setEntityHealth(0", "giveWeapon(", "createVehicle(", "setCoords(teleport",
        "aimbot", "wallhack", "esp", "speedhack", "noclip", "godmode",
        "crashPlayer", "kickPlayer", "freezePlayer", "spectatePlayer",
        "moneyCheat", "setMoney(", "cashCheat", "vehicleSpawn",
        "resourceInject", "luaExec", "jsExec", "nativeExec",
    ];

    private static readonly string[] AltVCsharpCheatPatterns =
    [
        "AltV.Net.Natives", "AltV.Net.CheatBypass", "AltV.Net.Hack",
        "NativeInvoke.Invoke", "Natives.GIVE_WEAPON_TO_PED",
        "Natives.SET_ENTITY_COORDS", "Natives.SET_ENTITY_INVINCIBLE",
        "cheatMenu", "modMenu", "godMode", "noclip", "speedHack",
        "aimbot", "wallHack", "espOverlay", "teleportPlayer",
        "crashPlayer", "kickPlayer", "moneyCheat", "vehicleSpawn",
        "bypassAnticheat", "disableAnticheat", "evadeAnticheat",
    ];

    private static readonly string[] AltVDataPaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "altv"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "alt-v"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "alt-v"),
    ];

    private static readonly string[] AltVDownloadArtifacts =
    [
        "altv_cheat.zip", "altv_hack.zip", "altv_menu.zip", "altv_modmenu.zip",
        "altv_cheat.rar", "altv_hack.rar", "altv_menu.rar", "altv_modmenu.rar",
        "altv_cheat.7z", "altv_hack.7z", "altv_cheat_setup.exe", "altv_hack_setup.exe",
        "altv_menu_setup.exe", "altv_bypass_setup.exe", "altv_injector_setup.exe",
        "altvcheats_loader.exe", "altv_cheat_v2.exe", "altv_hack_v2.exe",
        "altv_modmenu.exe", "altv_trainer_v2.exe",
    ];

    private static readonly string[] AltVRegistryCheatKeys =
    [
        @"SOFTWARE\AltVCheat", @"SOFTWARE\AltVHack", @"SOFTWARE\AltVMenu",
        @"SOFTWARE\AltVBypass", @"SOFTWARE\AltVModMenu", @"SOFTWARE\AltVTrainer",
        @"SOFTWARE\AltVGodmode", @"SOFTWARE\AltVInjector",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckAltVCheatExecutables(ctx, ct),
            CheckAltVCheatDlls(ctx, ct),
            CheckAltVResourceFolders(ctx, ct),
            CheckAltVServerLogs(ctx, ct),
            CheckAltVClientLogs(ctx, ct),
            CheckAltVJsCheatScripts(ctx, ct),
            CheckAltVCsharpCheatScripts(ctx, ct),
            CheckAltVOffsetFiles(ctx, ct),
            CheckAltVDownloadArtifacts(ctx, ct),
            CheckRegistryKeysForAltVCheats(ctx, ct),
            CheckUserAssistForAltVCheats(ctx, ct),
            CheckMuiCacheForAltVCheats(ctx, ct),
            CheckAltVInstallerRecords(ctx, ct),
            CheckAltVCacheForCheatDlls(ctx, ct),
            CheckAltVRecentDocuments(ctx, ct)
        );
    }

    private Task CheckAltVCheatExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(AltVDataPaths)
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };
        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (AltVCheatExecutables.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V cheat executable",
                            Risk = Risk.Critical,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = "Known alt:V cheat executable detected",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVCheatDlls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(AltVDataPaths)
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };
        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (AltVCheatDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V cheat DLL",
                            Risk = Risk.Critical,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = "Known alt:V cheat DLL detected",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVResourceFolders(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var altVDir in AltVDataPaths)
        {
            var resourceDir = Path.Combine(altVDir, "resources");
            if (!Directory.Exists(resourceDir)) continue;
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(resourceDir, "*", SearchOption.TopDirectoryOnly))
                {
                    var folderName = Path.GetFileName(dir).ToLowerInvariant();
                    if (AltVResourceCheatNames.Any(k => folderName.Contains(k.ToLowerInvariant())))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Suspicious alt:V resource folder",
                            Risk = Risk.High,
                            Location = resourceDir,
                            FileName = Path.GetFileName(dir),
                            Reason = $"alt:V resource folder has cheat-related name: '{Path.GetFileName(dir)}'",
                            Detail = $"Path: {dir}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVServerLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var serverLogDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "altv-server", "logs"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "alt-v-server", "logs"),
            @"C:\altv-server\logs",
            @"C:\alt-v-server\logs",
        };
        foreach (var logDir in serverLogDirs)
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
                        foreach (var pattern in AltVServerLogCheatPatterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "alt:V server log: cheat detected",
                                    Risk = Risk.High,
                                    Location = logDir,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"Server log records cheat activity: '{pattern}'",
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

    private Task CheckAltVClientLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var altVDir in AltVDataPaths)
        {
            if (!Directory.Exists(altVDir)) continue;
            try
            {
                foreach (var logFile in Directory.EnumerateFiles(altVDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(altVDir, "*.txt", SearchOption.AllDirectories)))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        foreach (var pattern in AltVClientLogCheatPatterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "alt:V client log cheat artifact",
                                    Risk = Risk.High,
                                    Location = Path.GetDirectoryName(logFile) ?? altVDir,
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

    private Task CheckAltVJsCheatScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var altVDir in AltVDataPaths)
        {
            var resourceDir = Path.Combine(altVDir, "resources");
            if (!Directory.Exists(resourceDir)) continue;
            try
            {
                foreach (var jsFile in Directory.EnumerateFiles(resourceDir, "*.js", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        int hits = 0;
                        foreach (var pattern in AltVJsCheatPatterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                                hits++;
                        }
                        if (hits >= 3)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V JS resource with cheat patterns",
                                Risk = Risk.Critical,
                                Location = Path.GetDirectoryName(jsFile) ?? resourceDir,
                                FileName = Path.GetFileName(jsFile),
                                Reason = $"JS resource file contains {hits} cheat patterns (native manipulation, aimbot, speedhack etc.)",
                                Detail = $"Path: {jsFile}"
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

    private Task CheckAltVCsharpCheatScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var altVDir in AltVDataPaths)
        {
            var resourceDir = Path.Combine(altVDir, "resources");
            if (!Directory.Exists(resourceDir)) continue;
            try
            {
                foreach (var csFile in Directory.EnumerateFiles(resourceDir, "*.cs", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(resourceDir, "*.dll", SearchOption.AllDirectories)))
                {
                    ctx.IncrementFiles();
                    var ext = Path.GetExtension(csFile).ToLowerInvariant();
                    if (ext != ".cs") continue;
                    try
                    {
                        using var fs = new FileStream(csFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        int hits = 0;
                        foreach (var pattern in AltVCsharpCheatPatterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                                hits++;
                        }
                        if (hits >= 3)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V C# resource with cheat patterns",
                                Risk = Risk.Critical,
                                Location = Path.GetDirectoryName(csFile) ?? resourceDir,
                                FileName = Path.GetFileName(csFile),
                                Reason = $"C# resource file contains {hits} cheat patterns (native manipulation, aimbot etc.)",
                                Detail = $"Path: {csFile}"
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

    private Task CheckAltVOffsetFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(AltVDataPaths)
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
                    if (AltVOffsetFiles.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V cheat offset/address file",
                            Risk = Risk.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = "Offset or pattern file used by alt:V cheat tools",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                    if (AltVDownloadArtifacts.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V cheat download artifact",
                            Risk = Risk.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = "alt:V cheat package or setup file found",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRegistryKeysForAltVCheats(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var keyPath in AltVRegistryCheatKeys)
        {
            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V cheat registry key",
                        Risk = Risk.High,
                        Location = @"HKCU\" + keyPath,
                        FileName = string.Empty,
                        Reason = "Registry key left by alt:V cheat installation",
                        Detail = $"Key: HKCU\\{keyPath}"
                    });
                }
            }
            catch (Exception) { }
        }

        try
        {
            ctx.IncrementRegistryKeys();
            using var run = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
            if (run != null)
            {
                foreach (var val in run.GetValueNames())
                {
                    var data = run.GetValue(val)?.ToString() ?? string.Empty;
                    var lower = data.ToLowerInvariant();
                    if (lower.Contains("altv cheat") || lower.Contains("altv hack") || lower.Contains("altv bypass")
                        || lower.Contains("altv modmenu") || lower.Contains("altv trainer")
                        || AltVCheatExecutables.Any(k => lower.Contains(k.ToLowerInvariant().Replace(".exe", ""))))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V cheat autostart (Run key)",
                            Risk = Risk.High,
                            Location = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                            FileName = val,
                            Reason = "alt:V cheat configured to auto-start via Run registry key",
                            Detail = $"Value: {val} = {data}"
                        });
                    }
                }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckUserAssistForAltVCheats(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                        bool isCheat = AltVCheatExecutables.Any(k => decoded.Contains(k.ToLowerInvariant().Replace(".exe", "")))
                            || decoded.Contains("altv cheat") || decoded.Contains("altv hack")
                            || decoded.Contains("altv bypass") || decoded.Contains("altv modmenu")
                            || decoded.Contains("altv trainer") || decoded.Contains("altv injector");
                        if (isCheat)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V cheat execution (UserAssist)",
                                Risk = Risk.High,
                                Location = $@"HKCU\{uaPath}\{guidName}\Count",
                                FileName = decoded,
                                Reason = "UserAssist records execution of alt:V cheat tool",
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

    private Task CheckMuiCacheForAltVCheats(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                    bool isCheat = AltVCheatExecutables.Any(k => lower.Contains(k.ToLowerInvariant().Replace(".exe", "")))
                        || lower.Contains("altv cheat") || lower.Contains("altv hack")
                        || lower.Contains("altv bypass") || lower.Contains("altv modmenu")
                        || lower.Contains("altv trainer") || lower.Contains("altv injector");
                    if (isCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V cheat execution (MUICache)",
                            Risk = Risk.High,
                            Location = @"HKCU\" + muiPath,
                            FileName = Path.GetFileName(valName),
                            Reason = "MUICache records execution of alt:V cheat tool",
                            Detail = $"Entry: {valName}"
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckAltVInstallerRecords(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var sub = uninst.OpenSubKey(subKeyName);
                        var displayName = sub?.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        var lower = displayName.ToLowerInvariant();
                        if (lower.Contains("altv cheat") || lower.Contains("altv hack") || lower.Contains("altv bypass")
                            || lower.Contains("altv modmenu") || lower.Contains("altv trainer"))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V cheat installer record",
                                Risk = Risk.High,
                                Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                FileName = displayName,
                                Reason = "Uninstall record found for alt:V cheat software",
                                Detail = $"Key: {subKeyName}, Name: {displayName}"
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckAltVCacheForCheatDlls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var altVDir in AltVDataPaths)
        {
            var cacheDir = Path.Combine(altVDir, "data");
            if (!Directory.Exists(cacheDir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(cacheDir, "*.dll", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (AltVCheatDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat DLL in alt:V data folder",
                            Risk = Risk.Critical,
                            Location = Path.GetDirectoryName(file) ?? cacheDir,
                            FileName = fn,
                            Reason = "Known cheat DLL found inside alt:V data directory",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVRecentDocuments(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var recentDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft", "Windows", "Recent");
        if (!Directory.Exists(recentDir)) return;
        try
        {
            foreach (var lnk in Directory.EnumerateFiles(recentDir, "*.lnk", SearchOption.TopDirectoryOnly))
            {
                ctx.IncrementFiles();
                var fn = Path.GetFileNameWithoutExtension(lnk).ToLowerInvariant();
                bool isAltVCheat = fn.Contains("altv cheat") || fn.Contains("altv hack") || fn.Contains("altv bypass")
                    || fn.Contains("altv modmenu") || fn.Contains("altv trainer") || fn.Contains("altv injector")
                    || AltVDownloadArtifacts.Any(k => fn.Contains(k.ToLowerInvariant().Replace(".exe", "").Replace(".zip", "").Replace(".rar", "").Replace(".7z", "")));
                if (isAltVCheat)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V cheat recent document",
                        Risk = Risk.Medium,
                        Location = recentDir,
                        FileName = Path.GetFileName(lnk),
                        Reason = "Recent Documents contains link to alt:V cheat file",
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
