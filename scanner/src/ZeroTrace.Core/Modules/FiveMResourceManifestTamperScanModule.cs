using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMResourceManifestTamperScanModule : IScanModule
{
    public string Name => "FiveM Resource Manifest Tampering Detection";
    public double Weight => 4.4;
    public int ParallelGroup => 4;

    private static readonly string[] ManifestCheatKeywords =
    [
        "cheat", "hack", "exploit", "aimbot", "wallhack", "esp",
        "godmode", "noclip", "teleport", "speedhack", "money_drop",
        "moneydrop", "vehicle_spawn", "modmenu", "mod_menu",
        "bypass", "inject", "executor", "lua_executor", "native_spoof",
        "native_hook", "native_bypass", "invoke_native", "invokenative",
        "SetEntityInvincible", "SetPlayerInvincible", "NetworkSetFriendlyFireOption",
        "AddExplosion", "AddExplosionWithUserVars", "GiveWeaponToPed",
        "GiveAllWeapons", "NetworkHasControlOfEntity",
        "freeze_player", "freeze_ped", "freeze_vehicle",
        "super_jump", "infinite_ammo", "infinite_health",
        "remove_wanted", "set_wanted_level", "clear_wanted",
        "trigger_event", "trigger_server_event", "trigger_latent",
        "emit_net", "emit_server", "rpc_call", "native_invoke",
        "game_invoke", "invoke_bypass", "spoof_native",
    ];

    private static readonly string[] SuspiciousScriptPatterns =
    [
        "Citizen.InvokeNative(", "Citizen.InvokeNativeByHash(",
        "InvokeNative(", "SetEntityInvincible(",
        "SetPlayerInvincible(", "NetworkSetFriendlyFireOption(",
        "AddExplosion(", "AddExplosionWithUserVars(",
        "GiveWeaponToPed(", "GiveAllWeaponsToPed(",
        "SetEntityHealth(", "SetPedMaxHealth(",
        "SetVehicleEngineHealth(", "SetVehicleBodyHealth(",
        "NetworkHasControlOfEntity(", "SetNetworkIdExistsOnAllMachines(",
        "SpawnVehicle(", "CreateVehicle(",
        "SetEntityCoords(", "SetEntityVelocity(",
        "TeleportEntityToCoords(", "SetPedComponentVariation(",
        "RemoveWeaponsFromPed(", "ClearPedBloodDamage(",
        "SetPlayerWantedLevel(", "ClearPlayerWantedLevel(",
        "TriggerServerEvent(", "TriggerNetworkEvent(",
        "TriggerLatentServerEvent(", "TriggerEvent(",
        "exports[", "exports.", "GetPlayerPed(",
        "PlayerPedId(", "PlayerId(", "GetPlayers(",
        "GetAllPlayers(", "GetNumPlayerIndices(",
        "NetworkIsPlayerActive(",
        "require(", "load(", "loadstring(",
        "pcall(", "xpcall(",
        "dofile(", "loadfile(",
        "io.open(", "io.read(", "io.write(",
        "os.execute(", "os.getenv(",
    ];

    private static readonly string[] KnownMaliciousResourceDirNames =
    [
        "cheat", "hack", "exploit", "menu", "modmenu", "mod_menu",
        "aimbot", "wallhack", "esp", "godmode", "teleport",
        "speedhack", "money_drop", "moneydrop", "bypass",
        "executor", "lua_executor", "native_hook", "native_spoof",
        "native_bypass", "inject", "injector", "loader",
        "unlimited_ammo", "unlimited_health", "super_jump",
        "vehicle_god", "veh_god", "ped_god", "player_god",
        "no_clip", "fly", "fly_mod", "noclip", "superspeed",
        "super_speed", "night_vision", "thermal_vision",
        "remove_wanted", "star_remove", "cop_clear",
        "2take1", "eulen", "cherax", "kiddions", "impulse",
        "stand", "brutan", "force", "ketchup_menu",
        "gang_gang", "night", "lunax", "midnight",
        "atone", "simple", "shift", "partial", "gravity",
    ];

    private static readonly string[] CfxLogBypassPatterns =
    [
        "native bypass", "native hook", "invoke bypass",
        "injection detected", "cheat detected", "exploit detected",
        "unauthorized native", "unauthorized invoke",
        "anticheat triggered", "anti-cheat triggered",
        "resource blocked", "script blocked",
    ];

    private static readonly string[] ResourceManifestFiles =
    [
        "__resource.lua", "fxmanifest.lua",
    ];

    private static readonly string[] FiveMDataDirs;

    static FiveMResourceManifestTamperScanModule()
    {
        var dirs = new List<string>();
        string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        string? appData = Environment.GetEnvironmentVariable("APPDATA");

        if (localAppData != null)
        {
            dirs.Add(Path.Combine(localAppData, "FiveM"));
            dirs.Add(Path.Combine(localAppData, "FiveM", "FiveM.app"));
            dirs.Add(Path.Combine(localAppData, "FiveM", "FiveM Application Data"));
        }
        if (appData != null)
        {
            dirs.Add(Path.Combine(appData, "CitizenFX"));
            dirs.Add(Path.Combine(appData, "FiveM"));
        }

        FiveMDataDirs = [.. dirs];
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            ScanResourceManifestsForCheatKeywords(ctx, ct),
            ScanLuaFilesForSuspiciousPatterns(ctx, ct),
            ScanJavaScriptFilesForSuspiciousPatterns(ctx, ct),
            ScanForMaliciousResourceDirNames(ctx, ct),
            CheckCitizenFxLogForBypassPatterns(ctx, ct),
            ScanCacheForCheatResources(ctx, ct),
            CheckFiveMIntegrityFiles(ctx, ct),
            ScanCfxConfigForBypassKeywords(ctx, ct),
            CheckStreamDirForCheatAssets(ctx, ct),
            ScanFiveMRegistryArtifacts(ctx, ct)
        ).ConfigureAwait(false);
    }

    private Task ScanResourceManifestsForCheatKeywords(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string baseDir in FiveMDataDirs)
            {
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (string manifestFile in Directory.EnumerateFiles(
                        baseDir, "fxmanifest.lua", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var fs = new FileStream(manifestFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            foreach (string kw in ManifestCheatKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Cheat Keyword in FiveM Resource Manifest",
                                        Risk = Risk.Critical,
                                        Location = manifestFile,
                                        FileName = Path.GetFileName(manifestFile),
                                        Reason = $"fxmanifest.lua contains cheat/exploit keyword: '{kw}'",
                                        Detail = $"Malicious manifest keyword in: {manifestFile}"
                                    });
                                    ctx.IncrementFiles();
                                    break;
                                }
                            }
                        }
                        catch (IOException) { }
                    }

                    foreach (string manifestFile in Directory.EnumerateFiles(
                        baseDir, "__resource.lua", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var fs = new FileStream(manifestFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            foreach (string kw in ManifestCheatKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Cheat Keyword in FiveM Legacy Resource Manifest",
                                        Risk = Risk.Critical,
                                        Location = manifestFile,
                                        FileName = Path.GetFileName(manifestFile),
                                        Reason = $"__resource.lua contains cheat keyword: '{kw}'",
                                        Detail = $"Legacy manifest with cheat keyword: {manifestFile}"
                                    });
                                    ctx.IncrementFiles();
                                    break;
                                }
                            }
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanLuaFilesForSuspiciousPatterns(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string baseDir in FiveMDataDirs)
            {
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (string luaFile in Directory.EnumerateFiles(baseDir, "*.lua", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(luaFile);
                        if (fn.Equals("fxmanifest.lua", StringComparison.OrdinalIgnoreCase) ||
                            fn.Equals("__resource.lua", StringComparison.OrdinalIgnoreCase)) continue;

                        try
                        {
                            using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            int suspiciousCount = 0;
                            var foundPatterns = new List<string>();
                            foreach (string pattern in SuspiciousScriptPatterns)
                            {
                                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                {
                                    suspiciousCount++;
                                    foundPatterns.Add(pattern);
                                    if (suspiciousCount >= 3) break;
                                }
                            }

                            if (suspiciousCount >= 2)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Suspicious Lua Script with Multiple Cheat Patterns",
                                    Risk = suspiciousCount >= 4 ? Risk.Critical : Risk.High,
                                    Location = luaFile,
                                    FileName = fn,
                                    Reason = $"Lua script contains {suspiciousCount} cheat/native-abuse patterns",
                                    Detail = $"Patterns found: {string.Join(", ", foundPatterns)} in {luaFile}"
                                });
                                ctx.IncrementFiles();
                            }
                            else if (suspiciousCount == 1 &&
                                     (content.Contains("aimbot", StringComparison.OrdinalIgnoreCase) ||
                                      content.Contains("wallhack", StringComparison.OrdinalIgnoreCase) ||
                                      content.Contains("esp", StringComparison.OrdinalIgnoreCase) ||
                                      content.Contains("godmode", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Lua Script with Cheat Indicator",
                                    Risk = Risk.High,
                                    Location = luaFile,
                                    FileName = fn,
                                    Reason = "Lua script contains cheat functionality identifier",
                                    Detail = $"Cheat Lua script found: {luaFile}"
                                });
                                ctx.IncrementFiles();
                            }
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanJavaScriptFilesForSuspiciousPatterns(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string baseDir in FiveMDataDirs)
            {
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (string jsFile in Directory.EnumerateFiles(baseDir, "*.js", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            int suspiciousCount = 0;
                            var foundPatterns = new List<string>();
                            foreach (string pattern in SuspiciousScriptPatterns)
                            {
                                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                {
                                    suspiciousCount++;
                                    foundPatterns.Add(pattern);
                                    if (suspiciousCount >= 4) break;
                                }
                            }

                            if (suspiciousCount >= 2)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Suspicious JavaScript Resource with Cheat Patterns",
                                    Risk = suspiciousCount >= 4 ? Risk.Critical : Risk.High,
                                    Location = jsFile,
                                    FileName = Path.GetFileName(jsFile),
                                    Reason = $"JS resource contains {suspiciousCount} cheat/native-abuse patterns",
                                    Detail = $"Patterns: {string.Join(", ", foundPatterns)} in {jsFile}"
                                });
                                ctx.IncrementFiles();
                            }
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanForMaliciousResourceDirNames(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string baseDir in FiveMDataDirs)
            {
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (string dir in Directory.EnumerateDirectories(baseDir, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string dn = Path.GetFileName(dir);
                        foreach (string malDir in KnownMaliciousResourceDirNames)
                        {
                            if (dn.Equals(malDir, StringComparison.OrdinalIgnoreCase)
                                || dn.Contains(malDir, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Known Cheat Resource Directory in FiveM Data",
                                    Risk = Risk.Critical,
                                    Location = dir,
                                    FileName = dn,
                                    Reason = $"Directory name '{dn}' matches known FiveM cheat resource",
                                    Detail = $"Malicious resource directory: {dir}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckCitizenFxLogForBypassPatterns(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string baseDir in FiveMDataDirs)
            {
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (string logFile in Directory.EnumerateFiles(baseDir, "CitizenFX.log", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            foreach (string pattern in CfxLogBypassPatterns)
                            {
                                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "FiveM Log Contains Bypass/Cheat Detection Pattern",
                                        Risk = Risk.High,
                                        Location = logFile,
                                        FileName = Path.GetFileName(logFile),
                                        Reason = $"CitizenFX.log contains suspicious pattern: '{pattern}'",
                                        Detail = $"Log indicates cheat/bypass activity: {logFile}"
                                    });
                                    ctx.IncrementFiles();
                                    break;
                                }
                            }
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanCacheForCheatResources(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string baseDir in FiveMDataDirs)
            {
                if (!Directory.Exists(baseDir)) continue;

                string cacheDir = Path.Combine(baseDir, "cache");
                if (!Directory.Exists(cacheDir)) continue;

                try
                {
                    foreach (string file in Directory.EnumerateFiles(cacheDir, "*.exe", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Executable File in FiveM Cache Directory",
                            Risk = Risk.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Executable found in FiveM cache — not a legitimate cache file",
                            Detail = $"Suspicious EXE in FiveM cache: {file}"
                        });
                        ctx.IncrementFiles();
                    }
                }
                catch (UnauthorizedAccessException) { }

                try
                {
                    foreach (string dir in Directory.EnumerateDirectories(cacheDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        string dn = Path.GetFileName(dir);
                        foreach (string malDir in KnownMaliciousResourceDirNames)
                        {
                            if (dn.Equals(malDir, StringComparison.OrdinalIgnoreCase)
                                || dn.Contains(malDir, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Cheat Resource Cached in FiveM Cache",
                                    Risk = Risk.Critical,
                                    Location = dir,
                                    FileName = dn,
                                    Reason = $"FiveM cached a cheat resource named '{dn}'",
                                    Detail = $"Cheat resource in cache: {dir}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckFiveMIntegrityFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (localAppData == null) return;

            string fivemDir = Path.Combine(localAppData, "FiveM");
            if (!Directory.Exists(fivemDir)) return;

            string[] coreFiles =
            [
                "FiveM.exe", "FiveM_b2545_GTAProcess.exe",
                "FiveM_b2699_GTAProcess.exe", "FiveM_ROSLauncher.exe",
            ];

            try
            {
                foreach (string coreFile in coreFiles)
                {
                    string fullPath = Path.Combine(fivemDir, coreFile);
                    if (!File.Exists(fullPath)) continue;
                    try
                    {
                        var fi = new FileInfo(fullPath);
                        if (fi.Length < 1_000_000)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Core Executable Suspiciously Small",
                                Risk = Risk.High,
                                Location = fullPath,
                                FileName = coreFile,
                                Reason = "FiveM core executable is much smaller than expected — possible replacement",
                                Detail = $"'{coreFile}' is only {fi.Length} bytes"
                            });
                            ctx.IncrementFiles();
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task ScanCfxConfigForBypassKeywords(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string baseDir in FiveMDataDirs)
            {
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (string cfgFile in Directory.EnumerateFiles(baseDir, "*.cfg", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var fs = new FileStream(cfgFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            foreach (string kw in ManifestCheatKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Cheat Keyword in FiveM Config File",
                                        Risk = Risk.High,
                                        Location = cfgFile,
                                        FileName = Path.GetFileName(cfgFile),
                                        Reason = $"FiveM .cfg file contains cheat keyword: '{kw}'",
                                        Detail = $"Cheat config: {cfgFile}"
                                    });
                                    ctx.IncrementFiles();
                                    break;
                                }
                            }
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckStreamDirForCheatAssets(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string baseDir in FiveMDataDirs)
            {
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (string dir in Directory.EnumerateDirectories(baseDir, "stream", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            foreach (string file in Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories))
                            {
                                ct.ThrowIfCancellationRequested();
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "DLL Found in FiveM Stream Directory",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = "DLL file in stream/ directory — not a valid streaming asset, possible injection payload",
                                    Detail = $"DLL in stream dir: {file}"
                                });
                                ctx.IncrementFiles();
                            }

                            foreach (string file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                            {
                                ct.ThrowIfCancellationRequested();
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "EXE Found in FiveM Stream Directory",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = "Executable in stream/ directory — not a valid streaming asset, possible payload",
                                    Detail = $"EXE in stream dir: {file}"
                                });
                                ctx.IncrementFiles();
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanFiveMRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using RegistryKey? muiCache = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
                if (muiCache == null) return;

                string[] cheatToolNames =
                [
                    "2take1", "eulen", "cherax", "kiddions", "impulse", "stand",
                    "brutan", "force", "ketchup", "gang_gang", "lunax", "midnight",
                    "atone", "modmenu", "mod_menu", "fivem_cheat", "fivem_hack",
                ];

                foreach (string valName in muiCache.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (string cheatTool in cheatToolNames)
                    {
                        if (valName.Contains(cheatTool, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Cheat Tool Execution Evidence in MUICache",
                                Risk = Risk.Critical,
                                Location = @"HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                                FileName = "registry",
                                Reason = $"MUICache records previous execution of FiveM cheat tool: '{cheatTool}'",
                                Detail = $"MUICache entry: {valName}"
                            });
                            ctx.IncrementRegistryKeys();
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }
}
