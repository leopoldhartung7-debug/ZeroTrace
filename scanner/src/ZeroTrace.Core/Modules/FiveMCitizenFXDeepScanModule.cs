using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class FiveMCitizenFXDeepScanModule : IScanModule
{
    public string Name => "FiveM / CitizenFX Deep Analysis";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] CheatResourceNames = new[]
    {
        "cheat", "hack", "esp", "aimbot", "wallhack", "triggerbot", "noclip", "godmode",
        "kiddion", "stand", "eulen", "disturbed", "2take1", "midnight", "cherax",
        "cobramod", "excalibur", "frostbyte", "modmenu", "trainer",
        "moneydrop", "cashdrop", "rpdrop", "weaponmod", "speedhack",
        "teleport", "superjump", "superrun", "invcible", "invincible",
        "unlock", "unlocker", "carspawn", "vehspawn", "objectspawn",
        "bypass", "anticheat", "inject", "dll", "exploit",
        "lua_", "lua-", "luamod", "scripthook", "asi",
        "keylogger", "stealer", "rat", "remote", "control",
        "freecam", "nametag", "radar", "minimap", "worldedit",
    };

    private static readonly string[] CheatLuaKeywords = new[]
    {
        "GetPlayerPed", "SetEntityCoords", "SetPlayerInvincible", "GiveWeaponToPed",
        "SetPedMaxHealth", "NetworkGetEntityOwner", "GetEntityCoords",
        "RequestModel", "CreateVehicle", "DeleteEntity",
        "ped:addBlip", "AddExplosion", "ShootSingleBulletBetweenCoords",
        "SetPedArmour", "AddAmmoToPed", "SetWeaponAmmoCount",
        "NetworkRequestControlOfEntity", "IsEntityAVehicle",
        "GetClosestPed", "GetClosestVehicle", "GetNearbyEntities",
        "SetVehicleEngineHealth", "SetVehicleBodyHealth",
        "N_0x", "Citizen.InvokeNative", "Citizen.Await",
        "LoadInterior", "SetInteriorActive",
        "SetEntityVisible", "SetEntityAlpha",
        "GetPlayerFromServerId", "GetPlayerPedScriptIndex",
        "TriggerServerEvent.*cheat", "TriggerServerEvent.*hack",
        "TriggerServerEvent.*admin", "TriggerServerEvent.*bypass",
        "exports.*cheat", "exports.*hack",
        "RegisterNetEvent.*cheat",
        "GetVehiclePedIsIn",
        "SetVehicleHandlingFloat", "ModifyVehicle",
        "GetEntityHealth", "SetEntityHealth",
    };

    private static readonly string[] CheatScriptKeywords = new[]
    {
        "inject", "bypass", "cheat", "hack", "exploit", "godmode", "noclip",
        "aimbot", "esp", "wallhack", "spinbot", "bhop", "teleport",
        "money", "cash", "rp", "level", "unlock", "unlocker",
        "anticheat_bypass", "ac_bypass", "eac_bypass", "fiveguard_bypass",
        "screengrab_bypass", "screenshot_bypass", "anticheat disable",
        "GetPlayerIdentifiers", "GetPlayerTokens", "GetPlayerIps",
        "TriggerClientEvent.*ExecuteCommand",
        "ExecuteCommand.*add_principal",
        "AddAce", "AddPrincipal",
        "SetTimeout.*0.*function", "Citizen.SetTimeout.*0",
        "while true do", "while(true)",
        "pcall", "xpcall",
        "load(", "loadstring(", "dofile(",
        "rawget", "rawset", "rawequal",
        "getfenv", "setfenv", "getmetatable", "setmetatable",
        "debug.getinfo", "debug.sethook",
    };

    private static readonly string[] FiveMCheatServerHosts = new[]
    {
        "kiddionsmods", "stand.gg", "eulen.xyz", "disturbed.lol", "2take1.menu",
        "midnight.gg", "cherax.net", "lynxmenu.com", "redengine.cc",
        "cobramodmenu", "excaliburcheat", "frostbytecheat",
        "fivemcheats", "fivemhacks", "fivembypass",
        "guardbypass", "fiveguardbypass", "anticheatbypass",
    };

    private static readonly string[] ScreenshotBypassIndicators = new[]
    {
        "screengrab", "screenshot_basic", "screenshot-basic", "nui_screenshot",
        "Screenshot", "sc_nui", "sc-nui",
        "SetNuiCallback.*screenshot", "RegisterNuiCallback.*screenshot",
        "bypass", "hide", "invisible", "transparent", "opacity",
    };

    private static readonly string[] FiveMResourcePaths = new[]
    {
        @"FiveM Application Data\resources",
        @"FiveM Application Data\plugins",
        @"FiveM.app\FiveM Application Data\resources",
        @"AppData\Local\FiveM\FiveM Application Data\resources",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckFiveMResourceManifests(ctx, ct),
            CheckFiveMLuaScripts(ctx, ct),
            CheckFiveMJavaScriptMods(ctx, ct),
            CheckFiveMNUIResources(ctx, ct),
            CheckFiveMPluginDLLs(ctx, ct),
            CheckFiveMCacheCheatArtifacts(ctx, ct),
            CheckFiveMConfigCheatSettings(ctx, ct),
            CheckFiveMCitizenLogCheat(ctx, ct),
            CheckFiveMServerHistoryCheat(ctx, ct),
            CheckFiveMASILoaderArtifacts(ctx, ct),
            CheckFiveMScriptHookArtifacts(ctx, ct),
            CheckFiveMProxyDLLArtifacts(ctx, ct),
            CheckFiveMAntiCheatBypassArtifacts(ctx, ct),
            CheckFiveMDownloadedMods(ctx, ct),
            CheckFiveMRegistryArtifacts(ctx, ct),
            CheckFiveMNetworkTraceCheat(ctx, ct),
            CheckFiveMCrashDumpCheat(ctx, ct),
            CheckFiveMScreenshotBypass(ctx, ct)
        );
    }

    private Task CheckFiveMResourceManifests(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string resourceRelPath in FiveMResourcePaths)
        {
            string resourcePath = Path.Combine(userProfile, resourceRelPath);
            if (!Directory.Exists(resourcePath)) continue;

            foreach (string manifestFile in Directory.GetFiles(resourcePath, "fxmanifest.lua", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(resourcePath, "__resource.lua", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(manifestFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    string resourceDir = Path.GetDirectoryName(manifestFile) ?? string.Empty;
                    string resourceName = Path.GetFileName(resourceDir).ToLowerInvariant();

                    foreach (string cheatName in CheatResourceNames)
                    {
                        if (resourceName.Contains(cheatName, StringComparison.OrdinalIgnoreCase) ||
                            content.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Resource Manifest — Cheat Resource",
                                Risk = Risk.Critical,
                                Location = manifestFile,
                                FileName = Path.GetFileName(manifestFile),
                                Reason = $"FiveM resource manifest contains cheat-related name or keyword: '{cheatName}'",
                                Detail = $"Resource: '{resourceName}' — cheat resources run as part of the FiveM client environment"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckFiveMLuaScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string resourceRelPath in FiveMResourcePaths)
        {
            string resourcePath = Path.Combine(userProfile, resourceRelPath);
            if (!Directory.Exists(resourcePath)) continue;

            string[] luaFiles = Directory.GetFiles(resourcePath, "*.lua", SearchOption.AllDirectories);
            int scanned = 0;
            foreach (string luaFile in luaFiles)
            {
                if (ct.IsCancellationRequested || scanned > 500) break;
                scanned++;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    int matchCount = 0;
                    string? lastMatch = null;
                    foreach (string luaKw in CheatLuaKeywords)
                    {
                        if (content.Contains(luaKw, StringComparison.OrdinalIgnoreCase))
                        {
                            matchCount++;
                            lastMatch = luaKw;
                        }
                    }

                    if (matchCount >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Lua Script — Cheat API Usage",
                            Risk = Risk.Critical,
                            Location = luaFile,
                            FileName = Path.GetFileName(luaFile),
                            Reason = $"Lua script uses {matchCount} cheat-related native API calls (last: '{lastMatch}')",
                            Detail = "FiveM Lua script contains multiple cheat-related native function calls — strong indicator of cheat script"
                        });
                    }
                    else if (matchCount >= 1)
                    {
                        foreach (string cheatScKw in CheatScriptKeywords)
                        {
                            if (content.Contains(cheatScKw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "FiveM Lua Script — Suspicious Content",
                                    Risk = Risk.High,
                                    Location = luaFile,
                                    FileName = Path.GetFileName(luaFile),
                                    Reason = $"Lua script contains cheat-related pattern: '{cheatScKw}'",
                                    Detail = "FiveM Lua script combines native API calls with cheat-specific patterns"
                                });
                                break;
                            }
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckFiveMJavaScriptMods(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string resourceRelPath in FiveMResourcePaths)
        {
            string resourcePath = Path.Combine(userProfile, resourceRelPath);
            if (!Directory.Exists(resourcePath)) continue;

            string[] jsFiles = Directory.GetFiles(resourcePath, "*.js", SearchOption.AllDirectories);
            int scanned = 0;
            foreach (string jsFile in jsFiles)
            {
                if (ct.IsCancellationRequested || scanned > 300) break;
                scanned++;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    string[] jsCheatKeywords = new[]
                    {
                        "invokeNative", "Citizen.invokeNative", "GetPlayerPed",
                        "SetEntityCoords", "GiveWeaponToPed", "AddExplosion",
                        "cheat", "hack", "inject", "bypass", "exploit",
                        "fetch.*discord.gg", "fetch.*cheat", "axios.*cheat",
                        "window.location.*cheat", "document.cookie",
                        "eval(atob(", "eval(unescape(",
                        "new Function(", "setTimeout(eval",
                    };

                    foreach (string jsKw in jsCheatKeywords)
                    {
                        if (content.Contains(jsKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM JavaScript Mod — Cheat Content",
                                Risk = Risk.High,
                                Location = jsFile,
                                FileName = Path.GetFileName(jsFile),
                                Reason = $"JavaScript resource contains cheat keyword: '{jsKw}'",
                                Detail = "FiveM JavaScript NUI scripts can be used for ESP overlays, radar hacks, and UI-based cheat tools"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckFiveMNUIResources(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string resourceRelPath in FiveMResourcePaths)
        {
            string resourcePath = Path.Combine(userProfile, resourceRelPath);
            if (!Directory.Exists(resourcePath)) continue;

            string[] htmlFiles = Directory.GetFiles(resourcePath, "*.html", SearchOption.AllDirectories);
            int scanned = 0;
            foreach (string htmlFile in htmlFiles)
            {
                if (ct.IsCancellationRequested || scanned > 300) break;
                scanned++;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(htmlFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    string[] nuiCheatKeywords = new[]
                    {
                        "esp", "aimbot", "wallhack", "radar", "minimap", "cheat",
                        "hack", "noclip", "godmode", "money", "rp",
                        "teleport", "speedhack", "bypass",
                        "fetch(", "XMLHttpRequest", "postMessage.*cheat",
                        "window.cheat", "window.hack", "window.esp",
                    };

                    foreach (string nuiKw in nuiCheatKeywords)
                    {
                        if (content.Contains(nuiKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM NUI HTML — Cheat Interface",
                                Risk = Risk.High,
                                Location = htmlFile,
                                FileName = Path.GetFileName(htmlFile),
                                Reason = $"FiveM NUI HTML file contains cheat UI keyword: '{nuiKw}'",
                                Detail = "NUI (New UI) resources can render ESP overlays, cheat menus, and radar displays within FiveM"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckFiveMPluginDLLs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] pluginBasePaths = new[]
        {
            Path.Combine(userProfile, @"FiveM Application Data\plugins"),
            Path.Combine(userProfile, @"AppData\Local\FiveM\FiveM Application Data\plugins"),
            Path.Combine(userProfile, @"FiveM Application Data\citizen\clr2\lib\mono\4.5"),
        };

        foreach (string pluginPath in pluginBasePaths)
        {
            if (!Directory.Exists(pluginPath)) continue;
            foreach (string dllFile in Directory.GetFiles(pluginPath, "*.dll", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                string dllName = Path.GetFileName(dllFile).ToLowerInvariant();

                foreach (string cheatName in CheatResourceNames)
                {
                    if (dllName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Plugin DLL — Cheat Library",
                            Risk = Risk.Critical,
                            Location = dllFile,
                            FileName = Path.GetFileName(dllFile),
                            Reason = $"FiveM plugin DLL name matches cheat pattern: '{cheatName}'",
                            Detail = "FiveM plugin DLLs can inject cheat functionality directly into the CitizenFX runtime"
                        });
                        break;
                    }
                }

                try
                {
                    using var fs = new FileStream(dllFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    if (content.Contains("CitizenFX", StringComparison.OrdinalIgnoreCase) &&
                        CheatResourceNames.Any(c => content.Contains(c, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Plugin DLL — CitizenFX Cheat Hook",
                            Risk = Risk.Critical,
                            Location = dllFile,
                            FileName = Path.GetFileName(dllFile),
                            Reason = "DLL references CitizenFX alongside cheat-related strings",
                            Detail = "DLL hooking the CitizenFX API is a common method for implementing FiveM cheats"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckFiveMCacheCheatArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] cachePaths = new[]
        {
            Path.Combine(userProfile, @"FiveM Application Data\cache"),
            Path.Combine(userProfile, @"AppData\Local\FiveM\FiveM Application Data\cache"),
        };

        foreach (string cachePath in cachePaths)
        {
            if (!Directory.Exists(cachePath)) continue;
            foreach (string cacheFile in Directory.GetFiles(cachePath, "*", SearchOption.AllDirectories)
                .Where(f => f.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
                            f.EndsWith(".dat", StringComparison.OrdinalIgnoreCase) ||
                            f.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 512 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    foreach (string cheatName in CheatResourceNames)
                    {
                        if (content.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Cache — Cheat Resource Artifact",
                                Risk = Risk.High,
                                Location = cacheFile,
                                FileName = Path.GetFileName(cacheFile),
                                Reason = $"FiveM cache file contains cheat resource reference: '{cheatName}'",
                                Detail = "FiveM caches downloaded resources — cheat names in cache prove that the cheat was loaded from a server"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckFiveMConfigCheatSettings(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] configPaths = new[]
        {
            Path.Combine(userProfile, @"FiveM Application Data\CitizenFX.ini"),
            Path.Combine(userProfile, @"AppData\Local\FiveM\FiveM Application Data\CitizenFX.ini"),
            Path.Combine(userProfile, @"FiveM Application Data\settings.ini"),
            Path.Combine(userProfile, @"AppData\Roaming\CitizenFX\CitizenFX.ini"),
        };

        foreach (string configPath in configPaths)
        {
            if (!File.Exists(configPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                string[] configCheatKeywords = new[]
                {
                    "bypass", "cheat", "hack", "inject", "disable_anti", "no_ac",
                    "IgnoreMismatch", "DisableNativeSecurity",
                    "ForcedSinglePlayer", "DisableScreenshots",
                };

                foreach (string cfgKw in configCheatKeywords)
                {
                    if (content.Contains(cfgKw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Config — Cheat/Bypass Setting",
                            Risk = Risk.High,
                            Location = configPath,
                            FileName = Path.GetFileName(configPath),
                            Reason = $"FiveM configuration file contains suspicious setting: '{cfgKw}'",
                            Detail = "FiveM config file has been modified to disable security features or enable cheat-compatible settings"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckFiveMCitizenLogCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] logPaths = new[]
        {
            Path.Combine(userProfile, @"FiveM Application Data\CitizenFX.log"),
            Path.Combine(userProfile, @"AppData\Local\FiveM\FiveM Application Data\CitizenFX.log"),
            Path.Combine(userProfile, @"FiveM Application Data\CitizenFX.log.1"),
        };

        foreach (string logPath in logPaths)
        {
            if (!File.Exists(logPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string cheatName in CheatResourceNames)
                {
                    if (content.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM CitizenFX Log — Cheat Resource Loaded",
                            Risk = Risk.Critical,
                            Location = logPath,
                            FileName = Path.GetFileName(logPath),
                            Reason = $"CitizenFX log shows cheat resource was loaded: '{cheatName}'",
                            Detail = "The CitizenFX log records all loaded resources — cheat names prove the cheat was active on a server"
                        });
                        break;
                    }
                }

                foreach (string srvHost in FiveMCheatServerHosts)
                {
                    if (content.Contains(srvHost, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Log — Connected to Cheat Server",
                            Risk = Risk.Critical,
                            Location = logPath,
                            FileName = Path.GetFileName(logPath),
                            Reason = $"CitizenFX log shows connection to known cheat provider: '{srvHost}'",
                            Detail = "FiveM log records server connections — connection to known cheat server hosts is definitive evidence"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckFiveMServerHistoryCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] serverHistoryPaths = new[]
        {
            Path.Combine(userProfile, @"AppData\Roaming\CitizenFX\recentServers.json"),
            Path.Combine(userProfile, @"FiveM Application Data\recentServers.json"),
            Path.Combine(userProfile, @"AppData\Local\FiveM\FiveM Application Data\recentServers.json"),
        };

        foreach (string histPath in serverHistoryPaths)
        {
            if (!File.Exists(histPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(histPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (string srvHost in FiveMCheatServerHosts)
                {
                    if (content.Contains(srvHost, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Recent Servers — Cheat Server History",
                            Risk = Risk.Critical,
                            Location = histPath,
                            FileName = Path.GetFileName(histPath),
                            Reason = $"FiveM recent servers list contains known cheat server: '{srvHost}'",
                            Detail = "Recent server history proves the user actively connected to known cheat-providing FiveM servers"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckFiveMASILoaderArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string[] gta5Paths = new[]
        {
            @"C:\Program Files\Rockstar Games\Grand Theft Auto V",
            @"C:\Program Files (x86)\Rockstar Games\Grand Theft Auto V",
            @"C:\Program Files\Epic Games\GTAV",
            @"C:\Games\Grand Theft Auto V",
        };

        string[] asiCheatNames = new[]
        {
            "menyoo", "openiv", "trainerv", "kiddion", "scripthookvdotnet",
            "cheat", "hack", "inject", "bypass", "esp", "aimbot",
            "dsound", "dinput8", "winmm", "version",
        };

        foreach (string gtaPath in gta5Paths)
        {
            if (!Directory.Exists(gtaPath)) continue;
            foreach (string asiFile in Directory.GetFiles(gtaPath, "*.asi", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                string asiName = Path.GetFileName(asiFile).ToLowerInvariant();
                foreach (string cheatAsi in asiCheatNames)
                {
                    if (asiName.Contains(cheatAsi, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "GTA V ASI Loader — Cheat Plugin",
                            Risk = Risk.Critical,
                            Location = asiFile,
                            FileName = Path.GetFileName(asiFile),
                            Reason = $"GTA V ASI file matches cheat plugin pattern: '{cheatAsi}'",
                            Detail = "ASI plugins loaded by ScriptHookV can inject cheat code into GTA V / FiveM runtime"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckFiveMScriptHookArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string[] gta5Paths = new[]
        {
            @"C:\Program Files\Rockstar Games\Grand Theft Auto V",
            @"C:\Program Files (x86)\Rockstar Games\Grand Theft Auto V",
            @"C:\Program Files\Epic Games\GTAV",
        };

        string[] scriptHookFiles = new[]
        {
            "ScriptHookV.dll", "ScriptHookVDotNet.dll", "ScriptHookVDotNet2.dll",
            "ScriptHookVDotNet3.dll", "dinput8.dll", "dsound.dll",
            "NativeTrainer.asi", "Menyoo.asi",
        };

        foreach (string gtaPath in gta5Paths)
        {
            if (!Directory.Exists(gtaPath)) continue;
            foreach (string hookFile in scriptHookFiles)
            {
                string fullPath = Path.Combine(gtaPath, hookFile);
                if (File.Exists(fullPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "ScriptHook / Trainer Artifact in GTA V",
                        Risk = Risk.High,
                        Location = fullPath,
                        FileName = hookFile,
                        Reason = $"GTA V directory contains script hook or trainer file: '{hookFile}'",
                        Detail = "ScriptHookV and trainer ASIs enable cheat script execution in GTA V and can persist across FiveM launches"
                    });
                }
            }
        }
    }, ct);

    private Task CheckFiveMProxyDLLArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string fivemPath = Path.Combine(userProfile, @"AppData\Local\FiveM");
        if (!Directory.Exists(fivemPath)) return;

        string[] proxyDllNames = new[]
        {
            "dinput8.dll", "dsound.dll", "winmm.dll", "version.dll",
            "d3d9.dll", "d3d10.dll", "d3d11.dll", "opengl32.dll",
            "dxgi.dll", "wsock32.dll", "ws2_32.dll", "winhttp.dll",
        };

        foreach (string proxyDll in proxyDllNames)
        {
            foreach (string fivemSubDir in Directory.GetDirectories(fivemPath, "*", SearchOption.AllDirectories)
                .Take(100))
            {
                if (ct.IsCancellationRequested) return;
                string proxyPath = Path.Combine(fivemSubDir, proxyDll);
                if (!File.Exists(proxyPath)) continue;
                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(proxyPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    byte[] buf = new byte[Math.Min(fs.Length, 256 * 1024)];
                    int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                    string content = Encoding.UTF8.GetString(buf, 0, read);

                    if (content.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("hook", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Proxy DLL — Cheat Hook",
                            Risk = Risk.Critical,
                            Location = proxyPath,
                            FileName = proxyDll,
                            Reason = $"Proxy DLL '{proxyDll}' in FiveM directory contains cheat-related strings",
                            Detail = "Proxy DLLs in game directories intercept API calls to inject cheat code into FiveM process"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckFiveMAntiCheatBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] fivemBasePaths = new[]
        {
            Path.Combine(userProfile, @"FiveM Application Data"),
            Path.Combine(userProfile, @"AppData\Local\FiveM"),
        };

        string[] bypassKeywords = new[]
        {
            "fiveguard_bypass", "screengrab_bypass", "screenshot_bypass",
            "anticheat_bypass", "ac_bypass", "anticheat disable",
            "bypass", "disable_screenshots", "no_screenshots",
        };

        foreach (string basePath in fivemBasePaths)
        {
            if (!Directory.Exists(basePath)) continue;
            foreach (string file in Directory.GetFiles(basePath, "*", SearchOption.AllDirectories)
                .Where(f => f.EndsWith(".lua", StringComparison.OrdinalIgnoreCase) ||
                            f.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
                            f.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
                            f.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (string bpKw in bypassKeywords)
                    {
                        if (content.Contains(bpKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Anti-Cheat Bypass Artifact",
                                Risk = Risk.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"FiveM file contains anti-cheat bypass keyword: '{bpKw}'",
                                Detail = "Anti-cheat bypass artifacts in FiveM data directory indicate attempt to evade FiveGuard or server AC"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckFiveMDownloadedMods(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloadsPath = Path.Combine(userProfile, "Downloads");
        if (!Directory.Exists(downloadsPath)) return;

        string[] cheatFilePatterns = new[]
        {
            "fivem", "ragemp", "altv", "gta5", "kiddion", "stand",
            "eulen", "disturbed", "2take1", "midnight", "cherax",
            "cheat", "hack", "bypass", "inject", "spoof",
        };

        foreach (string file in Directory.GetFiles(downloadsPath, "*", SearchOption.TopDirectoryOnly))
        {
            if (ct.IsCancellationRequested) return;
            string fileName = Path.GetFileName(file).ToLowerInvariant();
            foreach (string pattern in cheatFilePatterns)
            {
                if (fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Downloads — FiveM/GTA Cheat File",
                        Risk = Risk.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Downloaded file name matches FiveM cheat pattern: '{pattern}'",
                        Detail = "File in Downloads folder has a name indicating it is a cheat tool for FiveM or GTA"
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckFiveMRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string[] registryPaths = new[]
        {
            @"SOFTWARE\FiveM",
            @"SOFTWARE\CitizenFX",
            @"SOFTWARE\Rockstar Games\Grand Theft Auto V",
        };

        foreach (string regPath in registryPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath) ??
                                Registry.CurrentUser.OpenSubKey(regPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();

                foreach (string valueName in key.GetValueNames())
                {
                    string val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    foreach (string cheatName in CheatResourceNames)
                    {
                        if (val.Contains(cheatName, StringComparison.OrdinalIgnoreCase) ||
                            valueName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Registry — FiveM/GTA Cheat Artifact",
                                Risk = Risk.High,
                                Location = $@"Registry\{regPath}\{valueName}",
                                FileName = valueName,
                                Reason = $"Registry value contains cheat-related name: '{cheatName}'",
                                Detail = "FiveM or GTA registry entries modified by cheat tools to store configuration or license data"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckFiveMNetworkTraceCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] netLogPaths = new[]
        {
            Path.Combine(userProfile, @"FiveM Application Data\logs"),
            Path.Combine(userProfile, @"AppData\Local\FiveM\FiveM Application Data\logs"),
        };

        foreach (string logDir in netLogPaths)
        {
            if (!Directory.Exists(logDir)) continue;
            foreach (string logFile in Directory.GetFiles(logDir, "*.log", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (string srvHost in FiveMCheatServerHosts)
                    {
                        if (content.Contains(srvHost, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Network Log — Cheat Server Connection",
                                Risk = Risk.Critical,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"FiveM network log shows connection to cheat server: '{srvHost}'",
                                Detail = "Network log records all server connections — connection to cheat provider domains is definitive"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckFiveMCrashDumpCheat(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] crashPaths = new[]
        {
            Path.Combine(userProfile, @"FiveM Application Data\crashes"),
            Path.Combine(userProfile, @"AppData\Local\FiveM\FiveM Application Data\crashes"),
        };

        foreach (string crashPath in crashPaths)
        {
            if (!Directory.Exists(crashPath)) continue;
            foreach (string dmpFile in Directory.GetFiles(crashPath, "*.dmp", SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "FiveM Crash Dump — Forensic Artifact",
                    Risk = Risk.Medium,
                    Location = dmpFile,
                    FileName = Path.GetFileName(dmpFile),
                    Reason = "FiveM crash dump found — may contain cheat module traces in process memory snapshot",
                    Detail = "FiveM crash dumps capture the full process state including loaded DLLs and memory — can reveal cheat modules"
                });
            }
        }
    }, ct);

    private Task CheckFiveMScreenshotBypass(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string resourceRelPath in FiveMResourcePaths)
        {
            string resourcePath = Path.Combine(userProfile, resourceRelPath);
            if (!Directory.Exists(resourcePath)) continue;

            foreach (string file in Directory.GetFiles(resourcePath, "*.lua", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(resourcePath, "*.js", SearchOption.AllDirectories)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (string sbKw in ScreenshotBypassIndicators)
                    {
                        if (content.Contains(sbKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Screenshot Bypass — Anti-Detection",
                                Risk = Risk.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"FiveM resource script contains screenshot bypass indicator: '{sbKw}'",
                                Detail = "Screenshot bypass in FiveM is used to hide cheat menus/ESP from server-side anti-cheat screenshot detection"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);
}
