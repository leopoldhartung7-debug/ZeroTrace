using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class FiveMDeepForensicScanModule : IScanModule
{
    public string Name => "FiveM Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] CheatLuaKeywords = { "god_mode", "no_clip", "esp", "aimbot", "wallhack", "teleport", "spawn_ped", "spawn_vehicle", "blow_up", "freeze_player", "set_entity_invincible", "network_request_control", "get_closest_ped", "delete_entity", "get_all_vehicles", "set_ped_to_ragdoll", "set_vehicle_fixed", "NoClip", "GodMode", "SuperJump", "InfiniteAmmo", "NeverWanted", "AlwaysWanted", "WantedLevel", "SetPlayerModel", "SetPedCanRagdoll", "AddExplosion" };
    private static readonly string[] ModMenuFilePrefixes = { "menyoo", "trainerv", "trainer_v", "simplist", "noose.ini", "YimMenu", "Stand_Config", "2Take1", "Enhanced_Native_Trainer", "modmenu_config" };
    private static readonly string[] PremiumCheatNames = { "2take1", "stand", "yimmenu", "eulen", "redengine", "skript", "brainobrain" };
    private static readonly string[] InjectorDllNames = { "fivem_injector.dll", "cfx_inject.dll", "fivem_hook.dll", "gta5_trainer.dll", "menyoo.dll", "yimmenu.dll", "stand.dll", "2take1.dll", "themida_bypass.dll", "fivem_bypass.dll", "cfx_hook.dll" };
    private static readonly string[] CheatPrefetchNames = { "MENYOO", "TRAINERV", "YIMMENU", "2TAKE1", "STAND_LOADER", "THEMIDA", "FIVEM_BYPASS", "CFX_BYPASS", "EXECUTOR", "SYNAPSE", "KRNL", "SENTINEL", "EULEN", "REDENGINE" };
    private static readonly string[] AntiCheatBypassKeywords = { "disableAnticheat", "bypassAnticheat", "disableOneSync", "bypassDetection", "antidetect", "HideFromAnticheat", "ac_bypass", "anticheat_bypass", "disable_cfx", "cfx_bypass", "block_cfx", "disable_ac", "bypass_ac" };
    private static readonly string[] ExecutorLogFileNames = { "krnl.log", "synapse_log.txt", "sentinel_log.txt", "executor_log.txt", "autoexec.log", "script_exec.log", "inject_log.txt" };

    private static readonly string[] CitizenLogInjectionKeywords = { "[PluginLoader]", "[Injector]", "Injecting module", "DLL injected", "LoadLibrary called", "CreateRemoteThread", "process injection", "[cheat]", "error loading script", "unauthorized", "execution blocked" };
    private static readonly string[] CitizenLogCheatResourcePrefixes = { "menu_", "trainer_", "executor_", "cheat_", "esp_", "aimbot_" };
    private static readonly string[] CacheScriptKeywords = { "RegisterNetEvent", "TriggerServerEvent('esx:", "exports.es_extended", "QBCore.Functions", "addMoney", "addItem", "setJob", "giveWeapon", "setHealth", "setArmour", "teleportToWaypoint", "setCoords", "spawnVehicle", "deleteVehicle", "setModel", "setPedComponentVariation" };
    private static readonly string[] CacheMoneyWeaponPatterns = { "addMoney", "addItem", "giveWeapon", "addAccountMoney", "QBCore.Functions.AddItem", "QBCore.Functions.AddMoney" };
    private static readonly string[] NativeHashContextKeywords = { "GetPlayerPed", "SetEntityInvincible", "NetworkHasControlOfEntity", "SetPedMaxHealth", "AddExplosion", "ShootSingleBulletBetweenCoords" };
    private static readonly string[] NativeDbFileNames = { "natives.json", "nativedb.json", "offsets.json", "hazedumper.json" };
    private static readonly string[] AntiCheatBypassFolderNames = { "ac_bypass", "anticheat_bypass", "hide", "stealth", "ghost", "invisible_resource", "fake_resource" };
    private static readonly string[] ScriptDumpFileNames = { "script_dump.lua", "dump_scripts.lua", "resource_dump", "cached_scripts" };
    private static readonly string[] SuspiciousServerTerms = { "cheater", "hacker", "exploit", "bypass", "test server", "private cheat", "mod menu", "esp server", "aimbot test" };
    private static readonly string[] ESXQBCoreAbusePattens = { "TriggerEvent('esx:setJob'", "xPlayer.addMoney", "xPlayer.addAccountMoney", "xPlayer.addWeapon", "ESX.RegisterUsableItem", "QBCore.Functions.AddItem", "QBCore.Functions.AddMoney" };
    private static readonly string[] CEFNUIExploitKeywords = { "fetch('http://localhost:", "SendNUIMessage", "executeCommand", "setModel", "spawnEntity" };
    private static readonly string[] SpeedHackFileNames = { "speedhack.exe", "speed_hack.dll", "cheat_engine.exe", "ce.exe" };
    private static readonly string[] SpawnPatterns = { "spawnVehicle", "CreateVehicle", "request_model" };
    private static readonly string[] TeleportPatterns = { "setEntityCoords", "setEntityVelocity" };
    private static readonly string[] NetworkToolFileNames = { "fivem_packet_dump", "gta_network_sniffer", "cfx_packet_analyzer" };

    private static string AppData => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static string Documents => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static string Desktop => Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static string UserProfile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static string FiveMAppData => Path.Combine(AppData, "citizenfx", "FiveM", "FiveM.app");
    private static string FiveMLocalAppData => Path.Combine(LocalAppData, "FiveM", "FiveM.app");

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckFiveMResourceManifests(ctx, ct),
            CheckFiveMCitizenLog(ctx, ct),
            CheckFiveMCacheResources(ctx, ct),
            CheckFiveMModMenuScripts(ctx, ct),
            CheckFiveMNativeHashFiles(ctx, ct),
            CheckFiveMAntiCheatBypassScripts(ctx, ct),
            CheckFiveMDumpedScripts(ctx, ct),
            CheckFiveMServerConnectionHistory(ctx, ct),
            CheckFiveMInjectorArtifacts(ctx, ct),
            CheckFiveMESXQBCoreAdminAbuse(ctx, ct),
            CheckFiveMCEFNUIExploits(ctx, ct),
            CheckFiveMSpeedrunnerTools(ctx, ct),
            CheckFiveMVehicleSpawnLogs(ctx, ct),
            CheckFiveMRegistryArtifacts(ctx, ct),
            CheckFiveMPrefetchArtifacts(ctx, ct),
            CheckFiveMNetworkPacketTools(ctx, ct),
            CheckFiveMStreamBypassArtifacts(ctx, ct),
            CheckFiveMScriptExecutorArtifacts(ctx, ct)
        );
    }

    private Task CheckFiveMResourceManifests(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> manifestFiles;
            try
            {
                manifestFiles = Directory.GetFiles(root, "fxmanifest.lua", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(root, "__resource.lua", SearchOption.AllDirectories));
            }
            catch (Exception)
            {
                continue;
            }

            foreach (var path in manifestFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var kw in CheatLuaKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Resource Manifest — Cheat Keyword",
                                Risk = RiskLevel.High,
                                Location = path,
                                FileName = Path.GetFileName(path),
                                Reason = $"Resource manifest contains cheat keyword: '{kw}'",
                                Detail = $"Manifest at '{path}' references known cheat functionality"
                            });
                            break;
                        }
                    }
                }
                catch (Exception) { }
            }
        }
    }, ct);

    private Task CheckFiveMCitizenLog(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logPaths = new[]
        {
            Path.Combine(FiveMAppData, "logs", "CitizenFX.log"),
            Path.Combine(FiveMLocalAppData, "logs", "CitizenFX.log"),
        };

        foreach (var logPath in logPaths)
        {
            if (!File.Exists(logPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (var kw in CitizenLogInjectionKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM CitizenFX Log — Injection Attempt",
                            Risk = RiskLevel.High,
                            Location = logPath,
                            FileName = Path.GetFileName(logPath),
                            Reason = $"CitizenFX log contains injection indicator: '{kw}'",
                            Detail = "Log entry suggests DLL or script injection activity"
                        });
                        break;
                    }
                }

                foreach (var prefix in CitizenLogCheatResourcePrefixes)
                {
                    if (content.Contains(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM CitizenFX Log — Cheat Resource Name",
                            Risk = RiskLevel.High,
                            Location = logPath,
                            FileName = Path.GetFileName(logPath),
                            Reason = $"CitizenFX log references resource with cheat prefix: '{prefix}'",
                            Detail = "Resource naming pattern matches known cheat resource conventions"
                        });
                        break;
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckFiveMCacheResources(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Path.Combine(FiveMLocalAppData, "cache", "game", "citizen", "scripting"),
            Path.Combine(FiveMAppData, "cache"),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> scriptFiles;
            try
            {
                scriptFiles = Directory.GetFiles(root, "*.lua", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(root, "*.js", SearchOption.AllDirectories));
            }
            catch (Exception)
            {
                continue;
            }

            foreach (var path in scriptFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool hasMoneyOrWeapon = false;
                    foreach (var p in CacheMoneyWeaponPatterns)
                    {
                        if (content.Contains(p, StringComparison.OrdinalIgnoreCase))
                        {
                            hasMoneyOrWeapon = true;
                            break;
                        }
                    }

                    int matchCount = 0;
                    string? lastMatch = null;
                    foreach (var kw in CacheScriptKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            matchCount++;
                            lastMatch = kw;
                        }
                    }

                    if (matchCount >= 2)
                    {
                        var risk = hasMoneyOrWeapon ? RiskLevel.Critical : RiskLevel.High;
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Cache Script — ESX/QBCore Cheat Pattern",
                            Risk = risk,
                            Location = path,
                            FileName = Path.GetFileName(path),
                            Reason = $"Cached script contains {matchCount} cheat-related API calls including '{lastMatch}'",
                            Detail = hasMoneyOrWeapon
                                ? "Script includes money/weapon manipulation patterns suggesting economy abuse"
                                : "Multiple suspicious server-event and entity patterns found"
                        });
                    }
                }
                catch (Exception) { }
            }
        }
    }, ct);

    private Task CheckFiveMModMenuScripts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var gtaVDocs = Path.Combine(Documents, "Rockstar Games", "GTA V");
        var searchRoots = new[]
        {
            gtaVDocs,
            FiveMAppData,
            FiveMLocalAppData,
        };

        var premiumFolders = new[] { "2Take1", "YimMenu", "Stand_Config" };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var prefix in ModMenuFilePrefixes)
            {
                var isPremium = PremiumCheatNames.Any(p => prefix.Contains(p, StringComparison.OrdinalIgnoreCase));
                var risk = isPremium ? RiskLevel.Critical : RiskLevel.High;

                try
                {
                    foreach (var file in Directory.GetFiles(root, "*", SearchOption.TopDirectoryOnly))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        var fileName = Path.GetFileName(file);
                        if (fileName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Mod Menu Artifact — Config File",
                                Risk = risk,
                                Location = file,
                                FileName = fileName,
                                Reason = $"Mod menu configuration file found matching prefix: '{prefix}'",
                                Detail = isPremium ? "Premium mod menu artifact — high-confidence cheat indicator" : "Known mod menu configuration file"
                            });
                        }
                    }
                }
                catch (Exception) { }

                try
                {
                    var dirPath = Path.Combine(root, prefix);
                    if (Directory.Exists(dirPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Mod Menu Artifact — Directory",
                            Risk = risk,
                            Location = dirPath,
                            FileName = prefix,
                            Reason = $"Mod menu directory found: '{prefix}'",
                            Detail = isPremium ? "Premium mod menu directory — high-confidence cheat indicator" : "Known mod menu folder present"
                        });
                    }
                }
                catch (Exception) { }
            }
        }
    }, ct);

    private Task CheckFiveMNativeHashFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            FiveMAppData,
            FiveMLocalAppData,
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
        };

        var nativeHashPattern = new System.Text.RegularExpressions.Regex(
            @"0x[0-9A-Fa-f]{16}",
            System.Text.RegularExpressions.RegexOptions.Compiled);

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var dbFileName in NativeDbFileNames)
            {
                var candidate = Path.Combine(root, dbFileName);
                if (File.Exists(candidate))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM Native Database File",
                        Risk = RiskLevel.High,
                        Location = candidate,
                        FileName = dbFileName,
                        Reason = $"Known native database file found: '{dbFileName}'",
                        Detail = "Native database files are used by cheat tools to call game functions by hash"
                    });
                }
            }

            IEnumerable<string> scriptFiles;
            try
            {
                scriptFiles = Directory.GetFiles(root, "*.lua", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(root, "*.js", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(root, "*.json", SearchOption.AllDirectories));
            }
            catch (Exception)
            {
                continue;
            }

            foreach (var path in scriptFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    if (!nativeHashPattern.IsMatch(content)) continue;

                    foreach (var kw in NativeHashContextKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Script — Raw Native Hash with Cheat Context",
                                Risk = RiskLevel.High,
                                Location = path,
                                FileName = Path.GetFileName(path),
                                Reason = $"Script uses raw native hash (0x...) combined with cheat-context keyword: '{kw}'",
                                Detail = "Raw native hashes with cheat-related function names indicate obfuscated cheat scripting"
                            });
                            break;
                        }
                    }
                }
                catch (Exception) { }
            }
        }
    }, ct);

    private Task CheckFiveMAntiCheatBypassScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var folderName in AntiCheatBypassFolderNames)
            {
                try
                {
                    var bypassDir = Path.Combine(root, folderName);
                    if (Directory.Exists(bypassDir))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Anti-Cheat Bypass — Suspicious Resource Folder",
                            Risk = RiskLevel.Critical,
                            Location = bypassDir,
                            FileName = folderName,
                            Reason = $"Resource folder named after anti-cheat bypass technique: '{folderName}'",
                            Detail = "Folder name matches known anti-cheat evasion resource naming pattern"
                        });
                    }
                }
                catch (Exception) { }
            }

            IEnumerable<string> scriptFiles;
            try
            {
                scriptFiles = Directory.GetFiles(root, "*.lua", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(root, "*.js", SearchOption.AllDirectories));
            }
            catch (Exception)
            {
                continue;
            }

            foreach (var path in scriptFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var kw in AntiCheatBypassKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Script — Anti-Cheat Bypass Keyword",
                                Risk = RiskLevel.Critical,
                                Location = path,
                                FileName = Path.GetFileName(path),
                                Reason = $"Script contains anti-cheat bypass keyword: '{kw}'",
                                Detail = "Anti-cheat bypass scripts attempt to defeat server-side and client-side detection mechanisms"
                            });
                            break;
                        }
                    }
                }
                catch (Exception) { }
            }
        }
    }, ct);

    private Task CheckFiveMDumpedScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            FiveMAppData,
            FiveMLocalAppData,
            Path.GetTempPath(),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var dumpName in ScriptDumpFileNames)
            {
                try
                {
                    foreach (var path in Directory.GetFiles(root, dumpName + "*", SearchOption.AllDirectories))
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Script Dump Artifact",
                            Risk = RiskLevel.High,
                            Location = path,
                            FileName = Path.GetFileName(path),
                            Reason = $"Script dump file found: '{Path.GetFileName(path)}'",
                            Detail = "Script dump files are created by tools that extract game scripts for analysis or modification"
                        });
                    }
                }
                catch (Exception) { }
            }

            try
            {
                foreach (var path in Directory.GetFiles(root, "*.ysc.lua", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(root, "*.ysc.js", SearchOption.AllDirectories)))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM Decompiled Vehicle Script Artifact",
                        Risk = RiskLevel.High,
                        Location = path,
                        FileName = Path.GetFileName(path),
                        Reason = $"Decompiled .ysc script file found: '{Path.GetFileName(path)}'",
                        Detail = "YSC files are compiled game scripts; .ysc.lua/.ysc.js files indicate decompilation for exploitation"
                    });
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckFiveMServerConnectionHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var historyPaths = new[]
        {
            Path.Combine(FiveMAppData, "data", "servers.json"),
            Path.Combine(FiveMLocalAppData, "data", "servers.json"),
        };

        foreach (var path in historyPaths)
        {
            if (!File.Exists(path)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (var term in SuspiciousServerTerms)
                {
                    if (content.Contains(term, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Server History — Suspicious Server Name",
                            Risk = RiskLevel.Medium,
                            Location = path,
                            FileName = Path.GetFileName(path),
                            Reason = $"Server connection history contains suspicious term: '{term}'",
                            Detail = "User connected to a server whose name/description references cheating or exploit testing"
                        });
                        break;
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckFiveMInjectorArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var searchRoots = new[]
        {
            Path.GetTempPath(),
            Path.Combine(LocalAppData, "Temp"),
            AppData,
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var dllName in InjectorDllNames)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    var candidate = Path.Combine(root, dllName);
                    if (!File.Exists(candidate)) continue;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM Injector DLL Artifact",
                        Risk = RiskLevel.Critical,
                        Location = candidate,
                        FileName = dllName,
                        Reason = $"Known FiveM injector DLL found: '{dllName}'",
                        Detail = "Injector DLLs are used to load unauthorized code into the FiveM game process"
                    });
                }
                catch (Exception) { }
            }
        }
    }, ct);

    private Task CheckFiveMESXQBCoreAdminAbuse(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> scriptFiles;
            try
            {
                scriptFiles = Directory.GetFiles(root, "*.lua", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(root, "*.js", SearchOption.AllDirectories));
            }
            catch (Exception)
            {
                continue;
            }

            foreach (var path in scriptFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    int matchCount = 0;
                    string? lastMatch = null;
                    foreach (var pattern in ESXQBCoreAbusePattens)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            matchCount++;
                            lastMatch = pattern;
                        }
                    }

                    if (matchCount >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM ESX/QBCore Admin Abuse Pattern",
                            Risk = RiskLevel.High,
                            Location = path,
                            FileName = Path.GetFileName(path),
                            Reason = $"Script contains {matchCount} ESX/QBCore admin function calls including '{lastMatch}'",
                            Detail = "Client-side scripts invoking server-side economy/admin functions suggest bypass of server validation"
                        });
                    }
                }
                catch (Exception) { }
            }
        }
    }, ct);

    private Task CheckFiveMCEFNUIExploits(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Path.Combine(FiveMLocalAppData, "NUI"),
            Path.Combine(FiveMAppData, "data", "nui-storage"),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var crxFile in Directory.GetFiles(root, "*.crx", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM NUI — Chrome Extension Artifact",
                        Risk = RiskLevel.High,
                        Location = crxFile,
                        FileName = Path.GetFileName(crxFile),
                        Reason = "Chrome extension (.crx) file found in FiveM NUI cache",
                        Detail = "CRX files loaded into FiveM's CEF browser can intercept NUI messages and manipulate game state"
                    });
                }
            }
            catch (Exception) { }

            IEnumerable<string> nuiFiles;
            try
            {
                nuiFiles = Directory.GetFiles(root, "*.html", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(root, "*.js", SearchOption.AllDirectories));
            }
            catch (Exception)
            {
                continue;
            }

            foreach (var path in nuiFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool hasFetch = content.Contains("fetch('http://localhost:", StringComparison.OrdinalIgnoreCase)
                        || content.Contains("fetch(\"http://localhost:", StringComparison.OrdinalIgnoreCase);
                    if (!hasFetch) continue;

                    foreach (var kw in CEFNUIExploitKeywords)
                    {
                        if (kw.StartsWith("fetch", StringComparison.OrdinalIgnoreCase)) continue;
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM CEF/NUI Exploit Pattern",
                                Risk = RiskLevel.High,
                                Location = path,
                                FileName = Path.GetFileName(path),
                                Reason = $"NUI file combines localhost fetch with exploit keyword: '{kw}'",
                                Detail = "Localhost fetch combined with game command execution suggests NUI-based exploit injection"
                            });
                            break;
                        }
                    }
                }
                catch (Exception) { }
            }
        }
    }, ct);

    private Task CheckFiveMSpeedrunnerTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            Documents,
            AppData,
            LocalAppData,
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var toolName in SpeedHackFileNames)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    var candidate = Path.Combine(root, toolName);
                    if (!File.Exists(candidate)) continue;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM Speed Hack Tool Artifact",
                        Risk = RiskLevel.High,
                        Location = candidate,
                        FileName = toolName,
                        Reason = $"Known speed hack or timing manipulation tool found: '{toolName}'",
                        Detail = "Speed hack tools manipulate process timing to gain movement or action speed advantages in game"
                    });
                }
                catch (Exception) { }
            }

            try
            {
                foreach (var ctFile in Directory.GetFiles(root, "*.CT", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(ctFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        if (content.Contains("GTA5.exe", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("FiveM.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Cheat Engine Table — GTA5/FiveM Target",
                                Risk = RiskLevel.High,
                                Location = ctFile,
                                FileName = Path.GetFileName(ctFile),
                                Reason = "Cheat Engine table (.CT) references GTA5.exe or FiveM.exe as target process",
                                Detail = "Cheat Engine tables targeting FiveM are used to modify memory values such as health, ammo, and speed"
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckFiveMVehicleSpawnLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Path.Combine(FiveMAppData, "logs"),
            Path.Combine(FiveMLocalAppData, "logs"),
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.GetFiles(root, "*.lua", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(root, "*.log", SearchOption.AllDirectories));
            }
            catch (Exception)
            {
                continue;
            }

            foreach (var path in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    int spawnCount = 0;
                    foreach (var spawnPattern in SpawnPatterns)
                    {
                        int idx = 0;
                        while ((idx = content.IndexOf(spawnPattern, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                        {
                            spawnCount++;
                            idx += spawnPattern.Length;
                        }
                    }

                    if (spawnCount >= 5)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Mass Vehicle Spawn Pattern",
                            Risk = RiskLevel.High,
                            Location = path,
                            FileName = Path.GetFileName(path),
                            Reason = $"File contains {spawnCount} vehicle spawn calls — mass spawn pattern detected",
                            Detail = "Mass vehicle spawning in scripts or logs indicates vehicle flood/grief tool usage"
                        });
                        continue;
                    }

                    bool hasCoords = content.Contains(TeleportPatterns[0], StringComparison.OrdinalIgnoreCase);
                    bool hasVelocity = content.Contains(TeleportPatterns[1], StringComparison.OrdinalIgnoreCase);
                    if (hasCoords && hasVelocity)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Teleport Script Pattern",
                            Risk = RiskLevel.High,
                            Location = path,
                            FileName = Path.GetFileName(path),
                            Reason = "Script combines setEntityCoords and setEntityVelocity — teleport pattern",
                            Detail = "Entity coordinate and velocity manipulation together is a characteristic teleport cheat pattern"
                        });
                    }
                }
                catch (Exception) { }
            }
        }
    }, ct);

    private Task CheckFiveMRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var keysToCheck = new[]
        {
            @"Software\FiveM",
            @"Software\CitizenFX",
        };

        foreach (var keyPath in keysToCheck)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key == null) continue;

                ctx.IncrementRegistryKeys();
                var valueNames = key.GetValueNames();
                foreach (var valueName in valueNames)
                {
                    ctx.IncrementRegistryKeys();
                    var value = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    if (AntiCheatBypassKeywords.Any(kw => value.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        || PremiumCheatNames.Any(cn => value.Contains(cn, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Registry — Cheat-Related Value",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKCU\{keyPath}\{valueName}",
                            FileName = null,
                            Reason = $"Registry value '{valueName}' under FiveM key contains suspicious content",
                            Detail = $"Value data: '{(value.Length > 200 ? value[..200] + "..." : value)}'"
                        });
                    }
                }
            }
            catch (Exception) { }
        }

        try
        {
            using var runMru = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU");
            if (runMru != null)
            {
                ctx.IncrementRegistryKeys();
                foreach (var valueName in runMru.GetValueNames())
                {
                    ctx.IncrementRegistryKeys();
                    var value = runMru.GetValue(valueName)?.ToString() ?? string.Empty;
                    if (PremiumCheatNames.Any(cn => value.Contains(cn, StringComparison.OrdinalIgnoreCase))
                        || InjectorDllNames.Any(dll => value.Contains(dll, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Registry — RunMRU Cheat Executable",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\{valueName}",
                            FileName = null,
                            Reason = "RunMRU entry references a known FiveM cheat executable",
                            Detail = $"RunMRU value: '{(value.Length > 200 ? value[..200] + "..." : value)}'"
                        });
                    }
                }
            }
        }
        catch (Exception) { }

        try
        {
            using var appPaths = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths");
            if (appPaths != null)
            {
                ctx.IncrementRegistryKeys();
                foreach (var subKeyName in appPaths.GetSubKeyNames())
                {
                    if (PremiumCheatNames.Any(cn => subKeyName.Contains(cn, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Registry — Cheat App Path Entry",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{subKeyName}",
                            FileName = null,
                            Reason = $"App Paths registry entry references known cheat: '{subKeyName}'",
                            Detail = "App Paths entries persist after cheat tool installation even if the executable is deleted"
                        });
                    }
                }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckFiveMPrefetchArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir)) return;

        var premiumPrefetchNames = new[] { "2TAKE1", "STAND_LOADER", "YIMMENU" };

        try
        {
            foreach (var pfFile in Directory.GetFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var pfName = Path.GetFileNameWithoutExtension(pfFile).ToUpperInvariant();

                foreach (var cheatName in CheatPrefetchNames)
                {
                    if (!pfName.Contains(cheatName, StringComparison.OrdinalIgnoreCase)) continue;

                    var isPremium = premiumPrefetchNames.Any(p => pfName.Contains(p, StringComparison.OrdinalIgnoreCase));
                    var risk = isPremium ? RiskLevel.Critical : RiskLevel.High;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM Prefetch — Cheat Executable Launched",
                        Risk = risk,
                        Location = pfFile,
                        FileName = Path.GetFileName(pfFile),
                        Reason = $"Prefetch file indicates cheat executable was run: '{cheatName}'",
                        Detail = isPremium
                            ? "Premium cheat (2Take1/Stand/YimMenu) prefetch entry — high-confidence prior execution"
                            : "Cheat tool prefetch entry indicates the tool was previously executed on this system"
                    });
                    break;
                }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckFiveMNetworkPacketTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            Documents,
            AppData,
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var toolName in NetworkToolFileNames)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    foreach (var path in Directory.GetFiles(root, toolName + "*", SearchOption.AllDirectories))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Network Packet Analysis Tool",
                            Risk = RiskLevel.High,
                            Location = path,
                            FileName = Path.GetFileName(path),
                            Reason = $"FiveM-specific network analysis tool found: '{Path.GetFileName(path)}'",
                            Detail = "Network packet tools targeting FiveM are used to analyze and replay game traffic for exploitation"
                        });
                    }
                }
                catch (Exception) { }
            }

            try
            {
                var pcapFiles = Directory.GetFiles(root, "*.pcap", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(root, "*.pcapng", SearchOption.AllDirectories));

                foreach (var pcapPath in pcapFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(pcapPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.Latin1);
                        string content = await sr.ReadToEndAsync(ct);

                        if (content.Contains("GTA5", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("FiveM", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("cfx", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Network Capture File",
                                Risk = RiskLevel.High,
                                Location = pcapPath,
                                FileName = Path.GetFileName(pcapPath),
                                Reason = "Network capture file contains GTA5/FiveM/CFX traffic markers",
                                Detail = "Packet capture files targeting FiveM traffic are used for session analysis and exploit development"
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckFiveMStreamBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var privCachePath = Path.Combine(FiveMAppData, "data", "cache", "priv");
        var nuiStoragePath = Path.Combine(FiveMAppData, "data", "nui-storage");

        var suspiciousAssetFiles = new[] { "modifiedTextures.json", "custom_assets_map.json" };

        var assetSearchRoots = new[] { privCachePath, nuiStoragePath };

        foreach (var root in assetSearchRoots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var assetFile in suspiciousAssetFiles)
            {
                var candidate = Path.Combine(root, assetFile);
                if (!File.Exists(candidate)) continue;
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "FiveM Stream — Non-Standard Asset Map",
                    Risk = RiskLevel.High,
                    Location = candidate,
                    FileName = assetFile,
                    Reason = $"Non-standard asset mapping file found in FiveM private cache: '{assetFile}'",
                    Detail = "Custom asset maps in the FiveM private cache can indicate texture replacement for ESP/wallhack visual aids"
                });
            }

            try
            {
                var visualSettingsPath = Path.Combine(root, "visualsettings.dat");
                if (File.Exists(visualSettingsPath))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(visualSettingsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        if (content.Contains("esp", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("wallhack", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("xray", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("noclip", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Visual Settings — ESP Modification",
                                Risk = RiskLevel.High,
                                Location = visualSettingsPath,
                                FileName = "visualsettings.dat",
                                Reason = "FiveM visualsettings.dat contains ESP or wallhack-related modification keywords",
                                Detail = "Modified visual settings in FiveM paths can enable see-through walls and entity highlighting"
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckFiveMScriptExecutorArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Path.Combine(FiveMAppData, "cache"),
            FiveMLocalAppData,
        };

        var autoExecPaths = new[]
        {
            Path.Combine(FiveMAppData, "cache", "autoexec.lua"),
            Path.Combine(FiveMLocalAppData, "autoexec.lua"),
            Path.Combine(FiveMAppData, "cache", "scripts", "init.lua"),
            Path.Combine(FiveMLocalAppData, "scripts", "init.lua"),
            Path.Combine(FiveMAppData, "cache", "scripts", "main.lua"),
            Path.Combine(FiveMLocalAppData, "scripts", "main.lua"),
        };

        foreach (var autoExec in autoExecPaths)
        {
            if (!File.Exists(autoExec)) continue;
            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "FiveM Script Executor — Auto-Execute Script",
                Risk = RiskLevel.High,
                Location = autoExec,
                FileName = Path.GetFileName(autoExec),
                Reason = $"Script executor auto-execute location found: '{autoExec}'",
                Detail = "autoexec.lua and scripts/init.lua/main.lua are auto-loaded by FiveM script executors on startup"
            });
        }

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var logName in ExecutorLogFileNames)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    var candidate = Path.Combine(root, logName);
                    if (!File.Exists(candidate)) continue;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM Script Executor — Log File Artifact",
                        Risk = RiskLevel.Critical,
                        Location = candidate,
                        FileName = logName,
                        Reason = $"Script executor log file found: '{logName}'",
                        Detail = "Executor log files (KRNL, Synapse, Sentinel) confirm a script executor was used with FiveM"
                    });
                }
                catch (Exception) { }
            }

            try
            {
                var executorConfigPath = Path.Combine(root, "executor_config.json");
                if (File.Exists(executorConfigPath))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM Script Executor — Configuration File",
                        Risk = RiskLevel.Critical,
                        Location = executorConfigPath,
                        FileName = "executor_config.json",
                        Reason = "Script executor configuration file found in FiveM directories",
                        Detail = "executor_config.json is created by script executor tools that inject Lua/JS into the FiveM environment"
                    });
                }
            }
            catch (Exception) { }

            try
            {
                foreach (var logPath in Directory.GetFiles(root, "*.log", SearchOption.AllDirectories))
                {
                    if (ct.IsCancellationRequested) return;
                    var logName = Path.GetFileName(logPath);
                    if (!ExecutorLogFileNames.Any(n => n.Equals(logName, StringComparison.OrdinalIgnoreCase))) continue;

                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        if (content.Length > 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Script Executor — Active Log File",
                                Risk = RiskLevel.Critical,
                                Location = logPath,
                                FileName = logName,
                                Reason = $"Non-empty executor log file found: '{logName}'",
                                Detail = $"Log file contains {content.Length} bytes of executor activity data"
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
            catch (Exception) { }
        }
    }, ct);
}
