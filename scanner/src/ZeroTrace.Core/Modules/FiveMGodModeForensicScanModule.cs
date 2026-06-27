using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMGodModeForensicScanModule : IScanModule
{
    public string Name => "FiveM-GodMode-Forensic";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    private static readonly string[] GodModeFilePatterns =
    {
        "godmode*", "god_mode*", "invincible_hack*", "fivem_godmode*",
        "noclip_fivem*", "health_hack_fivem*", "armor_hack_fivem*",
        "immortal_fivem*", "GodMode*", "god_hack*", "invincibility*",
        "fivem_invincible*", "health_bypass*", "armor_bypass*",
        "player_god*", "noclip_hack*", "fivem_noclip*", "god_player*"
    };

    private static readonly string[] GodModeExeNames =
    {
        "GodMode.exe", "Invincible.exe", "NoClip.exe", "HealthHack.exe",
        "godmode.exe", "invincible.exe", "noclip.exe", "healthhack.exe",
        "god_mode.exe", "invincible_hack.exe", "noclip_fivem.exe",
        "health_hack_fivem.exe", "armor_hack_fivem.exe", "immortal_fivem.exe",
        "FiveMGodMode.exe", "FiveMInvincible.exe", "FiveMNoClip.exe",
        "PlayerGod.exe", "GodHack.exe", "FiveMHealth.exe", "ArmorHack.exe"
    };

    private static readonly string[] LogKeywords =
    {
        "god mode", "invincible hack", "health hack", "noclip fivem",
        "armor hack fivem", "god mode fivem", "immortal player",
        "godmode", "invincibility hack", "player invincible",
        "health_hack", "noclip_fivem", "fivem god mode",
        "armor bypass fivem", "player health hack", "entity invincible",
        "setentityinvincible", "health bypass fivem", "noclip hack fivem",
        "god mode enabled", "invincible enabled", "immortal fivem"
    };

    private static readonly string[] FiveMConfigKeywords =
    {
        "SetEntityInvincible", "SetEntityHealth 1000", "godMode = true",
        "god_mode = true", "invincible = true", "SetPlayerInvincible",
        "SetEntityHealth(PlayerPedId(), 1000", "godMode=true",
        "playerGodMode", "noclip_enabled", "health_hack = true",
        "armor_max_hack", "SetEntityInvincible(PlayerPedId()",
        "NetworkSetPlayerIsPassive", "SetPedMaxHealth",
        "SetEntityMaxHealth", "RestorePlayerStamina",
        "SetPlayerHealthRechargeMultiplier", "SetPedArmour",
        "GiveWeaponToPed", "SetPlayerMayNotEnterAnyVehicle",
        "SetMaxWantedLevel(0)", "ClearPlayerWantedLevel"
    };

    private static readonly string[] LuaScriptPatterns =
    {
        "SetEntityInvincible(PlayerPedId(), true)",
        "SetEntityHealth", "TriggerEvent('godmode')",
        "TriggerEvent(\"godmode\")", "noclip_hack",
        "armor_bypass", "SetEntityInvincible(ped, true)",
        "SetEntityInvincible(GetPlayerPed(-1), true)",
        "SetEntityHealth(PlayerPedId(), 200)",
        "SetEntityMaxHealth(PlayerPedId()",
        "TriggerServerEvent('godmode')",
        "TriggerServerEvent(\"godmode\")",
        "exports['godmode']", "exports[\"godmode\"]",
        "GodMode = true", "godMode = true",
        "IsEntityInvincible(", "SetEntityInvincible(",
        "SetPedCanSufferCriticalHits(PlayerPedId(), false)",
        "SetPlayerHealthRechargeMultiplier(PlayerId(), 0.0)",
        "NetworkSetEntityInvisibleToNetwork(",
        "SetEntityCollision(PlayerPedId(), false",
        "SetEntityAlpha(PlayerPedId(), 0",
        "TriggerEvent('noclip')", "TriggerEvent(\"noclip\")",
        "noclip = true", "SetEntityCollision(",
        "SetPedToRagdoll(", "ResurrectPed("
    };

    private static readonly string[] JsGodModePatterns =
    {
        "SetEntityInvincible(", "SetEntityHealth(", "godMode",
        "invincible", "noclip_hack", "armor_bypass",
        "alt.emit('godmode'", "alt.emit(\"godmode\"",
        "TriggerEvent('godmode'", "mp.events.add('godmode'",
        "SetEntityInvincible(mp.players.local.handle",
        "PlayerPedId()", "SetPlayerInvincible(",
        "GivePlayerMoney(", "NetworkSetPlayerIsPassive(",
        "god_mode_active", "invincibility_active",
        "health_regen_hack", "armor_max_set",
        "SetMaxWantedLevel(0", "ClearPlayerWantedLevel("
    };

    private static readonly string[] NativeDbPatterns =
    {
        "0xDAF87BE498650776", // SET_ENTITY_INVINCIBLE
        "0x6B76DC1F3AE6E6A3", // SET_ENTITY_HEALTH
        "0xEEF059FAD016D209", // GET_ENTITY_HEALTH
        "0x6E7A6DBA", // SET_PLAYER_INVINCIBLE (legacy)
        "0xB721981B2B939E07", // SET_PED_MAX_HEALTH
        "SET_ENTITY_INVINCIBLE", "GET_PLAYER_PED",
        "SET_ENTITY_HEALTH", "SET_PED_ARMOUR",
        "SET_PLAYER_HEALTH_RECHARGE_MULTIPLIER",
        "NetworkSetEntityInvisibleToNetwork",
        "SET_PED_CAN_SUFFER_CRITICAL_HITS",
        "RESURRECT_PED", "0xC1AF4A" // RESURRECT_PED hash fragment
    };

    private static readonly string[] CefCacheGodModePatterns =
    {
        "SetEntityInvincible", "godMode", "invincible_hack",
        "noclip_fivem", "armor_bypass", "health_hack",
        "fivem_godmode", "player_god_mode", "immortal_player",
        "TriggerEvent('godmode'", "godmode_active",
        "SetEntityHealth", "PlayerPedId", "invincibility",
        "god_mode_script", "health_regen", "armor_max"
    };

    private static readonly string[] DiscordKeywords =
    {
        "fivem god mode", "invincible fivem", "health hack fivem",
        "noclip fivem", "armor hack", "god mode fivem",
        "fivem godmode", "fivem invincible", "fivem noclip",
        "immortal fivem", "health hack fivem", "armor bypass fivem",
        "fivem health hack", "fivem armor hack", "god mode cheat fivem",
        "player invincible fivem", "fivem no clip", "fivem god hack"
    };

    private static readonly string[] MemoryManipulationKeywords =
    {
        "SetEntityInvincible", "SetEntityHealth", "godmode_inject",
        "invincible_patch", "health_hack", "fivem_god",
        "noclip_inject", "armor_bypass", "player_health_patch",
        "god_mode_offset", "health_offset_fivem", "invincible_offset",
        "fivem_health_inject", "noclip_offset", "armor_offset_fivem"
    };

    private static readonly string UserAssistBase =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

    private static readonly string[] UserAssistGodModeKeywords =
    {
        "godmode", "god_mode", "invincible", "noclip", "healthhack",
        "health_hack", "armorhack", "armor_hack", "immortal",
        "fivem_god", "fivemgod", "fivem_invincible", "fiveminvincible",
        "player_god", "playergod", "god_hack", "godhack"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting FiveM god mode forensic scan");

        await Task.WhenAll(
            CheckGodModeFiles(ctx, ct),
            CheckFiveMConfigFiles(ctx, ct),
            CheckLogFiles(ctx, ct),
            CheckLuaScriptFiles(ctx, ct),
            CheckJsScriptFiles(ctx, ct),
            CheckKnownGodModeExes(ctx, ct),
            CheckRegistry(ctx, ct),
            CheckPrefetch(ctx, ct),
            CheckUserAssist(ctx, ct),
            CheckDiscordArtifacts(ctx, ct),
            CheckNativeDbExploitPatterns(ctx, ct),
            CheckCefBrowserCache(ctx, ct),
            CheckMemoryManipulationArtifacts(ctx, ct),
            CheckFiveMCacheDirectories(ctx, ct),
            CheckTempGodModeArtifacts(ctx, ct)
        );

        ctx.Report(1.0, Name, "FiveM god mode forensic scan complete");
    }

    private Task CheckGodModeFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        var searchRoots = new[]
        {
            appData, localAppData, temp, desktop, docs, downloads,
            Path.Combine(appData, "FiveM"),
            Path.Combine(localAppData, "FiveM"),
            Path.Combine(appData, "FiveM.app"),
            Path.Combine(localAppData, "FiveM.app")
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            foreach (var pattern in GodModeFilePatterns)
            {
                if (ct.IsCancellationRequested) return;
                string[] found = Array.Empty<string>();
                try
                {
                    found = Directory.GetFiles(root, pattern, SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var f in found)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM god mode file: {Path.GetFileName(f)}",
                        Risk = RiskLevel.High,
                        Location = f,
                        FileName = Path.GetFileName(f),
                        Reason = $"File matching god mode pattern '{pattern}' found at '{f}'. " +
                                 "Files with these naming patterns are characteristic of FiveM god mode, invincibility, and noclip cheat tools. " +
                                 "This artifact indicates the presence of a player invincibility or health hack tool."
                    });
                }
            }

            foreach (var pattern in GodModeFilePatterns)
            {
                if (ct.IsCancellationRequested) return;
                if (root == appData || root == localAppData || root == temp) continue;

                string[] deepFound = Array.Empty<string>();
                try
                {
                    deepFound = Directory.GetFiles(root, pattern, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var f in deepFound)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM god mode file (deep): {Path.GetFileName(f)}",
                        Risk = RiskLevel.High,
                        Location = f,
                        FileName = Path.GetFileName(f),
                        Reason = $"File matching god mode pattern '{pattern}' found at '{f}' in FiveM directory tree. " +
                                 "Deep scan within FiveM application directories reveals god mode cheat files deployed as resources or scripts. " +
                                 "This is a forensic artifact of FiveM god mode tool deployment."
                    });
                }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMConfigFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var fiveMRoots = new[]
        {
            Path.Combine(appData, "FiveM"),
            Path.Combine(localAppData, "FiveM"),
            Path.Combine(appData, "FiveM.app"),
            Path.Combine(localAppData, "FiveM.app"),
            Path.Combine(localAppData, "FiveM", "FiveM.app")
        };

        foreach (var fiveMRoot in fiveMRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(fiveMRoot)) continue;

            string[] configFiles = Array.Empty<string>();
            try
            {
                configFiles = Directory.GetFiles(fiveMRoot, "*.cfg", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(fiveMRoot, "*.json", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(fiveMRoot, "*.ini", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(fiveMRoot, "*.xml", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(fiveMRoot, "*.lua", SearchOption.AllDirectories))
                    .Where(f => new FileInfo(f).Length < 5 * 1024 * 1024)
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var configFile in configFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var keyword in FiveMConfigKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM god mode config: {Path.GetFileName(configFile)}",
                            Risk = RiskLevel.High,
                            Location = configFile,
                            FileName = Path.GetFileName(configFile),
                            Detail = $"Config keyword: {keyword}",
                            Reason = $"FiveM configuration file '{configFile}' contains god mode setting '{keyword}'. " +
                                     "God mode tools write configuration to FiveM config files enabling persistent invincibility settings. " +
                                     "This configuration artifact indicates god mode was enabled via a FiveM cheat resource."
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckLogFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();

        var logSearchRoots = new[]
        {
            Path.Combine(appData, "FiveM"),
            Path.Combine(localAppData, "FiveM"),
            Path.Combine(appData, "FiveM.app"),
            Path.Combine(localAppData, "FiveM.app"),
            temp
        };

        foreach (var logRoot in logSearchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(logRoot)) continue;

            string[] logFiles = Array.Empty<string>();
            try
            {
                logFiles = Directory.GetFiles(logRoot, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(logRoot, "*.txt", SearchOption.AllDirectories))
                    .Where(f => new FileInfo(f).Length < 10 * 1024 * 1024)
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var logFile in logFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var keyword in LogKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM god mode log evidence: {Path.GetFileName(logFile)}",
                            Risk = RiskLevel.High,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Detail = $"Log keyword: {keyword}",
                            Reason = $"FiveM log file '{logFile}' contains god mode keyword '{keyword}'. " +
                                     "FiveM client and server logs record cheat events and status messages. " +
                                     "Log entries referencing god mode or invincibility are forensic evidence of cheat tool activity."
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckLuaScriptFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var luaSearchRoots = new[]
        {
            Path.Combine(appData, "FiveM"),
            Path.Combine(localAppData, "FiveM"),
            Path.Combine(appData, "FiveM.app"),
            Path.Combine(localAppData, "FiveM.app"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "plugins"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "citizen"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "resources")
        };

        foreach (var luaRoot in luaSearchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(luaRoot)) continue;

            string[] luaFiles = Array.Empty<string>();
            try
            {
                luaFiles = Directory.GetFiles(luaRoot, "*.lua", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(luaRoot, "*.luac", SearchOption.AllDirectories))
                    .Where(f => new FileInfo(f).Length < 5 * 1024 * 1024)
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var luaFile in luaFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var pattern in LuaScriptPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM god mode Lua script: {Path.GetFileName(luaFile)}",
                            Risk = RiskLevel.High,
                            Location = luaFile,
                            FileName = Path.GetFileName(luaFile),
                            Detail = $"Lua pattern: {pattern}",
                            Reason = $"FiveM Lua script '{luaFile}' contains god mode API pattern '{pattern}'. " +
                                     "FiveM Lua resources are the primary delivery mechanism for god mode and invincibility cheats. " +
                                     "This script contains native calls that set the player entity invincible or manipulate health/armor. " +
                                     "This is a high-confidence forensic indicator of god mode cheat script deployment."
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckJsScriptFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var jsSearchRoots = new[]
        {
            Path.Combine(appData, "FiveM"),
            Path.Combine(localAppData, "FiveM"),
            Path.Combine(appData, "FiveM.app"),
            Path.Combine(localAppData, "FiveM.app"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "plugins"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "citizen"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "resources")
        };

        foreach (var jsRoot in jsSearchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(jsRoot)) continue;

            string[] jsFiles = Array.Empty<string>();
            try
            {
                jsFiles = Directory.GetFiles(jsRoot, "*.js", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(jsRoot, "*.mjs", SearchOption.AllDirectories))
                    .Where(f => new FileInfo(f).Length < 5 * 1024 * 1024)
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var jsFile in jsFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var pattern in JsGodModePatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM god mode JS script: {Path.GetFileName(jsFile)}",
                            Risk = RiskLevel.High,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Detail = $"JS pattern: {pattern}",
                            Reason = $"FiveM JavaScript resource '{jsFile}' contains god mode pattern '{pattern}'. " +
                                     "JavaScript-based FiveM resources can invoke GTA V natives to set player invincibility, " +
                                     "manipulate health and armor, and enable noclip. " +
                                     "This script artifact is forensic evidence of a JS-based FiveM god mode cheat."
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckKnownGodModeExes(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FiveM"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM")
        };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var exeName in GodModeExeNames)
            {
                if (ct.IsCancellationRequested) return;
                string[] found = Array.Empty<string>();
                try
                {
                    found = Directory.GetFiles(dir, exeName, SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var exe in found)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM god mode executable: {exeName}",
                        Risk = RiskLevel.Critical,
                        Location = exe,
                        FileName = exeName,
                        Reason = $"Known FiveM god mode executable '{exeName}' found at '{exe}'. " +
                                 "This is a recognized FiveM god mode, invincibility, noclip, or health hack tool executable. " +
                                 "The presence of this file is a critical forensic indicator of god mode cheat tool possession."
                    });
                }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckRegistry(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var registryPaths = new[]
        {
            @"Software\FiveM\GodMode",
            @"Software\FiveMInvincible",
            @"Software\FiveM\Invincible",
            @"Software\FiveM\NoClip",
            @"Software\FiveM\HealthHack",
            @"Software\FiveMGodMode",
            @"Software\FiveMNoClip",
            @"Software\FiveMHealthHack",
            @"Software\FiveM\ArmorHack",
            @"Software\FiveMArmorHack",
            @"Software\FiveM\Immortal",
            @"Software\FiveMImmortal",
            @"Software\GodModeFiveM",
            @"Software\InvincibleFiveM"
        };

        foreach (var regPath in registryPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"FiveM god mode registry key: {regPath}",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{regPath}",
                    Reason = $"Registry key 'HKCU\\{regPath}' associated with FiveM god mode tools was found. " +
                             "God mode and invincibility cheat tools for FiveM store configuration and activation state in the registry. " +
                             "This key persists after tool removal and is a reliable forensic artifact of god mode cheat use."
                });

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();
                    var valueData = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM god mode registry value: {valueName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{regPath}\{valueName}",
                        Detail = $"Value: {valueName} = {valueData}",
                        Reason = $"Registry value '{valueName}' under god mode key 'HKCU\\{regPath}' contains: '{valueData}'. " +
                                 "FiveM god mode tool configuration values remain in the registry as forensic artifacts. " +
                                 "This value is evidence that the god mode tool was configured and activated on this system."
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var godModeValueKeywords = new[]
        {
            "godmode", "god_mode", "invincible", "noclip", "healthhack",
            "health_hack", "armorhack", "armor_hack", "immortal",
            "fivem_god", "fivemgod", "player_god", "god_player"
        };

        try
        {
            using var swKey = Registry.CurrentUser.OpenSubKey(@"Software", writable: false);
            if (swKey is not null)
            {
                foreach (var subKeyName in swKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    bool isGodMode = godModeValueKeywords.Any(k =>
                        subKeyName.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (!isGodMode) continue;

                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM god mode software key: {subKeyName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\Software\{subKeyName}",
                        Reason = $"Registry subkey 'HKCU\\Software\\{subKeyName}' matches FiveM god mode tool naming patterns. " +
                                 "God mode cheat software registry keys persist after uninstallation. " +
                                 "This key is a forensic artifact indicating FiveM god mode or invincibility tool installation."
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckPrefetch(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir))
        {
            await Task.CompletedTask;
            return;
        }

        string[] pfFiles = Array.Empty<string>();
        try
        {
            pfFiles = Directory.GetFiles(prefetchDir, "*.pf");
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        var godModeExeNamesNoExt = GodModeExeNames
            .Select(e => Path.GetFileNameWithoutExtension(e).ToUpperInvariant())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var godModeKeywordsUpper = new[]
        {
            "GODMODE", "GOD_MODE", "INVINCIBLE", "NOCLIP", "HEALTHHACK",
            "HEALTH_HACK", "ARMORHACK", "ARMOR_HACK", "IMMORTAL",
            "FIVEM_GOD", "PLAYER_GOD", "GOD_HACK", "FIVEM_INVINCIBLE",
            "HEALTH_BYPASS", "ARMOR_BYPASS", "NOCLIP_FIVEM"
        };

        foreach (var pf in pfFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var pfName = Path.GetFileNameWithoutExtension(pf).ToUpperInvariant();
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            bool isGodMode = godModeExeNamesNoExt.Contains(exeName) ||
                             godModeKeywordsUpper.Any(k => exeName.Contains(k, StringComparison.OrdinalIgnoreCase));

            if (!isGodMode) continue;

            DateTime lastRun = default;
            try { lastRun = File.GetLastWriteTimeUtc(pf); } catch { }

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"FiveM god mode prefetch: {exeName}",
                Risk = RiskLevel.High,
                Location = pf,
                FileName = exeName + ".exe",
                Detail = lastRun != default ? $"Prefetch last updated: {lastRun:yyyy-MM-dd HH:mm:ss} UTC" : null,
                Reason = $"Windows Prefetch entry indicates execution of '{exeName}.exe', a known FiveM god mode or invincibility tool. " +
                         "Prefetch entries are created on first execution and updated on each subsequent run. " +
                         "This artifact proves the god mode tool was executed on this system even if the binary has since been deleted."
            });
        }
    }, ct);

    private Task CheckUserAssist(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var baseKey = Registry.CurrentUser.OpenSubKey(UserAssistBase, writable: false);
            if (baseKey is null)
            {
                await Task.CompletedTask;
                return;
            }

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

                        var decoded = Rot13Decode(encodedName).ToLowerInvariant();

                        bool isGodMode = UserAssistGodModeKeywords.Any(k =>
                            decoded.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (!isGodMode) continue;

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
                            Title = $"FiveM god mode UserAssist: {Path.GetFileName(decoded)}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{UserAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Detail = $"Decoded: {decoded} | Run count: {runCount} | " +
                                     $"Last run: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}",
                            Reason = $"UserAssist registry entry shows execution of FiveM god mode launcher '{Path.GetFileName(decoded)}' " +
                                     $"({runCount} time(s) executed" +
                                     (lastRun.HasValue ? $", last seen {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                     "). UserAssist ROT13-encoded entries survive file deletion and are reliable execution forensics. " +
                                     "This entry proves the god mode or invincibility tool was launched from Windows Explorer."
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckDiscordArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var discordClients = new[] { "discord", "discordptb", "discordcanary" };

        foreach (var client in discordClients)
        {
            if (ct.IsCancellationRequested) return;
            var discordRoot = Path.Combine(appData, client);
            if (!Directory.Exists(discordRoot)) continue;

            var cachePaths = new[]
            {
                Path.Combine(discordRoot, "Cache", "Cache_Data"),
                Path.Combine(discordRoot, "Cache"),
                Path.Combine(discordRoot, "Local Storage", "leveldb"),
                Path.Combine(discordRoot, "Session Storage"),
                Path.Combine(discordRoot, "Code Cache", "js")
            };

            foreach (var cachePath in cachePaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(cachePath)) continue;

                string[] cacheFiles = Array.Empty<string>();
                try
                {
                    cacheFiles = Directory.GetFiles(cachePath).Take(100).ToArray();
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var cacheFile in cacheFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    var fi = new FileInfo(cacheFile);
                    if (fi.Length > 10 * 1024 * 1024) continue;
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        var bytes = File.ReadAllBytes(cacheFile);
                        content = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var keyword in DiscordKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Discord FiveM god mode artifact: {keyword}",
                                Risk = RiskLevel.High,
                                Location = cacheFile,
                                FileName = Path.GetFileName(cacheFile),
                                Detail = $"Discord client: {client} | Keyword: {keyword}",
                                Reason = $"Discord cache file '{cacheFile}' contains FiveM god mode keyword '{keyword}'. " +
                                         "Discord cache preserves server names, channel content, and messages from cheat distribution servers. " +
                                         "This artifact indicates membership or activity in FiveM god mode or invincibility cheat communities."
                            });
                            break;
                        }
                    }
                }
            }
        }
    }, ct);

    private Task CheckNativeDbExploitPatterns(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var nativeSearchRoots = new[]
        {
            Path.Combine(appData, "FiveM"),
            Path.Combine(localAppData, "FiveM"),
            Path.Combine(appData, "FiveM.app"),
            Path.Combine(localAppData, "FiveM.app"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "citizen"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "resources"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "plugins")
        };

        foreach (var nativeRoot in nativeSearchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(nativeRoot)) continue;

            string[] scriptFiles = Array.Empty<string>();
            try
            {
                scriptFiles = Directory.GetFiles(nativeRoot, "*.lua", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(nativeRoot, "*.js", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(nativeRoot, "*.cs", SearchOption.AllDirectories))
                    .Concat(Directory.GetFiles(nativeRoot, "*.txt", SearchOption.AllDirectories))
                    .Where(f => new FileInfo(f).Length < 3 * 1024 * 1024)
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var scriptFile in scriptFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                var matched = NativeDbPatterns.FirstOrDefault(p =>
                    content.Contains(p, StringComparison.OrdinalIgnoreCase));

                if (matched is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"FiveM NativeDB god mode exploit: {Path.GetFileName(scriptFile)}",
                    Risk = RiskLevel.High,
                    Location = scriptFile,
                    FileName = Path.GetFileName(scriptFile),
                    Detail = $"NativeDB pattern: {matched}",
                    Reason = $"FiveM script '{scriptFile}' contains NativeDB exploit pattern '{matched}' " +
                             "used to invoke player health/invincibility natives directly. " +
                             "NativeDB hash values or native function names for SET_ENTITY_INVINCIBLE, SET_ENTITY_HEALTH, " +
                             "SET_PED_ARMOUR and related natives are the core mechanism of FiveM god mode cheats. " +
                             "This is a forensic artifact of native-level god mode exploitation."
                });
            }
        }
    }, ct);

    private Task CheckCefBrowserCache(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var cefCacheRoots = new[]
        {
            Path.Combine(localAppData, "FiveM", "FiveM.app", "cache", "browser"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "cache"),
            Path.Combine(localAppData, "FiveM", "cache"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "nui-storage"),
            Path.Combine(appData, "FiveM", "cache"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "data", "cache")
        };

        foreach (var cefRoot in cefCacheRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(cefRoot)) continue;

            string[] cefFiles = Array.Empty<string>();
            try
            {
                cefFiles = Directory.GetFiles(cefRoot, "*", SearchOption.AllDirectories)
                    .Where(f => {
                        var fi = new FileInfo(f);
                        return fi.Length > 0 && fi.Length < 8 * 1024 * 1024;
                    })
                    .Take(200)
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var cefFile in cefFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    var bytes = File.ReadAllBytes(cefFile);
                    content = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                var matched = CefCacheGodModePatterns.FirstOrDefault(p =>
                    content.Contains(p, StringComparison.OrdinalIgnoreCase));

                if (matched is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"FiveM CEF cache god mode payload: {Path.GetFileName(cefFile)}",
                    Risk = RiskLevel.High,
                    Location = cefFile,
                    FileName = Path.GetFileName(cefFile),
                    Detail = $"CEF pattern: {matched}",
                    Reason = $"FiveM CEF browser cache file '{cefFile}' contains god mode JavaScript payload pattern '{matched}'. " +
                             "FiveM's Chromium Embedded Framework (CEF) browser cache stores NUI (JavaScript UI) scripts from servers. " +
                             "God mode cheats delivered via FiveM's NUI system leave JavaScript payloads in the CEF cache. " +
                             "This is a forensic artifact of browser-delivered god mode exploitation."
                });
            }
        }
    }, ct);

    private Task CheckMemoryManipulationArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        var dumpSearchRoots = new[]
        {
            Path.Combine(appData, "FiveM"),
            Path.Combine(localAppData, "FiveM"),
            Path.Combine(localAppData, "CrashDumps"),
            docs,
            temp,
            @"C:\Windows\Temp"
        };

        foreach (var dumpRoot in dumpSearchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dumpRoot)) continue;

            string[] dumpFiles = Array.Empty<string>();
            try
            {
                dumpFiles = Directory.GetFiles(dumpRoot, "*.dmp", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(dumpRoot, "*.mdmp", SearchOption.TopDirectoryOnly))
                    .Concat(Directory.GetFiles(dumpRoot, "*.bin", SearchOption.TopDirectoryOnly))
                    .Where(f => {
                        var fi = new FileInfo(f);
                        return fi.Length > 0 && fi.Length < 200 * 1024 * 1024;
                    })
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dumpFile in dumpFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var headerSize = (int)Math.Min(65536, new FileInfo(dumpFile).Length);
                var header = new byte[headerSize];
                int bytesRead = 0;
                try
                {
                    using var fs = new FileStream(dumpFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    bytesRead = await fs.ReadAsync(header, 0, headerSize, ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                if (bytesRead == 0) continue;

                var headerText = Encoding.ASCII.GetString(header, 0, bytesRead);

                var matched = MemoryManipulationKeywords.FirstOrDefault(k =>
                    headerText.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (matched is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"FiveM god mode memory dump artifact: {Path.GetFileName(dumpFile)}",
                    Risk = RiskLevel.Medium,
                    Location = dumpFile,
                    FileName = Path.GetFileName(dumpFile),
                    Detail = $"Memory keyword: {matched}",
                    Reason = $"Memory dump file '{dumpFile}' contains FiveM god mode string '{matched}'. " +
                             "Memory dumps from FiveM process crashes or diagnostics may capture god mode tool code, " +
                             "player entity manipulation strings, and health/armor hack identifiers in process memory. " +
                             "These strings in a dump are forensic evidence of memory-level god mode injection."
                });
            }
        }
    }, ct);

    private Task CheckFiveMCacheDirectories(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var fiveMCacheRoots = new[]
        {
            Path.Combine(localAppData, "FiveM", "FiveM.app"),
            Path.Combine(localAppData, "FiveM"),
            Path.Combine(appData, "FiveM"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "citizen"),
            Path.Combine(localAppData, "FiveM", "FiveM.app", "resources")
        };

        var godModeDirKeywords = new[]
        {
            "godmode", "god_mode", "invincible", "noclip", "healthhack",
            "health_hack", "armorhack", "armor_hack", "immortal",
            "fivem_god", "player_god", "god_hack", "health_bypass",
            "armor_bypass", "noclip_hack", "god_player"
        };

        foreach (var cacheRoot in fiveMCacheRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(cacheRoot)) continue;

            string[] dirs = Array.Empty<string>();
            try
            {
                dirs = Directory.GetDirectories(cacheRoot, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var dir in dirs)
            {
                if (ct.IsCancellationRequested) return;
                var dirName = Path.GetFileName(dir).ToLowerInvariant();

                bool isGodModeDir = godModeDirKeywords.Any(k =>
                    dirName.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (!isGodModeDir) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"FiveM god mode cache directory: {Path.GetFileName(dir)}",
                    Risk = RiskLevel.High,
                    Location = dir,
                    FileName = Path.GetFileName(dir),
                    Reason = $"FiveM cache/resource directory '{Path.GetFileName(dir)}' at '{dir}' matches god mode naming patterns. " +
                             "FiveM god mode cheat resources are deployed as named directories in the FiveM application tree. " +
                             "These directories persist as forensic artifacts after the cheat resource is disabled or unloaded."
                });
            }

            string[] cacheFiles = Array.Empty<string>();
            try
            {
                cacheFiles = Directory.GetFiles(cacheRoot, "*", SearchOption.AllDirectories)
                    .Where(f => {
                        var name = Path.GetFileName(f).ToLowerInvariant();
                        return godModeDirKeywords.Any(k => name.Contains(k, StringComparison.OrdinalIgnoreCase));
                    })
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var cacheFile in cacheFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var matchedKw = godModeDirKeywords.First(k =>
                    Path.GetFileName(cacheFile).Contains(k, StringComparison.OrdinalIgnoreCase));

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"FiveM god mode cache file: {Path.GetFileName(cacheFile)}",
                    Risk = RiskLevel.High,
                    Location = cacheFile,
                    FileName = Path.GetFileName(cacheFile),
                    Detail = $"Keyword: {matchedKw}",
                    Reason = $"FiveM cache file '{Path.GetFileName(cacheFile)}' at '{cacheFile}' matches god mode keyword '{matchedKw}'. " +
                             "Cached files from god mode cheat resources persist in the FiveM application cache. " +
                             "This file name artifact is forensic evidence of god mode resource caching and execution."
                });
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckTempGodModeArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var temp = Path.GetTempPath();
        var localTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");

        var tempRoots = new[] { temp, localTemp };

        var godModeTempKeywords = new[]
        {
            "godmode", "god_mode", "invincible", "noclip_fivem",
            "health_hack", "armor_hack", "fivem_god", "player_god",
            "god_player_tmp", "invincible_tmp", "health_tmp_fivem",
            "armor_tmp_fivem", "noclip_tmp", "god_tmp"
        };

        foreach (var tempRoot in tempRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(tempRoot)) continue;

            foreach (var pattern in GodModeFilePatterns)
            {
                if (ct.IsCancellationRequested) return;
                string[] found = Array.Empty<string>();
                try
                {
                    found = Directory.GetFiles(tempRoot, pattern, SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var f in found)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM god mode temp artifact: {Path.GetFileName(f)}",
                        Risk = RiskLevel.High,
                        Location = f,
                        FileName = Path.GetFileName(f),
                        Reason = $"Temporary file matching god mode pattern '{pattern}' found at '{f}'. " +
                                 "FiveM god mode tools drop temporary files during injection and activation into FiveM processes. " +
                                 "These temp artifacts are created during god mode activation and indicate active cheat use."
                    });
                }
            }

            string[] allTempFiles = Array.Empty<string>();
            try
            {
                allTempFiles = Directory.GetFiles(tempRoot, "*", SearchOption.TopDirectoryOnly)
                    .Where(f => {
                        var name = Path.GetFileName(f).ToLowerInvariant();
                        return godModeTempKeywords.Any(k => name.Contains(k, StringComparison.OrdinalIgnoreCase));
                    })
                    .ToArray();
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var f in allTempFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var matchedKw = godModeTempKeywords.First(k =>
                    Path.GetFileName(f).Contains(k, StringComparison.OrdinalIgnoreCase));

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"FiveM god mode temp file: {Path.GetFileName(f)}",
                    Risk = RiskLevel.Medium,
                    Location = f,
                    FileName = Path.GetFileName(f),
                    Detail = $"Keyword: {matchedKw}",
                    Reason = $"Temporary file '{Path.GetFileName(f)}' at '{f}' matches god mode temp file keyword '{matchedKw}'. " +
                             "FiveM god mode injection tools generate temp files during player entity memory patching. " +
                             "These files are forensic artifacts of FiveM god mode activation attempts."
                });
            }
        }
        await Task.CompletedTask;
    }, ct);

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
}
