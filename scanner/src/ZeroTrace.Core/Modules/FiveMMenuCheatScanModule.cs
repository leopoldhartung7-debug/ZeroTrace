using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMMenuCheatScanModule : IScanModule
{
    public string Name => "FiveM Cheat Menu Detection";
    public double Weight => 4.5;
    public int ParallelGroup => 4;

    private static readonly string LocalApp = Environment.GetFolderPath(
        Environment.SpecialFolder.LocalApplicationData);
    private static readonly string AppData = Environment.GetFolderPath(
        Environment.SpecialFolder.ApplicationData);

    private static readonly string[] FiveMRootPaths =
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CitizenFX"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"FiveM\FiveM.app\data"),
    };

    private static readonly HashSet<string> CheatExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "eulen.exe", "impulse.exe", "force_menu.exe", "cherax.exe", "midnight.exe",
        "vanity.exe", "modest.exe", "kiddions.exe", "modmenugta.exe", "lua_executor.exe",
        "lua_runner.exe", "fivem_menu.exe", "fivem_cheat.exe", "fivem_hack.exe",
        "fivem_bypass.exe", "citizen_bypass.exe", "citizenfx_bypass.exe", "fivembypass.exe",
        "fivem_injector.exe", "fiveminject.exe", "fivem_bypass.exe", "mlo_bypass.exe",
        "nopixel_bypass.exe", "server_bypass.exe", "anticheat_bypass_fivem.exe",
        "cfx_bypass.exe", "cfxre_bypass.exe", "lspdfr_bypass.exe", "cheat_fivem.exe",
        "cheat_gta.exe", "gta5_bypass.exe", "gtav_bypass.exe", "fivem_lua.exe",
        "lua_inject.exe", "lua_bypass.exe", "script_injector.exe", "resource_bypass.exe",
        "txadmin_bypass.exe", "2take1.exe", "orbital.exe", "skript.exe", "lynx_menu.exe",
        "stand_menu.exe", "stand.exe", "ozark.exe", "tsunami.exe", "paragon.exe",
        "brute.exe", "plasticity.exe", "re_recovery.exe", "rockstar_recovery.exe",
        "recovery_tool.exe", "gta_recovery.exe", "money_recovery.exe", "mod_menu.exe",
        "gta5_mod.exe", "gtav_mod.exe", "fivem_mod.exe", "fivem_trainer.exe",
        "native_trainer.exe", "simple_trainer.exe", "menyoo_trainer.exe",
        "script_hook_launcher.exe", "asi_loader.exe", "dinput8_loader.exe",
        "version_loader.exe", "cheat_loader.exe", "injector_fivem.exe",
        "fivem_inject.exe", "fivem_hack_v2.exe", "cfx_cheat.exe", "citizenfx_cheat.exe",
        "cheat_engine_fivem.exe", "fivem_bypass_v2.exe", "fivem_bypass_v3.exe",
    };

    private static readonly HashSet<string> CheatDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "eulen.dll", "impulse.dll", "force.dll", "cherax.dll", "midnight.dll",
        "vanity.dll", "modest.dll", "kiddions.dll", "2take1.dll", "orbital.dll",
        "skript.dll", "lynx.dll", "stand.dll", "ozark.dll", "tsunami.dll",
        "paragon.dll", "brute.dll", "plasticity.dll", "cheat_fivem.dll",
        "fivem_cheat.dll", "fivem_hack.dll", "fivem_bypass.dll", "cfx_bypass.dll",
        "citizen_bypass.dll", "citizenfx_bypass.dll", "lua_executor.dll",
        "lua_inject.dll", "script_injector.dll", "resource_bypass.dll",
        "anticheat_bypass.dll", "gta5_bypass.dll", "fivem_menu.dll",
    };

    private static readonly HashSet<string> SuspiciousDllsInWrongDir = new(StringComparer.OrdinalIgnoreCase)
    {
        "script_hook_v.dll", "scripthookv.dll", "dinput8.dll", "version.dll",
        "ScriptHookV.dll", "ScriptHookVDotNet.dll", "ScriptHookVDotNet2.dll",
        "ScriptHookVDotNet3.dll", "dsound.dll", "winmm.dll", "d3d9.dll",
        "d3d11.dll", "bink2w64.dll",
    };

    private static readonly HashSet<string> CheatLuaFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "executor.lua", "cheat.lua", "menu.lua", "bypass.lua", "inject.lua",
        "aimbot.lua", "esp.lua", "godmode.lua", "noclip.lua", "teleport.lua",
        "speedhack.lua", "money.lua", "weapons.lua", "vehicle.lua", "crash.lua",
        "kick.lua", "freeze.lua", "spin.lua", "explosion.lua", "blackout.lua",
        "loader.lua", "main_cheat.lua", "cheat_menu.lua", "hack.lua",
        "exploit.lua", "grief.lua", "troll.lua", "modmenu.lua",
    };

    private static readonly string[] LuaCheatApiPatterns =
    {
        "Citizen.InvokeNative", "CitizenInvokeNative", "invokeNative",
        "NetworkSetVoiceActive", "SetEntityInvincible", "NetworkResurrectLocalPlayer",
        "SetPlayerWantedLevel", "GiveWeaponToPed", "AddExplosion",
        "SetEntityCoords", "TaskLeaveAnyCar", "RemoveAllPedWeapons",
        "SetPedMaxSpeed", "SetEntityCanMigrate", "NetworkRegisterEntityAsNetworked",
        "SetEntityHealth", "NetworkSetEntityInvisibleToNetwork", "DeleteEntity",
        "SetPedComponentVariation", "RequestCollisionAtCoord",
        "GetEntityBoneIndex", "GetEntityBonePosition", "GetEntityCoords",
        "TriggerCheatEvent", "ExecuteClientScript", "ClientScriptInject",
        "TriggerServerEvent.*cheat", "TriggerServerEvent.*bypass",
        "exports\\[.cheat", "exports\\[.hack", "exports\\[.inject",
        "mem.read", "mem.write", "mem.alloc", "hook.create", "hook.install",
        "hook.detour", "aimbot", "wallhack", "spinbot", "bunnyhop",
        "GodMode", "SuperSpeed", "NoClip", "triggerbot",
    };

    private static readonly string[] CheatConfigKeywords =
    {
        "cheat_menu", "lua_executor", "bypass_anticheat", "god_mode", "no_clip",
        "money_drop", "vehicle_spawn", "weapon_give", "teleport_player",
        "kick_player", "crash_player", "freeze_player", "wanted_level",
        "blackout_mode", "remove_ped", "delete_vehicle", "explosion_spam",
        "spin_players", "move_players", "network_bypass", "anticheat_bypass",
        "citizenfx_bypass", "cfx_bypass", "fivem_bypass", "lua_inject",
        "script_inject", "resource_inject", "native_bypass", "eac_bypass",
        "easyanticheat_bypass", "injection_method", "bypass_method",
        "cheat_enabled", "hack_enabled", "menu_enabled", "exploit_enabled",
        "aimbot_enabled", "esp_enabled", "wallhack_enabled", "speedhack_enabled",
        "bunnyhop_enabled", "spinbot_enabled", "godmode_enabled",
        "teleport_enabled", "noclip_enabled", "moneyloop_enabled",
        "vehicle_godmode", "weapon_godmode", "player_crash", "server_crash",
    };

    private static readonly string[] FiveMBypassIndicatorFiles =
    {
        "CitizenFX.log.bak", "CitizenFX_backup.log", "citizen_bypass.cfg",
        "fivem_bypass.cfg", "anticheat_bypass.json", "bypass_config.json",
        "cheat_config.json", "menu_config.json", "executor_config.json",
        "lua_executor.cfg", "bypass.ini", "cheat.ini", "menu.ini",
    };

    private static readonly string[] CacheCheatArtifacts =
    {
        "scripthookv_bypass", "dinput8_original", "version_original",
        "eac_bypass", "easyanticheat_bypass", "anticheat_patch",
        "citizen_patch", "citizenfx_patch", "cfx_patch",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting FiveM cheat menu scan...");

        bool fivemInstalled = FiveMRootPaths.Any(Directory.Exists);
        if (!fivemInstalled)
        {
            ctx.Report(1.0, Name, "FiveM installation not found; skipping.");
            return;
        }

        ctx.Report(0.05, Name, "FiveM installation found; scanning directories...");

        await Task.Run(() =>
        {
            double step = 0.0;

            ScanForCheatExecutables(ctx, ct);
            step += 0.15;
            ctx.Report(step, Name, "Executable scan complete.");

            ScanForCheatDlls(ctx, ct);
            step += 0.15;
            ctx.Report(step, Name, "DLL scan complete.");

            ScanForLuaExecutorArtifacts(ctx, ct);
            step += 0.15;
            ctx.Report(step, Name, "Lua executor scan complete.");

            ScanForBypassArtifacts(ctx, ct);
            step += 0.10;
            ctx.Report(step, Name, "Bypass artifact scan complete.");

            ScanForCheatConfigs(ctx, ct);
            step += 0.15;
            ctx.Report(step, Name, "Config keyword scan complete.");

            ScanCacheDirectory(ctx, ct);
            step += 0.10;
            ctx.Report(step, Name, "Cache directory scan complete.");

            ScanForMisplacedSystemDlls(ctx, ct);
            step += 0.10;
            ctx.Report(step, Name, "Misplaced DLL scan complete.");

            ScanForBrowserLogBypass(ctx, ct);
            step += 0.05;
            ctx.Report(step, Name, "Log location scan complete.");

            CheckRegistryBypassArtifacts(ctx, ct);

            ctx.Report(1.0, Name, "FiveM cheat menu scan complete.");
        }, ct);
    }

    private void ScanForCheatExecutables(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in FiveMRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fn = Path.GetFileName(file);

                if (CheatExeNames.Contains(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Cheat EXE: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known FiveM cheat menu executable '{fn}' found inside the FiveM directory tree. " +
                                 "This file is a recognised cheat menu, injector or bypass tool targeting FiveM / CitizenFX.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                var fnLower = fn.ToLowerInvariant();
                if (ContainsCheatKeyword(fnLower))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious EXE in FiveM directory: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Executable '{fn}' in the FiveM directory tree has a name associated with " +
                                 "cheat tools, injectors or bypass software. Not part of the legitimate FiveM install.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
    }

    private void ScanForCheatDlls(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in FiveMRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fn = Path.GetFileName(file);

                if (CheatDllNames.Contains(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Cheat DLL: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known FiveM cheat DLL '{fn}' found. This library is injected into FiveM's " +
                                 "process to enable cheat functionality such as god mode, ESP, aimbot, " +
                                 "teleportation or anti-cheat bypass.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                var fnLower = fn.ToLowerInvariant();
                bool inPluginDir = file.Contains("plugins", StringComparison.OrdinalIgnoreCase)
                                || file.Contains("mods", StringComparison.OrdinalIgnoreCase)
                                || file.Contains("scripts", StringComparison.OrdinalIgnoreCase);

                if (inPluginDir && ContainsCheatKeyword(fnLower))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious DLL in FiveM plugin directory: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"DLL '{fn}' in a FiveM plugin/mod directory has a name associated with " +
                                 "cheat software. Plugin DLLs are auto-loaded by FiveM's ASI loader.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
    }

    private void ScanForLuaExecutorArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var luaSearchRoots = new[]
        {
            Path.Combine(LocalApp, @"FiveM\FiveM.app\data\cache"),
            Path.Combine(LocalApp, @"FiveM\FiveM.app\plugins"),
            Path.Combine(LocalApp, @"FiveM\FiveM.app\citizen"),
            Path.Combine(LocalApp, @"FiveM\FiveM.app\data"),
            Path.Combine(AppData, "CitizenFX"),
        };

        foreach (var searchRoot in luaSearchRoots)
        {
            if (!Directory.Exists(searchRoot)) continue;
            if (ct.IsCancellationRequested) return;

            IEnumerable<string> luaFiles;
            try
            {
                luaFiles = Directory.EnumerateFiles(searchRoot, "*.lua", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in luaFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fn = Path.GetFileName(file);

                if (CheatLuaFileNames.Contains(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known cheat Lua script: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Lua script '{fn}' has a name matching a known FiveM cheat executor, " +
                                 "menu script or bypass script. Lua executors allow arbitrary native " +
                                 "function calls inside the FiveM scripting engine.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                var fnLower = fn.ToLowerInvariant();
                if (ContainsCheatKeyword(fnLower))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious Lua script name: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Lua script '{fn}' has a name that contains cheat-associated keywords. " +
                                 "FiveM Lua executors use script files to call game natives for cheating.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                AnalyzeLuaContent(ctx, file, fn, ct);
            }
        }
    }

    private void AnalyzeLuaContent(ScanContext ctx, string file, string fn, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        FileInfo fi;
        try { fi = new FileInfo(file); }
        catch (IOException) { return; }

        if (fi.Length > 2 * 1024 * 1024) return;

        string content;
        try
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = sr.ReadToEnd();
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        var hits = new List<string>();
        foreach (var pattern in LuaCheatApiPatterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                hits.Add(pattern);
            if (hits.Count >= 8) break;
        }

        if (hits.Count == 0) return;

        var risk = hits.Count >= 4 ? RiskLevel.Critical
                 : hits.Count >= 2 ? RiskLevel.High
                 : RiskLevel.Medium;

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"Cheat Lua API calls in: {fn}",
            Risk = risk,
            Location = file,
            FileName = fn,
            Reason = $"Lua file '{fn}' contains {hits.Count} cheat-characteristic API pattern(s): " +
                     string.Join(", ", hits.Take(4).Select(h => $"'{h}'")) +
                     (hits.Count > 4 ? " ..." : "") +
                     ". These patterns indicate FiveM native abuse for god mode, teleportation, " +
                     "aimbot, ESP or anti-cheat bypass via Citizen.InvokeNative.",
            Detail = $"Matched patterns ({hits.Count}): {string.Join(", ", hits.Take(6))}"
        });
    }

    private void ScanForBypassArtifacts(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in FiveMRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            IEnumerable<string> allFiles;
            try
            {
                allFiles = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in allFiles)
            {
                if (ct.IsCancellationRequested) return;

                var fn = Path.GetFileName(file);
                var fnLower = fn.ToLowerInvariant();

                foreach (var indicator in FiveMBypassIndicatorFiles)
                {
                    if (fn.Equals(indicator, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM bypass artifact: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"File '{fn}' is a known artifact of FiveM bypass or cheat configuration. " +
                                     "Such files are created by cheat menus, injectors or bypass tools that " +
                                     "target CitizenFX's anti-cheat subsystem.",
                            Detail = $"Path: {file}"
                        });
                        break;
                    }
                }

                foreach (var cacheArtifact in CacheCheatArtifacts)
                {
                    if (fnLower.Contains(cacheArtifact, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM cache bypass artifact: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"File '{fn}' found in FiveM paths contains keywords associated with " +
                                     "anti-cheat bypass tools that patch cached CitizenFX components.",
                            Detail = $"Path: {file} | Matched keyword: {cacheArtifact}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private void ScanForCheatConfigs(ScanContext ctx, CancellationToken ct)
    {
        var configExtensions = new[] { ".cfg", ".ini", ".json", ".txt", ".conf", ".yaml", ".yml", ".toml" };

        foreach (var root in FiveMRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            foreach (var ext in configExtensions)
            {
                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, $"*{ext}", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    FileInfo fi;
                    try { fi = new FileInfo(file); }
                    catch (IOException) { continue; }

                    if (fi.Length > 512 * 1024) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = sr.ReadToEnd();
                    }
                    catch (IOException)
                    {
                        continue;
                    }

                    var hits = new List<string>();
                    foreach (var kw in CheatConfigKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            hits.Add(kw);
                        if (hits.Count >= 6) break;
                    }

                    if (hits.Count == 0) continue;

                    var risk = hits.Count >= 4 ? RiskLevel.Critical
                             : hits.Count >= 2 ? RiskLevel.High
                             : RiskLevel.Medium;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM cheat config keywords: {Path.GetFileName(file)}",
                        Risk = risk,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Config file '{Path.GetFileName(file)}' contains {hits.Count} cheat-related " +
                                 $"keyword(s): {string.Join(", ", hits.Take(4).Select(h => $"'{h}'"))}. " +
                                 "These keywords are characteristic of FiveM cheat menu configuration files.",
                        Detail = $"Matched keywords ({hits.Count}): {string.Join(", ", hits.Take(6))}"
                    });
                }
            }
        }
    }

    private void ScanCacheDirectory(ScanContext ctx, CancellationToken ct)
    {
        var cacheRoot = Path.Combine(LocalApp, @"FiveM\FiveM.app\data\cache");
        if (!Directory.Exists(cacheRoot)) return;

        IEnumerable<string> allFiles;
        try
        {
            allFiles = Directory.EnumerateFiles(cacheRoot, "*", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach (var file in allFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fn = Path.GetFileName(file);
            var fnLower = fn.ToLowerInvariant();
            var ext = Path.GetExtension(fn).ToLowerInvariant();

            if (ext == ".exe")
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"EXE in FiveM cache directory: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Reason = $"Executable '{fn}' found inside the FiveM cache directory. " +
                             "Legitimate FiveM cache files are pre-compiled citizen scripts and " +
                             "resource data — not executables. This may indicate a cheat installer.",
                    Detail = $"Path: {file}"
                });
                continue;
            }

            if ((ext == ".dll" || ext == ".asi") && ContainsCheatKeyword(fnLower))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspicious library in FiveM cache: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Reason = $"Library '{fn}' in the FiveM cache directory has a name associated with " +
                             "cheat software. Cheat injectors sometimes place their libraries here " +
                             "to survive cache clears.",
                    Detail = $"Path: {file}"
                });
            }
        }

        CheckScriptHookInWrongLocation(ctx, ct, cacheRoot);
    }

    private void CheckScriptHookInWrongLocation(ScanContext ctx, CancellationToken ct, string cacheRoot)
    {
        var pluginsRoot = Path.Combine(LocalApp, @"FiveM\FiveM.app\plugins");

        foreach (var suspect in SuspiciousDllsInWrongDir)
        {
            if (ct.IsCancellationRequested) return;

            var cachePath = Path.Combine(cacheRoot, suspect);
            if (File.Exists(cachePath))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Proxy/hook DLL in FiveM cache: {suspect}",
                    Risk = RiskLevel.Critical,
                    Location = cachePath,
                    FileName = suspect,
                    Reason = $"'{suspect}' found in FiveM cache directory. This DLL is commonly used as a " +
                             "proxy or hijack DLL to load cheat code at startup. Its presence in the cache " +
                             "directory is anomalous and indicates deliberate placement by a cheat tool.",
                    Detail = $"Path: {cachePath}"
                });
            }

            if (!Directory.Exists(pluginsRoot)) continue;

            var pluginPath = Path.Combine(pluginsRoot, suspect);
            if (File.Exists(pluginPath))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Proxy/hook DLL in FiveM plugins: {suspect}",
                    Risk = RiskLevel.Critical,
                    Location = pluginPath,
                    FileName = suspect,
                    Reason = $"'{suspect}' found in FiveM plugins directory. These DLL names are " +
                             "used by cheat menu loaders as proxy DLLs that intercept DirectInput " +
                             "or Windows version API calls to inject cheat code.",
                    Detail = $"Path: {pluginPath}"
                });
            }
        }
    }

    private void ScanForMisplacedSystemDlls(ScanContext ctx, CancellationToken ct)
    {
        var appDirs = new[]
        {
            Path.Combine(LocalApp, "FiveM"),
            Path.Combine(AppData, "CitizenFX"),
        };

        foreach (var root in appDirs)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            IEnumerable<string> dllFiles;
            try
            {
                dllFiles = Directory.EnumerateFiles(root, "*.dll", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in dllFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fn = Path.GetFileName(file);
                if (!SuspiciousDllsInWrongDir.Contains(fn)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"System DLL in FiveM app root: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Reason = $"'{fn}' found in the FiveM application root directory. This system DLL " +
                             "name is frequently hijacked by cheat loaders: the cheat places its own " +
                             "version here so Windows loads it instead of the legitimate system copy, " +
                             "enabling code injection without an explicit injector.",
                    Detail = $"Path: {file}"
                });
            }
        }
    }

    private void ScanForBrowserLogBypass(ScanContext ctx, CancellationToken ct)
    {
        var expectedLogPaths = new[]
        {
            Path.Combine(AppData, @"CitizenFX\CitizenFX.log"),
            Path.Combine(LocalApp, @"FiveM\FiveM.app\data\CitizenFX.log"),
        };

        var suspectLogLocations = new[]
        {
            Path.Combine(LocalApp, "FiveM", "CitizenFX.log"),
            Path.Combine(LocalApp, "CitizenFX.log"),
            Path.Combine(AppData, "CitizenFX.log"),
        };

        foreach (var logPath in suspectLogLocations)
        {
            if (ct.IsCancellationRequested) return;

            if (!File.Exists(logPath)) continue;

            bool isExpected = expectedLogPaths.Any(e =>
                logPath.Equals(e, StringComparison.OrdinalIgnoreCase));

            if (!isExpected)
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "CitizenFX log in unexpected location",
                    Risk = RiskLevel.Medium,
                    Location = logPath,
                    FileName = Path.GetFileName(logPath),
                    Reason = $"CitizenFX.log found at '{logPath}', which is not the standard location. " +
                             "Some FiveM bypass tools redirect or duplicate the log to intercept " +
                             "integrity check data. This may indicate tampering with the logging pathway.",
                    Detail = $"Expected: {string.Join(" or ", expectedLogPaths)}"
                });
            }
        }

        CheckCitizenGameTampering(ctx, ct);
        CheckEacInstall(ctx, ct);
    }

    private static void CheckCitizenGameTampering(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var citizenGamePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"FiveM\FiveM.app\citizen\game");

        if (!Directory.Exists(citizenGamePath)) return;

        var suspectFiles = new[]
        {
            "citizen_game_bypass.dll", "citizen_game_patch.dll",
            "citizen_game_hook.dll", "integrity_bypass.dll",
            "hash_bypass.dll", "eac_patch.dll",
        };

        foreach (var suspect in suspectFiles)
        {
            if (ct.IsCancellationRequested) return;
            var fp = Path.Combine(citizenGamePath, suspect);
            if (!File.Exists(fp)) continue;

            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = "FiveM Cheat Menu Detection",
                Title = $"Citizen game bypass DLL: {suspect}",
                Risk = RiskLevel.Critical,
                Location = fp,
                FileName = suspect,
                Reason = $"'{suspect}' found in FiveM's citizen/game directory. This DLL name " +
                         "indicates deliberate patching of FiveM's game integrity or EAC verification code.",
                Detail = $"Path: {fp}"
            });
        }

        IEnumerable<string> dllFiles;
        try
        {
            dllFiles = Directory.EnumerateFiles(citizenGamePath, "*.dll", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }

        foreach (var dll in dllFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fn = Path.GetFileName(dll);
            var fnLower = fn.ToLowerInvariant();

            if (fnLower.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                fnLower.Contains("patch", StringComparison.OrdinalIgnoreCase) ||
                fnLower.Contains("hook", StringComparison.OrdinalIgnoreCase) ||
                fnLower.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                fnLower.Contains("hack", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = "FiveM Cheat Menu Detection",
                    Title = $"Suspicious DLL in citizen/game: {fn}",
                    Risk = RiskLevel.Critical,
                    Location = dll,
                    FileName = fn,
                    Reason = $"DLL '{fn}' in FiveM's citizen/game directory has a name associated with " +
                             "game patching, hooking or bypass tools. This directory contains core " +
                             "FiveM game binaries — unexpected DLLs here indicate injection.",
                    Detail = $"Path: {dll}"
                });
            }
        }
    }

    private static void CheckEacInstall(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var fivemEacPath = Path.Combine(localApp, @"FiveM\FiveM.app\data\EasyAntiCheat");

        if (!Directory.Exists(fivemEacPath))
        {
            var fivemRoot = Path.Combine(localApp, "FiveM");
            if (!Directory.Exists(fivemRoot)) return;

            ctx.AddFinding(new Finding
            {
                Module = "FiveM Cheat Menu Detection",
                Title = "EasyAntiCheat directory missing from FiveM",
                Risk = RiskLevel.High,
                Location = fivemEacPath,
                FileName = "EasyAntiCheat",
                Reason = "The EasyAntiCheat directory is absent from the FiveM data folder. " +
                         "FiveM servers that use EAC require this directory. Its absence may indicate " +
                         "that it was removed by a bypass tool to prevent anti-cheat initialisation.",
                Detail = $"Expected path: {fivemEacPath}"
            });
            return;
        }

        var eacExe = Path.Combine(fivemEacPath, "EasyAntiCheat.exe");
        var eacDll = Path.Combine(fivemEacPath, "EasyAntiCheat.dll");

        if (!File.Exists(eacExe) && !File.Exists(eacDll))
        {
            ctx.AddFinding(new Finding
            {
                Module = "FiveM Cheat Menu Detection",
                Title = "EasyAntiCheat binaries missing from FiveM EAC directory",
                Risk = RiskLevel.High,
                Location = fivemEacPath,
                FileName = "EasyAntiCheat.exe",
                Reason = "The FiveM EasyAntiCheat directory exists but contains no EAC executable or DLL. " +
                         "Bypass tools may delete or replace these binaries to prevent EAC from loading.",
                Detail = $"EAC directory: {fivemEacPath}"
            });
        }
    }

    private void CheckRegistryBypassArtifacts(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var suspectValueNames = new[]
        {
            "FiveMBypass", "CitizenFXBypass", "CFXBypass", "EACBypass",
            "FiveMCheat", "FiveMHack", "LuaExecutor", "FiveMInjector",
        };

        var registryPaths = new[]
        {
            @"SOFTWARE\FiveM",
            @"SOFTWARE\CitizenFX",
            @"SOFTWARE\CFX",
            @"SOFTWARE\FiveMBypass",
        };

        using var hkcu = Registry.CurrentUser;
        using var hklm = Registry.LocalMachine;

        foreach (var regPath in registryPaths)
        {
            if (ct.IsCancellationRequested) return;

            foreach (var hive in new[] { hkcu, hklm })
            {
                RegistryKey? key = null;
                try { key = hive.OpenSubKey(regPath, writable: false); }
                catch (Exception) { }

                if (key == null) continue;

                using (key)
                {
                    ctx.IncrementRegistryKeys();

                    foreach (var valueName in key.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;

                        foreach (var suspect in suspectValueNames)
                        {
                            if (valueName.Contains(suspect, StringComparison.OrdinalIgnoreCase))
                            {
                                var val = key.GetValue(valueName)?.ToString() ?? "";
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"FiveM bypass registry value: {valueName}",
                                    Risk = RiskLevel.High,
                                    Location = $@"{(hive == hkcu ? "HKCU" : "HKLM")}\{regPath}\{valueName}",
                                    FileName = null,
                                    Reason = $"Registry value '{valueName}' under '{regPath}' contains keywords " +
                                             "associated with FiveM cheat or bypass configuration.",
                                    Detail = $"Value: {(val.Length > 200 ? val[..200] + "..." : val)}"
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        ScanUninstallKeysForFiveMCheats(ctx, ct);
    }

    private static void ScanUninstallKeysForFiveMCheats(ScanContext ctx, CancellationToken ct)
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        var cheatProductKeywords = new[]
        {
            "eulen", "impulse", "cherax", "kiddions", "2take1", "orbital",
            "stand menu", "fivem cheat", "fivem hack", "fivem bypass",
            "lua executor", "fivem injector", "citizenfx bypass",
        };

        using var hkcu = Registry.CurrentUser;
        using var hklm = Registry.LocalMachine;

        foreach (var path in uninstallPaths)
        {
            if (ct.IsCancellationRequested) return;

            foreach (var hive in new[] { hkcu, hklm })
            {
                RegistryKey? root = null;
                try { root = hive.OpenSubKey(path, writable: false); }
                catch (Exception) { }

                if (root == null) continue;

                using (root)
                {
                    foreach (var subKeyName in root.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        RegistryKey? sub = null;
                        try { sub = root.OpenSubKey(subKeyName, writable: false); }
                        catch (Exception) { }

                        if (sub == null) continue;

                        using (sub)
                        {
                            var displayName = sub.GetValue("DisplayName")?.ToString() ?? "";
                            var publisher = sub.GetValue("Publisher")?.ToString() ?? "";
                            var installLocation = sub.GetValue("InstallLocation")?.ToString() ?? "";

                            var combined = $"{displayName} {publisher} {installLocation}";

                            foreach (var kw in cheatProductKeywords)
                            {
                                if (combined.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "FiveM Cheat Menu Detection",
                                        Title = $"FiveM cheat software in Uninstall registry: {displayName}",
                                        Risk = RiskLevel.Critical,
                                        Location = $@"{(hive == hkcu ? "HKCU" : "HKLM")}\{path}\{subKeyName}",
                                        FileName = null,
                                        Reason = $"Uninstall registry entry '{displayName}' matches known FiveM " +
                                                 $"cheat software keyword '{kw}'. This indicates the software " +
                                                 "was formally installed on this system.",
                                        Detail = $"Publisher: {publisher} | InstallLocation: {installLocation}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private static bool ContainsCheatKeyword(string nameLower)
    {
        if (nameLower.Contains("cheat", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("hack", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("inject", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("exploit", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("aimbot", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("wallhack", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("godmode", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("god_mode", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("noclip", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("no_clip", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("spinbot", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("speedhack", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("teleport", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("executor", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("modmenu", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("mod_menu", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("trainer", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("eulen", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("impulse", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("cherax", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("kiddion", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("2take1", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("orbital", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("tsunami", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("ozark", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("vanity", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("modest", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("midnight", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("lua_exec", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("lua_runner", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("lua_inject", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("script_hook", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("scripthook", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("asi_load", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("asi_inject", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("cfx_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("citizen_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("eac_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("anticheat_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("recovery_tool", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("money_drop", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("money_loop", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("vehicle_spawn", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("weapon_give", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("crash_player", StringComparison.OrdinalIgnoreCase)) return true;
        if (nameLower.Contains("kick_player", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }
}
