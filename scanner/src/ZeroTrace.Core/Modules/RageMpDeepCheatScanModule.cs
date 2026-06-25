using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class RageMpDeepCheatScanModule : IScanModule
{
    public string Name => "RAGE Multiplayer Cheat Detection";
    public double Weight => 4.3;
    public int ParallelGroup => 4;

    private static readonly string LocalApp = Environment.GetFolderPath(
        Environment.SpecialFolder.LocalApplicationData);
    private static readonly string AppData = Environment.GetFolderPath(
        Environment.SpecialFolder.ApplicationData);

    private static readonly string[] RageMpRootPaths =
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RAGEMP"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RAGEMP"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ragemp"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RAGE-MP"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "rage-mp"),
    };

    private static readonly HashSet<string> CheatExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "ragemp_cheat.exe", "ragemp_hack.exe", "ragemp_menu.exe", "ragemp_bypass.exe",
        "ragemp_injector.exe", "ragemp_script.exe", "ragemp_resource.exe",
        "ragemp_exploit.exe", "ragemphack.exe", "ragempcheat.exe", "ragempmenu.exe",
        "ragempbypass.exe", "ragemp_lua.exe", "ragemp_js.exe", "ragemp_cef.exe",
        "ragemp_cef_bypass.exe", "ragemp_server_bypass.exe", "ragemp_client_bypass.exe",
        "ragemp_rage_bypass.exe", "ragemp_hash_bypass.exe", "ragemp_integrity_bypass.exe",
        "ragemp_esp.exe", "ragemp_aimbot.exe", "ragemp_godmode.exe", "ragemp_noclip.exe",
        "ragemp_speedhack.exe", "ragemp_teleport.exe", "ragemp_vehicle.exe",
        "ragemp_weapon.exe", "ragemp_money.exe", "ragemp_freeze.exe", "ragemp_kick.exe",
        "ragemp_crash.exe", "rage_bypass.exe", "rage_cheat.exe", "rage_hack.exe",
        "rage_menu.exe", "rage_injector.exe", "ragecheat.exe", "ragehack.exe",
        "ragemenu.exe", "rageinjector.exe", "ragebypass.exe", "rage_mp_bypass.exe",
        "rage_mp_cheat.exe", "rage_mp_hack.exe", "ragemploader.exe",
        "ragemp_loader.exe", "ragemp_launcher_bypass.exe", "ragemp_patch.exe",
        "ragemp_patcher.exe", "ragemp_cef_exploit.exe", "ragemp_cef_hack.exe",
        "ragemp_js_inject.exe", "ragemp_js_bypass.exe", "ragemp_event_bypass.exe",
        "ragemp_sync_bypass.exe", "ragemp_bridge_bypass.exe",
        "bridge_bypass.exe", "rage_hook_bypass.exe",
    };

    private static readonly HashSet<string> CheatDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "ragemp_cheat.dll", "ragemp_hack.dll", "ragemp_menu.dll", "ragemp_bypass.dll",
        "ragemp_injector.dll", "ragemp_script.dll", "ragemp_resource.dll",
        "ragemp_exploit.dll", "ragemphack.dll", "ragempcheat.dll", "ragempmenu.dll",
        "ragempbypass.dll", "ragemp_esp.dll", "ragemp_aimbot.dll",
        "ragemp_godmode.dll", "ragemp_noclip.dll", "ragemp_speedhack.dll",
        "ragemp_teleport.dll", "ragemp_cef_bypass.dll", "ragemp_server_bypass.dll",
        "ragemp_client_bypass.dll", "ragemp_hash_bypass.dll",
        "ragemp_integrity_bypass.dll", "ragemp_event_bypass.dll",
        "ragemp_sync_bypass.dll", "ragemp_bridge_bypass.dll",
        "rage_bypass.dll", "rage_cheat.dll", "rage_hook.dll",
        "ragecheat.dll", "ragehack.dll", "bridge_bypass.dll",
    };

    private static readonly HashSet<string> RageHookExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        "RageHook.dll", "RageHookPlugin.dll", "RagePluginHook.dll",
        "RAGEPluginHook.dll", "RAGE.Hook.dll", "rage_hook.dll",
        "RageHook_bypass.dll", "RageHook_cheat.dll", "RageHook_patch.dll",
    };

    private static readonly HashSet<string> BridgeDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Bridge.dll", "bridge.dll", "RageBridge.dll", "rage_bridge.dll",
        "RageMPBridge.dll", "ragemp_bridge.dll",
    };

    private static readonly HashSet<string> SuspiciousProxyDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "dinput8.dll", "version.dll", "dsound.dll", "winmm.dll",
        "d3d9.dll", "d3d11.dll", "bink2w64.dll", "msacm32.dll", "dxgi.dll",
    };

    private static readonly string[] JavaScriptCefCheatPatterns =
    {
        "mp.events.add(", "mp.events.addCommand(",
        "mp.players.forEach(", "mp.vehicles.forEach(",
        "mp.game.invoke(", "mp.game.ui.",
        "invokeNative(", "native.invoke(",
        "NETWORK_RESURRECT_LOCAL_PLAYER", "SET_ENTITY_INVINCIBLE",
        "SET_ENTITY_COORDS", "SET_PED_MAX_SPEED", "ADD_EXPLOSION",
        "GIVE_WEAPON_TO_PED", "SET_PLAYER_WANTED_LEVEL",
        "SET_ENTITY_HEALTH", "TASK_LEAVE_ANY_CAR",
        "DELETE_ENTITY", "REMOVE_ALL_PED_WEAPONS",
        "mp.game.ped.setArmour(", "mp.game.entity.setCoords(",
        "bypass", "anticheat_bypass", "aimbot", "wallhack",
        "godmode", "noclip", "speedhack", "spinbot",
        "eval(atob(", "eval(Buffer.from(", "Function('return ",
        "require('child_process')", "require(\"child_process\")",
        "window.location.href = 'asset://'",
        "cef.execute(", "mp.browsers.new(",
    };

    private static readonly string[] CSharpPluginCheatPatterns =
    {
        "RAGE.Game.Invoke", "RAGE.Elements.Player",
        "RAGE.Game.Entity.SetCoords", "RAGE.Game.Entity.SetInvincible",
        "InvokeNative", "NativeFunction.Call(",
        "SetEntityInvincible", "SetEntityCoords",
        "NetworkResurrectLocalPlayer", "AddExplosion",
        "GiveWeaponToPed", "SetPlayerWantedLevel",
        "SetPedMaxSpeed", "DeleteEntity", "RemoveAllPedWeapons",
        "bypass", "anticheat", "inject", "hook",
        "Marshal.GetDelegateForFunctionPointer",
        "VirtualAlloc", "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "OpenProcess",
        "Assembly.Load(", "Assembly.LoadFrom(",
        "RuntimeImport", "DllImport", "PInvoke",
    };

    private static readonly string[] CheatConfigKeywords =
    {
        "ragemp_god", "ragemp_noclip", "ragemp_tp", "ragemp_speed",
        "ragemp_spawn", "ragemp_weapon", "ragemp_kick", "ragemp_freeze",
        "ragemp_crash", "ragemp_invisible", "ragemp_admin",
        "ragemp_bypass_anticheat", "ragemp_exploit", "ragemp_cef_exploit",
        "ragemp_js_inject", "ragemp_event_bypass", "ragemp_sync_bypass",
        "ragemp_hash_bypass", "ragemp_integrity_bypass",
        "ragemp_bridge_bypass", "ragemp_aimbot", "ragemp_esp",
        "ragemp_wallhack", "ragemp_speedhack", "ragemp_godmode",
        "ragemp_money_drop", "ragemp_vehicle_spawn", "ragemp_weapon_give",
        "ragemp_kick_player", "ragemp_crash_player", "ragemp_freeze_player",
        "ragemp_teleport", "ragemp_spinbot", "ragemp_bunnyhop",
        "godmode_enabled", "noclip_enabled", "speedhack_enabled",
        "aimbot_enabled", "esp_enabled", "bypass_enabled",
        "cheat_mode", "hack_mode", "exploit_mode", "bypass_mode",
        "rage_game_invoke", "cef_exploit", "js_inject",
        "bridge_bypass", "sync_bypass", "event_bypass",
        "hash_bypass", "integrity_bypass", "anticheat_bypass",
    };

    private static readonly string[] ClientPackageCheatPatterns =
    {
        "rage_game_invoke", "invokeNative", "mp.game.invoke",
        "mp.events.addCommand", "bypass", "cheat", "hack",
        "aimbot", "wallhack", "godmode", "noclip", "spinbot",
        "speedhack", "teleport_coords", "money_drop",
        "vehicle_spawn_hack", "weapon_give_hack", "kick_player",
        "crash_player", "freeze_player", "invisible_player",
        "admin_bypass", "anticheat_bypass",
        "eval(atob(", "eval(Buffer.from(",
        "require('child_process')", "require(\"child_process\")",
        "process.env.", "window.location.href",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting RAGE Multiplayer cheat scan...");

        bool rageMpInstalled = RageMpRootPaths.Any(Directory.Exists);
        if (!rageMpInstalled)
        {
            ctx.Report(1.0, Name, "RAGE Multiplayer installation not found; skipping.");
            return;
        }

        ctx.Report(0.05, Name, "RAGE Multiplayer installation found; scanning...");

        await Task.Run(() =>
        {
            double step = 0.05;

            ScanForCheatExecutables(ctx, ct);
            step += 0.12;
            ctx.Report(step, Name, "Executable scan complete.");

            ScanForCheatDlls(ctx, ct);
            step += 0.12;
            ctx.Report(step, Name, "DLL scan complete.");

            ScanForRageHookBypass(ctx, ct);
            step += 0.07;
            ctx.Report(step, Name, "RageHook bypass check complete.");

            ScanForBridgeDllReplacement(ctx, ct);
            step += 0.07;
            ctx.Report(step, Name, "Bridge.dll replacement check complete.");

            ScanForProxyDlls(ctx, ct);
            step += 0.07;
            ctx.Report(step, Name, "Proxy DLL scan complete.");

            ScanClientPackages(ctx, ct);
            step += 0.13;
            ctx.Report(step, Name, "Client packages JavaScript scan complete.");

            ScanCSharpPlugins(ctx, ct);
            step += 0.13;
            ctx.Report(step, Name, "C# plugin scan complete.");

            ScanForCefExploitArtifacts(ctx, ct);
            step += 0.08;
            ctx.Report(step, Name, "CEF exploit scan complete.");

            ScanForCheatConfigs(ctx, ct);
            step += 0.10;
            ctx.Report(step, Name, "Config keyword scan complete.");

            CheckRageMpExeIntegrity(ctx, ct);
            step += 0.05;
            ctx.Report(step, Name, "Executable integrity check complete.");

            CheckRegistryArtifacts(ctx, ct);

            ctx.Report(1.0, Name, "RAGE Multiplayer cheat scan complete.");
        }, ct);
    }

    private void ScanForCheatExecutables(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in RageMpRootPaths)
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
                        Title = $"RageMP Cheat EXE: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known RAGE Multiplayer cheat executable '{fn}' found in the RageMP directory " +
                                 "tree. This file is a recognised cheat menu, injector or bypass tool " +
                                 "targeting the RAGE Multiplayer GTA V platform.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                if (IsRageMpCheatName(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious EXE in RageMP directory: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Executable '{fn}' in the RageMP directory tree has a name containing " +
                                 "cheat-associated keywords. Not a recognised legitimate RageMP component.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
    }

    private void ScanForCheatDlls(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in RageMpRootPaths)
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
                        Title = $"RageMP Cheat DLL: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known RAGE Multiplayer cheat DLL '{fn}' found. This library is injected " +
                                 "into the RageMP client process to enable god mode, ESP, aimbot, teleportation, " +
                                 "event bypass or anti-cheat circumvention.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                if (IsRageMpCheatName(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious DLL in RageMP directory: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"DLL '{fn}' in the RageMP directory tree has a cheat-associated name. " +
                                 "Cheat DLLs are loaded via injection or DLL hijacking into the RageMP " +
                                 "client process (ragemp.exe / ragemp_v.exe).",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
    }

    private void ScanForRageHookBypass(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in RageMpRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            IEnumerable<string> dllFiles;
            try
            {
                dllFiles = Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in dllFiles)
            {
                if (ct.IsCancellationRequested) return;

                var fn = Path.GetFileName(file);

                if (!RageHookExtensions.Contains(fn)) continue;

                ctx.IncrementFiles();

                bool signed = false;
                try
                {
                    System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(file);
                    signed = true;
                }
                catch { }

                if (!signed)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Unsigned RageHook DLL: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Unsigned RageHook plugin DLL '{fn}' found. Legitimate RagePluginHook " +
                                 "is signed by its vendor. Unsigned copies indicate a cheat-extended or " +
                                 "replaced version that exposes game internals (rage::game::invoke) to " +
                                 "cheat plugins loaded via the RPH plugin system.",
                        Detail = $"Path: {file} | Signed: No"
                    });
                    continue;
                }

                AnalyzeDllForCheatContent(ctx, file, fn, RageHookExtensions, ct);
            }
        }

        ScanForRageHookPlugins(ctx, ct);
    }

    private static void ScanForRageHookPlugins(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var rphPluginDirs = new[]
        {
            Path.Combine(localApp, @"RAGEMP\plugins"),
            Path.Combine(localApp, @"RAGEMP\dotnet\plugins"),
            Path.Combine(localApp, @"RAGEMP\RagePluginHook\plugins"),
        };

        var cheatPluginKeywords = new[]
        {
            "cheat", "hack", "bypass", "exploit", "aimbot", "wallhack",
            "godmode", "noclip", "speedhack", "esp", "spinbot",
            "teleport", "money", "inject", "menu", "trainer",
        };

        foreach (var pluginDir in rphPluginDirs)
        {
            if (!Directory.Exists(pluginDir)) continue;
            if (ct.IsCancellationRequested) return;

            IEnumerable<string> pluginFiles;
            try
            {
                pluginFiles = Directory.EnumerateFiles(pluginDir, "*.dll", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var dll in pluginFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fn = Path.GetFileName(dll).ToLowerInvariant();

                foreach (var kw in cheatPluginKeywords)
                {
                    if (fn.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "RAGE Multiplayer Cheat Detection",
                            Title = $"Suspicious RageHook plugin: {Path.GetFileName(dll)}",
                            Risk = RiskLevel.High,
                            Location = dll,
                            FileName = Path.GetFileName(dll),
                            Reason = $"RagePluginHook plugin '{Path.GetFileName(dll)}' has a name containing " +
                                     $"the cheat keyword '{kw}'. RPH plugins run with full RAGE engine access " +
                                     "and can invoke game::invoke to manipulate game state.",
                            Detail = $"Plugin directory: {pluginDir} | Keyword: {kw}"
                        });
                        break;
                    }
                }
            }
        }
    }

    private void ScanForBridgeDllReplacement(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in RageMpRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            foreach (var bridgeDll in BridgeDllNames)
            {
                if (ct.IsCancellationRequested) return;

                IEnumerable<string> found;
                try
                {
                    found = Directory.EnumerateFiles(root, bridgeDll, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in found)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    bool signed = false;
                    try
                    {
                        System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(file);
                        signed = true;
                    }
                    catch { }

                    if (!signed)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Unsigned Bridge.dll in RageMP: {bridgeDll}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = bridgeDll,
                            Reason = $"The RageMP Bridge DLL '{bridgeDll}' is unsigned. This DLL bridges " +
                                     "the C# managed layer to the native RAGE engine. Cheat tools replace it " +
                                     "to intercept all native calls, enabling god mode, ESP, aimbot and other " +
                                     "cheats by manipulating the bridge before calls reach the anti-cheat.",
                            Detail = $"Path: {file} | Signed: No"
                        });
                        continue;
                    }

                    FileInfo fi;
                    try { fi = new FileInfo(file); }
                    catch (IOException) { continue; }

                    var daysSinceWrite = (DateTime.UtcNow - fi.LastWriteTimeUtc).TotalDays;
                    if (daysSinceWrite >= 1) continue;

                    var rageMpExe = Path.Combine(root, "ragemp.exe");
                    var rageMpVExe = Path.Combine(root, "ragemp_v.exe");
                    bool launcherModified =
                        (File.Exists(rageMpExe) && (DateTime.UtcNow - new FileInfo(rageMpExe).LastWriteTimeUtc).TotalDays < 1) ||
                        (File.Exists(rageMpVExe) && (DateTime.UtcNow - new FileInfo(rageMpVExe).LastWriteTimeUtc).TotalDays < 1);

                    if (!launcherModified)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP Bridge.dll modified without launcher update: {bridgeDll}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = bridgeDll,
                            Reason = $"RageMP Bridge DLL '{bridgeDll}' was modified in the last 24 hours but " +
                                     "the RageMP launcher executables were not updated. Isolated modification " +
                                     "of Bridge.dll without a corresponding launcher update is characteristic " +
                                     "of a targeted Bridge.dll replacement attack.",
                            Detail = $"DLL last written: {fi.LastWriteTimeUtc:yyyy-MM-dd HH:mm} UTC"
                        });
                    }
                }
            }
        }
    }

    private void ScanForProxyDlls(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in RageMpRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            foreach (var proxyDll in SuspiciousProxyDlls)
            {
                if (ct.IsCancellationRequested) return;

                var proxyPath = Path.Combine(root, proxyDll);
                if (!File.Exists(proxyPath)) continue;

                ctx.IncrementFiles();

                bool signed = false;
                try
                {
                    System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(proxyPath);
                    signed = true;
                }
                catch { }

                if (!signed)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Unsigned proxy DLL in RageMP root: {proxyDll}",
                        Risk = RiskLevel.Critical,
                        Location = proxyPath,
                        FileName = proxyDll,
                        Reason = $"Unsigned '{proxyDll}' found in the RageMP installation root. " +
                                 "This Windows system DLL name is frequently hijacked by cheat loaders: " +
                                 "placing a custom version here causes the OS to load it instead of the " +
                                 "legitimate system copy, injecting cheat code at game startup.",
                        Detail = $"Path: {proxyPath} | Signed: No"
                    });
                }
            }
        }
    }

    private void ScanClientPackages(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in RageMpRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            var clientPkgDirs = new[]
            {
                Path.Combine(root, "client_packages"),
                Path.Combine(root, "packages"),
                Path.Combine(root, "data", "client_packages"),
            };

            foreach (var pkgDir in clientPkgDirs)
            {
                if (!Directory.Exists(pkgDir)) continue;
                if (ct.IsCancellationRequested) return;

                ScanJsFilesInDirectory(ctx, ct, pkgDir, "client_packages");
            }
        }
    }

    private void ScanJsFilesInDirectory(ScanContext ctx, CancellationToken ct,
        string dir, string context)
    {
        IEnumerable<string> jsFiles;
        try
        {
            jsFiles = Directory.EnumerateFiles(dir, "*.js", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach (var file in jsFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var fn = Path.GetFileName(file);
            var fnLower = fn.ToLowerInvariant();

            if (IsRageMpCheatName(fnLower))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspicious JS file in {context}: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Reason = $"JavaScript file '{fn}' in RageMP {context} directory has a name containing " +
                             "cheat-associated keywords. RageMP loads these JS packages in the game client context.",
                    Detail = $"Path: {file}"
                });
                continue;
            }

            FileInfo fi;
            try { fi = new FileInfo(file); }
            catch (IOException) { continue; }

            if (fi.Length > 2 * 1024 * 1024) continue;

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

            AnalyzeJsContent(ctx, file, fn, content, context);
        }
    }

    private void AnalyzeJsContent(ScanContext ctx, string file, string fn, string content, string context)
    {
        var hits = new List<string>();
        foreach (var pattern in JavaScriptCefCheatPatterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                hits.Add(pattern);
            if (hits.Count >= 8) break;
        }

        foreach (var pattern in ClientPackageCheatPatterns)
        {
            if (!hits.Contains(pattern) &&
                content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                hits.Add(pattern);
            if (hits.Count >= 10) break;
        }

        if (hits.Count == 0) return;

        bool hasObfuscation = content.Contains("eval(atob(", StringComparison.OrdinalIgnoreCase)
                           || content.Contains("eval(Buffer.from(", StringComparison.OrdinalIgnoreCase)
                           || content.Contains("Function('return ", StringComparison.OrdinalIgnoreCase);

        var risk = hits.Count >= 5 ? RiskLevel.Critical
                 : hits.Count >= 3 ? RiskLevel.High
                 : hits.Count >= 2 ? RiskLevel.Medium
                 : RiskLevel.Low;

        if (hasObfuscation && risk < RiskLevel.High) risk = RiskLevel.High;

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"Cheat patterns in RageMP JS {context}: {fn}",
            Risk = risk,
            Location = file,
            FileName = fn,
            Reason = $"RageMP JavaScript file '{fn}' in {context} contains {hits.Count} cheat-characteristic " +
                     $"pattern(s): {string.Join(", ", hits.Take(4).Select(h => $"'{h}'"))}. " +
                     "These patterns indicate mp.game.invoke abuse, CEF exploit code, eval-based obfuscated " +
                     "injection or anti-cheat bypass targeting the RAGE engine.",
            Detail = $"Matched ({hits.Count}): {string.Join(", ", hits.Take(6))}" +
                     (hasObfuscation ? " | Obfuscation detected" : "")
        });
    }

    private void ScanCSharpPlugins(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in RageMpRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            var pluginSearchDirs = new[]
            {
                Path.Combine(root, "plugins"),
                Path.Combine(root, "dotnet", "plugins"),
                Path.Combine(root, "dotnet"),
                Path.Combine(root, "csmodule"),
            };

            foreach (var pluginDir in pluginSearchDirs)
            {
                if (!Directory.Exists(pluginDir)) continue;
                if (ct.IsCancellationRequested) return;

                IEnumerable<string> dllFiles;
                try
                {
                    dllFiles = Directory.EnumerateFiles(pluginDir, "*.dll", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var dll in dllFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(dll);

                    if (IsRageMpCheatName(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious C# plugin DLL in RageMP: {fn}",
                            Risk = RiskLevel.High,
                            Location = dll,
                            FileName = fn,
                            Reason = $"RageMP C# plugin DLL '{fn}' has a cheat-associated name. RageMP " +
                                     "auto-loads .NET assemblies from the plugins directory. Cheat assemblies " +
                                     "here can access RAGE.Game.Invoke with full native game API access.",
                            Detail = $"Path: {dll}"
                        });
                        continue;
                    }

                    AnalyzeDllForCheatContent(ctx, dll, fn, null, ct);
                }
            }
        }
    }

    private void AnalyzeDllForCheatContent(ScanContext ctx, string file, string fn,
        HashSet<string>? skipSet, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        if (skipSet != null && skipSet.Contains(fn)) return;

        FileInfo fi;
        try { fi = new FileInfo(file); }
        catch (IOException) { return; }

        if (fi.Length > 10 * 1024 * 1024) return;

        string content;
        try
        {
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs, System.Text.Encoding.Latin1);
            content = sr.ReadToEnd();
        }
        catch (IOException)
        {
            return;
        }

        var hits = new List<string>();
        foreach (var pattern in CSharpPluginCheatPatterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                hits.Add(pattern);
            if (hits.Count >= 6) break;
        }

        if (hits.Count < 2) return;

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"Cheat strings in RageMP C# assembly: {fn}",
            Risk = hits.Count >= 4 ? RiskLevel.Critical : RiskLevel.High,
            Location = file,
            FileName = fn,
            Reason = $"RageMP C# assembly '{fn}' contains {hits.Count} strings characteristic of cheat code: " +
                     $"{string.Join(", ", hits.Take(4).Select(h => $"'{h}'"))}. " +
                     "These include RAGE.Game.Invoke patterns, process memory access imports or dynamic " +
                     "assembly loading used by cheat modules.",
            Detail = $"Matched patterns ({hits.Count}): {string.Join(", ", hits.Take(6))}"
        });
    }

    private void ScanForCefExploitArtifacts(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in RageMpRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            var cefDirs = new[]
            {
                Path.Combine(root, "cef"),
                Path.Combine(root, "data", "cef"),
                Path.Combine(root, "ui"),
                Path.Combine(root, "data", "ui"),
            };

            foreach (var cefDir in cefDirs)
            {
                if (!Directory.Exists(cefDir)) continue;
                if (ct.IsCancellationRequested) return;

                ScanHtmlFilesForCheat(ctx, ct, cefDir);
                ScanJsFilesInDirectory(ctx, ct, cefDir, "CEF");
            }

            ScanForCefDllInjection(ctx, ct, root);
        }
    }

    private static void ScanHtmlFilesForCheat(ScanContext ctx, CancellationToken ct, string dir)
    {
        IEnumerable<string> htmlFiles;
        try
        {
            htmlFiles = Directory.EnumerateFiles(dir, "*.html", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        var htmlCheatPatterns = new[]
        {
            "<script>mp.game.invoke(", "cef.execute(", "window.mp =",
            "invokeNative(", "bypass_anticheat", "cheat_enabled",
            "eval(atob(", "eval(Buffer.from(",
            "<script src=\"http://", "<script src=\"https://", "fetch('http",
            "XMLHttpRequest", "window.location.href = 'asset://'",
        };

        foreach (var file in htmlFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            FileInfo fi;
            try { fi = new FileInfo(file); }
            catch (IOException) { continue; }

            if (fi.Length > 1024 * 1024) continue;

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
            foreach (var p in htmlCheatPatterns)
            {
                if (content.Contains(p, StringComparison.OrdinalIgnoreCase))
                    hits.Add(p);
                if (hits.Count >= 4) break;
            }

            if (hits.Count == 0) continue;

            ctx.AddFinding(new Finding
            {
                Module = "RAGE Multiplayer Cheat Detection",
                Title = $"CEF HTML file with cheat patterns: {Path.GetFileName(file)}",
                Risk = hits.Count >= 3 ? RiskLevel.Critical : RiskLevel.High,
                Location = file,
                FileName = Path.GetFileName(file),
                Reason = $"RageMP CEF HTML file '{Path.GetFileName(file)}' contains {hits.Count} patterns " +
                         $"indicating CEF exploit code: {string.Join(", ", hits.Take(3).Select(h => $"'{h}'"))}. " +
                         "RageMP CEF pages can call back into the game engine; malicious HTML can be used " +
                         "for UI injection attacks to trigger native game calls.",
                Detail = $"Matched ({hits.Count}): {string.Join(", ", hits)}"
            });
        }
    }

    private static void ScanForCefDllInjection(ScanContext ctx, CancellationToken ct, string root)
    {
        if (ct.IsCancellationRequested) return;

        var cefBinaries = new[]
        {
            "libcef.dll", "cef.dll", "cef_sandbox.lib",
            "chrome_elf.dll", "d3dcompiler_47.dll",
        };

        foreach (var cefBin in cefBinaries)
        {
            var cefPath = Path.Combine(root, cefBin);
            if (!File.Exists(cefPath)) continue;

            ctx.IncrementFiles();

            bool signed = false;
            try
            {
                System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(cefPath);
                signed = true;
            }
            catch { }

            if (!signed)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "RAGE Multiplayer Cheat Detection",
                    Title = $"Unsigned CEF binary in RageMP: {cefBin}",
                    Risk = RiskLevel.High,
                    Location = cefPath,
                    FileName = cefBin,
                    Reason = $"CEF binary '{cefBin}' in the RageMP directory is unsigned. Legitimate " +
                             "CEF binaries are signed by Google or the Chromium Embedded Framework team. " +
                             "An unsigned copy may have been modified to allow JavaScript calls into the " +
                             "RAGE game engine, enabling the CEF UI exploit attack vector.",
                    Detail = $"Path: {cefPath} | Signed: No"
                });
            }
        }
    }

    private void ScanForCheatConfigs(ScanContext ctx, CancellationToken ct)
    {
        var configExtensions = new[] { ".cfg", ".ini", ".json", ".txt", ".conf", ".yaml", ".yml" };

        foreach (var root in RageMpRootPaths)
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
                        Title = $"RageMP cheat config keywords: {Path.GetFileName(file)}",
                        Risk = risk,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Config file '{Path.GetFileName(file)}' contains {hits.Count} RageMP cheat-related " +
                                 $"keyword(s): {string.Join(", ", hits.Take(4).Select(h => $"'{h}'"))}. " +
                                 "These keywords are characteristic of RageMP cheat menu or bypass tool configuration.",
                        Detail = $"Matched keywords ({hits.Count}): {string.Join(", ", hits.Take(6))}"
                    });
                }
            }
        }
    }

    private static void CheckRageMpExeIntegrity(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var rageMpRoots = new[]
        {
            Path.Combine(localApp, "RAGEMP"),
            Path.Combine(localApp, "ragemp"),
            Path.Combine(localApp, "RAGE-MP"),
        };

        var coreExeNames = new[] { "ragemp.exe", "ragemp_v.exe", "updater.exe" };

        foreach (var root in rageMpRoots)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            foreach (var exeName in coreExeNames)
            {
                var exePath = Path.Combine(root, exeName);
                if (!File.Exists(exePath)) continue;

                ctx.IncrementFiles();

                bool signed = false;
                try
                {
                    System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(exePath);
                    signed = true;
                }
                catch { }

                if (!signed)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "RAGE Multiplayer Cheat Detection",
                        Title = $"Unsigned RageMP core executable: {exeName}",
                        Risk = RiskLevel.Critical,
                        Location = exePath,
                        FileName = exeName,
                        Reason = $"The core RageMP executable '{exeName}' is not digitally signed. " +
                                 "Legitimate RageMP executables are always signed by RAGE Multiplayer. " +
                                 "An unsigned copy may be a modified version with anti-cheat checks patched " +
                                 "out or a wrapper that loads cheat code before the real RageMP process.",
                        Detail = $"Path: {exePath} | Signed: No"
                    });
                    continue;
                }

                FileInfo fi;
                try { fi = new FileInfo(exePath); }
                catch (IOException) { continue; }

                var daysSinceWrite = (DateTime.UtcNow - fi.LastWriteTimeUtc).TotalDays;
                if (daysSinceWrite < 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "RAGE Multiplayer Cheat Detection",
                        Title = $"RageMP core executable recently modified: {exeName}",
                        Risk = RiskLevel.Medium,
                        Location = exePath,
                        FileName = exeName,
                        Reason = $"RageMP core executable '{exeName}' was modified within the last 24 hours. " +
                                 "While this may be a legitimate update, it warrants review if no update " +
                                 "was expected. Bypass tools sometimes replace the executable entirely.",
                        Detail = $"Last written: {fi.LastWriteTimeUtc:yyyy-MM-dd HH:mm} UTC"
                    });
                }
            }
        }
    }

    private void CheckRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var registryPaths = new[]
        {
            @"SOFTWARE\RAGEMP",
            @"SOFTWARE\RageMP",
            @"SOFTWARE\RAGE-MP",
            @"SOFTWARE\RageMPBypass",
            @"SOFTWARE\RageMPCheat",
        };

        var suspectValueNames = new[]
        {
            "RageMPBypass", "RageMPCheat", "RageMPHack", "RageMPInjector",
            "RageMPExploit", "RageMPMenu", "CefBypass", "JsInject",
            "BridgeBypass", "SyncBypass", "EventBypass", "HashBypass",
            "IntegrityBypass", "AntiCheatBypass",
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
                                    Title = $"RageMP bypass registry value: {valueName}",
                                    Risk = RiskLevel.High,
                                    Location = $@"{(hive == hkcu ? "HKCU" : "HKLM")}\{regPath}\{valueName}",
                                    Reason = $"Registry value '{valueName}' under '{regPath}' contains keywords " +
                                             "associated with RAGE Multiplayer cheat or bypass configuration.",
                                    Detail = $"Value: {(val.Length > 200 ? val[..200] + "..." : val)}"
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        ScanUninstallKeysForRageMpCheats(ctx, ct);
        ScanMuiCacheForRageCheatExecutables(ctx, ct);
    }

    private static void ScanUninstallKeysForRageMpCheats(ScanContext ctx, CancellationToken ct)
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        var cheatProductKeywords = new[]
        {
            "ragemp cheat", "ragemp hack", "ragemp bypass", "ragemp menu",
            "ragemp injector", "ragemp exploit", "ragemp mod menu",
            "rage multiplayer cheat", "rage multiplayer hack",
            "rage mp cheat", "rage mp bypass", "rage mp hack",
            "ragepluginhook cheat", "ragehook cheat",
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
                                        Module = "RAGE Multiplayer Cheat Detection",
                                        Title = $"RageMP cheat software in Uninstall registry: {displayName}",
                                        Risk = RiskLevel.Critical,
                                        Location = $@"{(hive == hkcu ? "HKCU" : "HKLM")}\{path}\{subKeyName}",
                                        Reason = $"Uninstall registry entry '{displayName}' matches known " +
                                                 $"RageMP cheat software keyword '{kw}'. Indicates the software " +
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

    private static void ScanMuiCacheForRageCheatExecutables(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var muiCachePath = @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

        using var hkcu = Registry.CurrentUser;
        RegistryKey? muiKey = null;
        try { muiKey = hkcu.OpenSubKey(muiCachePath, writable: false); }
        catch (Exception) { }

        if (muiKey == null) return;

        using (muiKey)
        {
            ctx.IncrementRegistryKeys();

            foreach (var valueName in muiKey.GetValueNames())
            {
                if (ct.IsCancellationRequested) return;

                if (!valueName.EndsWith(".FriendlyAppName", StringComparison.OrdinalIgnoreCase)) continue;

                var exePath = valueName[..^".FriendlyAppName".Length];
                var exeName = Path.GetFileName(exePath);

                if (CheatExeNames.Contains(exeName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "RAGE Multiplayer Cheat Detection",
                        Title = $"RageMP cheat EXE execution history (MUICache): {exeName}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKCU\{muiCachePath}\{valueName}",
                        FileName = exeName,
                        Reason = $"MUICache record shows known RageMP cheat executable '{exeName}' was " +
                                 "previously run on this system. MUICache entries persist even after file " +
                                 "deletion, providing evidence of prior execution.",
                        Detail = $"Recorded path: {exePath}"
                    });
                    continue;
                }

                if (IsRageMpCheatName(exeName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "RAGE Multiplayer Cheat Detection",
                        Title = $"Suspicious RageMP-related EXE in MUICache: {exeName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{muiCachePath}\{valueName}",
                        FileName = exeName,
                        Reason = $"MUICache record shows executable '{exeName}' was previously run. " +
                                 "The name contains RageMP cheat-associated keywords. " +
                                 "MUICache persists after file deletion.",
                        Detail = $"Recorded path: {exePath}"
                    });
                }
            }
        }
    }

    private static bool IsRageMpCheatName(string name)
    {
        if (name.Contains("cheat", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("hack", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("inject", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("exploit", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("aimbot", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("wallhack", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("godmode", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("god_mode", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("noclip", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("no_clip", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("speedhack", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("speed_hack", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("spinbot", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("teleport", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("executor", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("modmenu", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("mod_menu", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("trainer", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("ragemp_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("rage_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("ragebypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("ragemp_cheat", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("rage_cheat", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("ragecheat", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("ragemp_hack", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("ragehack", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("cef_exploit", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("cef_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("js_inject", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("js_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("bridge_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("sync_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("event_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("hash_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("integrity_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("anticheat_bypass", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("money_drop", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("money_loop", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("vehicle_spawn", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("weapon_give", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("crash_player", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("kick_player", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("freeze_player", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("invisible_player", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("stealth_mode", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("grief", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("esp_", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("_esp", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

}
