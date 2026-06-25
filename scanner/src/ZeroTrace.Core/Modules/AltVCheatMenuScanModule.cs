using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AltVCheatMenuScanModule : IScanModule
{
    public string Name => "alt:V Cheat Menu Detection";
    public double Weight => 4.3;
    public int ParallelGroup => 4;

    private static readonly string LocalApp = Environment.GetFolderPath(
        Environment.SpecialFolder.LocalApplicationData);
    private static readonly string AppData = Environment.GetFolderPath(
        Environment.SpecialFolder.ApplicationData);

    private static readonly string[] AltVRootPaths =
    {
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "altv"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "alt-v"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "alt_v"),
    };

    private static readonly HashSet<string> CheatExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "altv_cheat.exe", "altv_hack.exe", "altv_menu.exe", "altv_bypass.exe",
        "altv_injector.exe", "altv_lua.exe", "altv_script.exe", "altv_resource.exe",
        "altv_exploit.exe", "altv_mod.exe", "altvcheat.exe", "altvhack.exe",
        "altvmenu.exe", "altvbypass.exe", "altvinjector.exe", "altv_javascript_bypass.exe",
        "altv_csharp_bypass.exe", "altv_server_bypass.exe", "altv_module_bypass.exe",
        "altv_nametag_bypass.exe", "altv_esp.exe", "altv_aimbot.exe",
        "altv_teleport.exe", "altv_godmode.exe", "altv_speedhack.exe",
        "altv_noclip.exe", "altv_vehicle.exe", "altv_weapon.exe", "altv_money.exe",
        "altv_rank.exe", "altv_admin_bypass.exe", "altv_permission_bypass.exe",
        "altv_event_bypass.exe", "altv_sync_bypass.exe", "altv_anticheat_bypass.exe",
        "altv_crash.exe", "altv_grief.exe", "altv_troll.exe", "altv_freeze.exe",
        "altv_kick.exe", "altv_clone.exe", "altv_stealth.exe", "altv_invisible.exe",
        "altv_overlay.exe", "altv_trainer.exe", "altv_modmenu.exe", "altv_loader.exe",
        "altv_inject.exe", "altv_executor.exe", "altv_runner.exe", "altv_patch.exe",
        "altv_hook.exe", "altv_proxy.exe", "altvmod.exe", "altvtrainer.exe",
        "altv_cef_bypass.exe", "altv_ui_bypass.exe", "altv_native_bypass.exe",
        "altv_hash_bypass.exe", "altv_integrity_bypass.exe",
    };

    private static readonly HashSet<string> CheatDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "altv_cheat.dll", "altv_hack.dll", "altv_menu.dll", "altv_bypass.dll",
        "altv_injector.dll", "altv_lua.dll", "altv_script.dll", "altv_resource.dll",
        "altv_exploit.dll", "altv_mod.dll", "altvcheat.dll", "altvhack.dll",
        "altvmenu.dll", "altvbypass.dll", "altvinjector.dll",
        "altv_javascript_bypass.dll", "altv_csharp_bypass.dll",
        "altv_server_bypass.dll", "altv_module_bypass.dll",
        "altv_esp.dll", "altv_aimbot.dll", "altv_godmode.dll",
        "altv_speedhack.dll", "altv_noclip.dll", "altv_money.dll",
        "altv_permission_bypass.dll", "altv_event_bypass.dll",
        "altv_sync_bypass.dll", "altv_anticheat_bypass.dll",
        "altv_client_hook.dll", "altv_native_hook.dll",
    };

    private static readonly HashSet<string> CoreClientDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "altv-client.dll", "altv_client.dll", "altv-client-main.dll",
        "altv-js.dll", "altv_js.dll",
    };

    private static readonly HashSet<string> SuspiciousProxyDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "dinput8.dll", "version.dll", "dsound.dll", "winmm.dll",
        "d3d9.dll", "d3d11.dll", "bink2w64.dll", "msacm32.dll",
    };

    private static readonly string[] JavaScriptCheatPatterns =
    {
        "alt.emit(", "alt.onServer(", "alt.emitServer(",
        "native.invoke(", "native.call(", "invokeNative(",
        "alt.Player.all", "alt.Vehicle.all",
        "SetEntityInvincible", "SetEntityCoords", "SetPedMaxSpeed",
        "AddExplosion", "GiveWeaponToPed", "SetPlayerWantedLevel",
        "NetworkResurrectLocalPlayer", "SetEntityHealth",
        "TaskLeaveAnyCar", "DeleteEntity", "RemoveAllPedWeapons",
        "bypass", "anticheat_bypass", "aimbot", "wallhack",
        "esp_enabled", "godmode_enabled", "noclip_enabled",
        "speedhack", "teleport_coords", "spinbot",
        "eval(atob(", "eval(Buffer.from(", "Function('return ",
        "require('child_process')", "require(\"child_process\")",
        "process.env.USERNAME", "__proto__", "Object.defineProperty.*configurable",
    };

    private static readonly string[] CSharpCheatPatterns =
    {
        "AltV.Net.Client", "AltV.Net.Async",
        "SetEntityInvincible", "SetEntityCoords", "InvokeNative",
        "SetPedMaxSpeed", "AddExplosion", "GiveWeaponToPed",
        "bypass", "anticheat", "inject", "hook",
        "RuntimeImport", "PInvoke", "DllImport",
        "Marshal.GetDelegateForFunctionPointer",
        "VirtualAlloc", "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "OpenProcess",
        "Assembly.Load(", "Assembly.LoadFrom(",
        "Activator.CreateInstance", "MethodBase.Invoke",
    };

    private static readonly string[] CheatConfigKeywords =
    {
        "altv_god_mode", "altv_no_clip", "altv_speed", "altv_tp_coords",
        "altv_spawn_vehicle", "altv_give_weapon", "altv_set_money",
        "altv_kick_player", "altv_crash_server", "altv_spam_event",
        "altv_emit_server", "altv_bypass_sync", "altv_fake_ping",
        "altv_clone_player", "altv_steal_id", "altv_dump_players",
        "altv_bypass_anticheat", "altv_anticheat_bypass",
        "altv_admin_bypass", "altv_permission_bypass",
        "altv_event_bypass", "altv_js_inject", "altv_csharp_inject",
        "altv_native_bypass", "altv_hash_bypass", "altv_integrity_bypass",
        "altv_esp_enabled", "altv_aimbot_enabled", "altv_wallhack_enabled",
        "altv_speedhack_enabled", "altv_godmode_enabled",
        "altv_noclip_enabled", "altv_spinbot_enabled",
        "altv_teleport_enabled", "altv_vehicle_godmode",
        "altv_weapon_godmode", "altv_freeze_player",
        "altv_invisible_player", "altv_stealth_mode",
        "bypass_mode", "cheat_mode", "hack_mode", "exploit_mode",
        "godmode", "noclip", "speedhack", "aimbot", "wallhack",
    };

    private static readonly string[] KnownCheatResourceNames =
    {
        "cheat-resource", "cheat_resource", "hack_resource", "exploit_resource",
        "bypass-resource", "bypass_resource", "aimbot_resource", "esp_resource",
        "godmode_resource", "noclip_resource", "speedhack_resource",
        "teleport_resource", "money_resource", "vehicle_resource",
        "weapon_resource", "grief_resource", "troll_resource",
        "crash_resource", "kick_resource", "freeze_resource",
        "invisible_resource", "stealth_resource", "admin_bypass",
    };

    private static readonly string[] ResourceFileEntryPoints =
    {
        "resource.cfg", "resource.json", "meta.json",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting alt:V cheat menu scan...");

        bool altVInstalled = AltVRootPaths.Any(Directory.Exists);
        if (!altVInstalled)
        {
            ctx.Report(1.0, Name, "alt:V installation not found; skipping.");
            return;
        }

        ctx.Report(0.05, Name, "alt:V installation found; scanning...");

        await Task.Run(() =>
        {
            double step = 0.05;

            ScanForCheatExecutables(ctx, ct);
            step += 0.14;
            ctx.Report(step, Name, "Executable scan complete.");

            ScanForCheatDlls(ctx, ct);
            step += 0.14;
            ctx.Report(step, Name, "DLL scan complete.");

            ScanForClientDllReplacement(ctx, ct);
            step += 0.07;
            ctx.Report(step, Name, "Client DLL replacement check complete.");

            ScanForProxyDlls(ctx, ct);
            step += 0.07;
            ctx.Report(step, Name, "Proxy DLL scan complete.");

            ScanJavaScriptResources(ctx, ct);
            step += 0.14;
            ctx.Report(step, Name, "JavaScript resource scan complete.");

            ScanCSharpPlugins(ctx, ct);
            step += 0.14;
            ctx.Report(step, Name, "C# plugin scan complete.");

            ScanDataDirectory(ctx, ct);
            step += 0.07;
            ctx.Report(step, Name, "Data directory scan complete.");

            ScanForCheatConfigs(ctx, ct);
            step += 0.10;
            ctx.Report(step, Name, "Config keyword scan complete.");

            ScanForMaliciousResources(ctx, ct);
            step += 0.10;
            ctx.Report(step, Name, "Resource scan complete.");

            CheckRegistryArtifacts(ctx, ct);

            ctx.Report(1.0, Name, "alt:V cheat menu scan complete.");
        }, ct);
    }

    private void ScanForCheatExecutables(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in AltVRootPaths)
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
                        Title = $"alt:V Cheat EXE: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known alt:V cheat executable '{fn}' found in the alt:V directory tree. " +
                                 "This file is a recognised cheat menu, injector or bypass tool targeting " +
                                 "the alt:V GTA V multiplayer platform.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                if (IsAltVCheatName(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious EXE in alt:V directory: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Executable '{fn}' in the alt:V directory tree has a name containing " +
                                 "cheat-associated keywords (bypass, hack, inject, exploit, cheat, aimbot). " +
                                 "Not a recognised legitimate alt:V component.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
    }

    private void ScanForCheatDlls(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in AltVRootPaths)
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
                        Title = $"alt:V Cheat DLL: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known alt:V cheat DLL '{fn}' found. This library is injected into the " +
                                 "alt:V client process to enable god mode, ESP, aimbot, teleportation, " +
                                 "event bypass or anti-cheat circumvention.",
                        Detail = $"Path: {file}"
                    });
                    continue;
                }

                if (IsAltVCheatName(fn))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious DLL in alt:V directory: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"DLL '{fn}' in the alt:V directory tree has a cheat-associated name. " +
                                 "Cheat DLLs are typically loaded via injection or DLL hijacking into " +
                                 "the alt:V client process.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
    }

    private void ScanForClientDllReplacement(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in AltVRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            foreach (var coredll in CoreClientDllNames)
            {
                var dllPath = Path.Combine(root, coredll);
                if (!File.Exists(dllPath)) continue;

                ctx.IncrementFiles();

                bool signed = false;
                try
                {
                    System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(dllPath);
                    signed = true;
                }
                catch { }

                if (!signed)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Unsigned alt:V core client DLL: {coredll}",
                        Risk = RiskLevel.Critical,
                        Location = dllPath,
                        FileName = coredll,
                        Reason = $"The core alt:V client DLL '{coredll}' is not digitally signed. " +
                                 "Legitimate alt:V client DLLs are signed by altMP/alt:V. An unsigned " +
                                 "copy indicates the file may have been replaced by a modified cheat version " +
                                 "that hooks into the alt:V JavaScript runtime or C# module loader.",
                        Detail = $"Path: {dllPath} | Signed: No"
                    });
                    continue;
                }

                FileInfo fi;
                try { fi = new FileInfo(dllPath); }
                catch (IOException) { continue; }

                var daysSinceWrite = (DateTime.UtcNow - fi.LastWriteTimeUtc).TotalDays;
                if (daysSinceWrite < 1)
                {
                    var altVExe = Path.Combine(root, "altv.exe");
                    bool exeAlsoModified = File.Exists(altVExe) &&
                        (DateTime.UtcNow - new FileInfo(altVExe).LastWriteTimeUtc).TotalDays < 1;

                    if (!exeAlsoModified)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V client DLL recently modified without client update: {coredll}",
                            Risk = RiskLevel.High,
                            Location = dllPath,
                            FileName = coredll,
                            Reason = $"alt:V core client DLL '{coredll}' was modified within the last 24 hours " +
                                     "but the main altv.exe was not updated simultaneously. This discrepancy " +
                                     "may indicate targeted patching of the client DLL by a bypass tool.",
                            Detail = $"DLL last written: {fi.LastWriteTimeUtc:yyyy-MM-dd HH:mm} UTC"
                        });
                    }
                }
            }
        }
    }

    private void ScanForProxyDlls(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in AltVRootPaths)
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
                        Title = $"Unsigned proxy DLL in alt:V root: {proxyDll}",
                        Risk = RiskLevel.Critical,
                        Location = proxyPath,
                        FileName = proxyDll,
                        Reason = $"Unsigned '{proxyDll}' found in the alt:V installation root. " +
                                 "This Windows system DLL name is commonly hijacked by cheat loaders: " +
                                 "the cheat places its own version here so the OS loads it instead of " +
                                 "the legitimate system copy, injecting code without an explicit injector.",
                        Detail = $"Path: {proxyPath} | Signed: No"
                    });
                }
            }
        }
    }

    private void ScanJavaScriptResources(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in AltVRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            var resourceDirs = new[]
            {
                Path.Combine(root, "resources"),
                Path.Combine(root, "data", "resources"),
            };

            foreach (var resDir in resourceDirs)
            {
                if (!Directory.Exists(resDir)) continue;

                IEnumerable<string> jsFiles;
                try
                {
                    jsFiles = Directory.EnumerateFiles(resDir, "*.js", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in jsFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

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

                    AnalyzeJavaScriptContent(ctx, file, content, ct);
                }
            }
        }
    }

    private void AnalyzeJavaScriptContent(ScanContext ctx, string file, string content, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var fn = Path.GetFileName(file);
        var hits = new List<string>();

        foreach (var pattern in JavaScriptCheatPatterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                hits.Add(pattern);
            if (hits.Count >= 8) break;
        }

        if (hits.Count == 0) return;

        var risk = hits.Count >= 5 ? RiskLevel.Critical
                 : hits.Count >= 3 ? RiskLevel.High
                 : hits.Count >= 2 ? RiskLevel.Medium
                 : RiskLevel.Low;

        bool hasObfuscation = content.Contains("eval(atob(", StringComparison.OrdinalIgnoreCase)
                           || content.Contains("eval(Buffer.from(", StringComparison.OrdinalIgnoreCase)
                           || content.Contains("Function('return ", StringComparison.OrdinalIgnoreCase);

        if (hasObfuscation && risk < RiskLevel.High)
            risk = RiskLevel.High;

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"Cheat patterns in alt:V JS resource: {fn}",
            Risk = risk,
            Location = file,
            FileName = fn,
            Reason = $"alt:V JavaScript resource file '{fn}' contains {hits.Count} cheat-characteristic " +
                     $"pattern(s): {string.Join(", ", hits.Take(4).Select(h => $"'{h}'"))}. " +
                     "These patterns indicate game native abuse, eval-based obfuscated injection, " +
                     "server event exploitation or anti-cheat bypass in an alt:V JS resource.",
            Detail = $"Matched ({hits.Count}): {string.Join(", ", hits.Take(6))}" +
                     (hasObfuscation ? " | Obfuscation detected" : "")
        });
    }

    private void ScanCSharpPlugins(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in AltVRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            var pluginDirs = new[]
            {
                Path.Combine(root, "plugins"),
                Path.Combine(root, "modules"),
                Path.Combine(root, "resources"),
                Path.Combine(root, "data", "plugins"),
            };

            foreach (var pluginDir in pluginDirs)
            {
                if (!Directory.Exists(pluginDir)) continue;

                IEnumerable<string> dlls;
                try
                {
                    dlls = Directory.EnumerateFiles(pluginDir, "*.dll", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var dll in dlls)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(dll);

                    if (IsAltVCheatName(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Suspicious C# plugin DLL: {fn}",
                            Risk = RiskLevel.High,
                            Location = dll,
                            FileName = fn,
                            Reason = $"alt:V C# plugin DLL '{fn}' has a name associated with cheat software. " +
                                     "alt:V auto-loads .NET assemblies from the plugins directory, making " +
                                     "this a vector for C# assembly injection with full .NET capabilities.",
                            Detail = $"Path: {dll}"
                        });
                        continue;
                    }

                    AnalyzeDllForCheatStrings(ctx, dll, fn, ct);
                }
            }
        }
    }

    private void AnalyzeDllForCheatStrings(ScanContext ctx, string file, string fn, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

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
        foreach (var pattern in CSharpCheatPatterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                hits.Add(pattern);
            if (hits.Count >= 6) break;
        }

        if (hits.Count < 2) return;

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = $"Cheat strings in alt:V C# assembly: {fn}",
            Risk = hits.Count >= 4 ? RiskLevel.Critical : RiskLevel.High,
            Location = file,
            FileName = fn,
            Reason = $"alt:V C# assembly '{fn}' contains {hits.Count} strings characteristic of cheat code: " +
                     $"{string.Join(", ", hits.Take(4).Select(h => $"'{h}'"))}. " +
                     "These include native invocation APIs, process memory access imports or " +
                     "dynamic assembly loading patterns used by cheat modules.",
            Detail = $"Matched patterns ({hits.Count}): {string.Join(", ", hits.Take(6))}"
        });
    }

    private void ScanDataDirectory(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in AltVRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            var dataDir = Path.Combine(root, "data");
            if (!Directory.Exists(dataDir)) continue;

            IEnumerable<string> exeFiles;
            try
            {
                exeFiles = Directory.EnumerateFiles(dataDir, "*.exe", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in exeFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fn = Path.GetFileName(file);

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"EXE in alt:V data directory: {fn}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fn,
                    Reason = $"Executable '{fn}' found in the alt:V data directory. Legitimate alt:V data " +
                             "files are configuration, cache and resource data — not executables. " +
                             "This may be a cheat launcher or bypass tool hidden in the data directory.",
                    Detail = $"Path: {file}"
                });
            }

            CheckDataModifications(ctx, ct, dataDir);
        }
    }

    private static void CheckDataModifications(ScanContext ctx, CancellationToken ct, string dataDir)
    {
        if (ct.IsCancellationRequested) return;

        var knownCorruptible = new[]
        {
            "voice.cfg", "settings.cfg", "branch.cfg",
        };

        foreach (var configFile in knownCorruptible)
        {
            if (ct.IsCancellationRequested) return;

            var cfgPath = Path.Combine(dataDir, configFile);
            if (!File.Exists(cfgPath)) continue;

            ctx.IncrementFiles();

            FileInfo fi;
            try { fi = new FileInfo(cfgPath); }
            catch (IOException) { continue; }

            if (fi.Length == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "alt:V Cheat Menu Detection",
                    Title = $"alt:V data config is empty: {configFile}",
                    Risk = RiskLevel.Medium,
                    Location = cfgPath,
                    FileName = configFile,
                    Reason = $"alt:V data configuration file '{configFile}' is empty (0 bytes). " +
                             "Some alt:V cheat tools blank out config files to disable anti-cheat " +
                             "or logging features that would detect their activity.",
                    Detail = $"Path: {cfgPath} | Size: 0 bytes"
                });
            }
        }
    }

    private void ScanForCheatConfigs(ScanContext ctx, CancellationToken ct)
    {
        var configExtensions = new[] { ".cfg", ".ini", ".json", ".txt", ".conf", ".yaml", ".yml" };

        foreach (var root in AltVRootPaths)
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
                        Title = $"alt:V cheat config keywords: {Path.GetFileName(file)}",
                        Risk = risk,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Config file '{Path.GetFileName(file)}' contains {hits.Count} alt:V cheat-related " +
                                 $"keyword(s): {string.Join(", ", hits.Take(4).Select(h => $"'{h}'"))}. " +
                                 "These keywords are characteristic of alt:V cheat menu or bypass configuration.",
                        Detail = $"Matched keywords ({hits.Count}): {string.Join(", ", hits.Take(6))}"
                    });
                }
            }
        }
    }

    private void ScanForMaliciousResources(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in AltVRootPaths)
        {
            if (!Directory.Exists(root)) continue;
            if (ct.IsCancellationRequested) return;

            var resDir = Path.Combine(root, "resources");
            if (!Directory.Exists(resDir)) continue;

            string[] resourceFolders;
            try
            {
                resourceFolders = Directory.GetDirectories(resDir);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var resourceFolder in resourceFolders)
            {
                if (ct.IsCancellationRequested) return;

                var resourceName = Path.GetFileName(resourceFolder).ToLowerInvariant();

                foreach (var knownCheat in KnownCheatResourceNames)
                {
                    if (resourceName.Contains(knownCheat, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Known cheat resource name: {resourceName}",
                            Risk = RiskLevel.Critical,
                            Location = resourceFolder,
                            FileName = resourceName,
                            Reason = $"alt:V resource folder '{resourceName}' matches a known cheat resource name. " +
                                     "Malicious resources are loaded automatically when connecting to a server " +
                                     "or can be self-hosted to execute cheat code in the client context.",
                            Detail = $"Path: {resourceFolder} | Matched: {knownCheat}"
                        });
                        break;
                    }
                }

                if (IsAltVCheatName(resourceName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious alt:V resource directory: {resourceName}",
                        Risk = RiskLevel.High,
                        Location = resourceFolder,
                        FileName = resourceName,
                        Reason = $"alt:V resource directory '{resourceName}' has a name containing " +
                                 "cheat-associated keywords. Resources with suspicious names may contain " +
                                 "JavaScript or C# cheat code that executes in the game client context.",
                        Detail = $"Path: {resourceFolder}"
                    });
                    continue;
                }

                ScanResourceEntryPoint(ctx, ct, resourceFolder, resourceName);
            }
        }
    }

    private void ScanResourceEntryPoint(ScanContext ctx, CancellationToken ct,
        string resourceFolder, string resourceName)
    {
        if (ct.IsCancellationRequested) return;

        foreach (var entryFile in ResourceFileEntryPoints)
        {
            var entryPath = Path.Combine(resourceFolder, entryFile);
            if (!File.Exists(entryPath)) continue;

            ctx.IncrementFiles();

            FileInfo fi;
            try { fi = new FileInfo(entryPath); }
            catch (IOException) { continue; }

            if (fi.Length > 64 * 1024) continue;

            string content;
            try
            {
                using var fs = new FileStream(entryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
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
                if (hits.Count >= 4) break;
            }

            if (hits.Count > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat keywords in alt:V resource config: {resourceName}/{entryFile}",
                    Risk = hits.Count >= 3 ? RiskLevel.High : RiskLevel.Medium,
                    Location = entryPath,
                    FileName = entryFile,
                    Reason = $"Resource config file '{resourceName}/{entryFile}' contains {hits.Count} " +
                             $"cheat-related keyword(s): {string.Join(", ", hits.Take(3).Select(h => $"'{h}'"))}. " +
                             "Cheat resources often declare their capabilities in their configuration manifest.",
                    Detail = $"Resource: {resourceName} | Matched: {string.Join(", ", hits)}"
                });
            }
        }
    }

    private void CheckRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var registryPaths = new[]
        {
            @"SOFTWARE\altv",
            @"SOFTWARE\alt-v",
            @"SOFTWARE\altMP",
            @"SOFTWARE\altVBypass",
        };

        var suspectValueNames = new[]
        {
            "AltVBypass", "AltVCheat", "AltVHack", "AltVInjector",
            "AltVExploit", "AltVMenu", "JavaScriptBypass", "CSharpBypass",
            "ResourceBypass", "SyncBypass", "EventBypass",
        };

        using var hkcu = Registry.CurrentUser;
        using var hklm = Registry.LocalMachine;

        foreach (var path in registryPaths)
        {
            if (ct.IsCancellationRequested) return;

            foreach (var hive in new[] { hkcu, hklm })
            {
                RegistryKey? key = null;
                try { key = hive.OpenSubKey(path, writable: false); }
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
                                    Title = $"alt:V bypass registry value: {valueName}",
                                    Risk = RiskLevel.High,
                                    Location = $@"{(hive == hkcu ? "HKCU" : "HKLM")}\{path}\{valueName}",
                                    Reason = $"Registry value '{valueName}' under '{path}' contains keywords " +
                                             "associated with alt:V cheat or bypass configuration.",
                                    Detail = $"Value: {(val.Length > 200 ? val[..200] + "..." : val)}"
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        ScanUninstallKeysForAltVCheats(ctx, ct);
    }

    private static void ScanUninstallKeysForAltVCheats(ScanContext ctx, CancellationToken ct)
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        var cheatProductKeywords = new[]
        {
            "altv cheat", "altv hack", "altv bypass", "altv menu",
            "altv injector", "altv exploit", "altv mod menu",
            "alt:v cheat", "alt:v hack", "alt:v bypass",
            "altmp cheat", "altmp hack",
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
                                        Module = "alt:V Cheat Menu Detection",
                                        Title = $"alt:V cheat software in Uninstall registry: {displayName}",
                                        Risk = RiskLevel.Critical,
                                        Location = $@"{(hive == hkcu ? "HKCU" : "HKLM")}\{path}\{subKeyName}",
                                        Reason = $"Uninstall registry entry '{displayName}' matches known alt:V " +
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

    private static bool IsAltVCheatName(string name)
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
        if (name.Contains("esp_", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("_esp", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("grief", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("crash_", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("_crash", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("kick_", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("_kick", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("freeze_player", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("money_drop", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("steal_id", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("clone_player", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("dump_players", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("invisible", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Contains("stealth", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

}
