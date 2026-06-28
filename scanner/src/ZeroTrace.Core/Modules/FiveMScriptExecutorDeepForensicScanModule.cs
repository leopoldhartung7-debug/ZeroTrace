using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class FiveMScriptExecutorDeepForensicScanModule : IScanModule
{
    public string Name => "FiveM Script Executor Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string LocalApp = Environment.GetFolderPath(
        Environment.SpecialFolder.LocalApplicationData);
    private static readonly string AppData = Environment.GetFolderPath(
        Environment.SpecialFolder.ApplicationData);
    private static readonly string UserProfile = Environment.GetFolderPath(
        Environment.SpecialFolder.UserProfile);
    private static readonly string Downloads = Path.Combine(UserProfile, "Downloads");
    private static readonly string Desktop = Environment.GetFolderPath(
        Environment.SpecialFolder.Desktop);
    private static readonly string Documents = Environment.GetFolderPath(
        Environment.SpecialFolder.MyDocuments);
    private static readonly string Temp = Path.GetTempPath();

    private static readonly string[] ExecutorInstallDirs = { "KRNL", "Synapse X", "Sentinel", "Script-Ware", "Electron Executor", "JJSploit", "Caesium", "Oxygen-U", "Oxygen" };
    private static readonly string[] ExecutorExeNames = { "KRNL.exe", "krnl_bootstrapper.exe", "SynapseX.exe", "S^X.exe", "Sentinel.exe", "SentinelLauncher.exe", "Script-Ware.exe", "Electron.exe", "ElectronExecutor.exe", "JJSploit.exe", "Caesium.exe", "OxygenU.exe" };
    private static readonly string[] ExecutorDLLNames = { "krnl.dll", "krnlss.dll", "SynapseX.dll", "sentinel.dll", "scriptware.dll", "electron.dll", "lua_executor.dll" };
    private static readonly string[] ExecutorRegistryKeys = { @"Software\KRNL", @"Software\Synapse X", @"Software\Sentinel", @"Software\Script-Ware", @"Software\JJSploit", @"Software\Electron", @"Software\Caesium" };
    private static readonly string[] ExecutorWebDomains = { "synapse.to", "krnl.ca", "sentinel.gg", "script-ware.com", "electron.gg", "jjsploit.net", "caesium.xyz" };
    private static readonly string[] FiveMScriptKeywords = { "TriggerServerEvent", "RegisterNetEvent", "AddEventHandler", "Citizen.CreateThread", "exports.spawnmanager", "TriggerEvent", "setImmediate", "Citizen.Wait" };
    private static readonly string[] FiveMExploitScriptKeywords = { "esx:addMoney", "QBCore:Server:AddMoney", "SetEntityInvincible", "GiveWeaponToPed", "AddExplosion", "NetworkExplodeVehicle", "crash", "kick", "godmode" };
    private static readonly string[] ScriptRepoSites = { "pastebin.com", "raw.githubusercontent.com", "scriptblox.com", "rscripts.net", "vc.to/scripts" };

    private static readonly string[] LicenseFileNames = { "key.txt", "license.txt", "license.key", "activation.key", "auth.json", "auth_token.txt" };
    private static readonly string[] AutoexecCheatKeywords = { "aimbot", "esp", "wallhack", "teleport", "godmode", "god_mode", "money", "crash", "kick", "spinbot", "noclip", "NoClip", "GodMode" };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckKRNLArtifacts(ctx, ct),
            CheckSynapseXArtifacts(ctx, ct),
            CheckSentinelArtifacts(ctx, ct),
            CheckScriptWareArtifacts(ctx, ct),
            CheckElectronExecutorArtifacts(ctx, ct),
            CheckJJSploitArtifacts(ctx, ct),
            CheckCaesiumExecutorArtifacts(ctx, ct),
            CheckOxygénExecutorArtifacts(ctx, ct),
            CheckExecutorWorkspaceScripts(ctx, ct),
            CheckExecutorLicenseKeyArtifacts(ctx, ct),
            CheckFiveMSpecificExecutorScripts(ctx, ct),
            CheckExecutorAutoexecScripts(ctx, ct),
            CheckExecutorRegistryTraces(ctx, ct),
            CheckExecutorPrefetchArtifacts(ctx, ct),
            CheckExecutorDLLArtifacts(ctx, ct),
            CheckExecutorCrashDumps(ctx, ct),
            CheckScriptRepositoryArtifacts(ctx, ct),
            CheckExecutorBrowserHistoryArtifacts(ctx, ct)
        );
    }

    private Task CheckKRNLArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var krnlLocalApp = Path.Combine(LocalApp, "KRNL");
            var krnlAppData = Path.Combine(AppData, "KRNL");

            foreach (var krnlDir in new[] { krnlLocalApp, krnlAppData })
            {
                if (!Directory.Exists(krnlDir)) continue;

                var exeTargets = new[] { "KRNL.exe", "krnl_bootstrapper.exe" };
                foreach (var exeName in exeTargets)
                {
                    var exePath = Path.Combine(krnlDir, exeName);
                    ctx.IncrementFiles();
                    if (File.Exists(exePath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"KRNL Executor Executable: {exeName}",
                            Risk = RiskLevel.Critical,
                            Location = exePath,
                            FileName = exeName,
                            Reason = "KRNL script executor executable found. KRNL is a free Roblox/FiveM script executor used to inject and run custom Lua scripts inside game environments.",
                            Detail = $"Directory: {krnlDir}"
                        });
                    }
                }

                var dllTargets = new[] { "krnlss.dll", "krnl.dll" };
                foreach (var dllName in dllTargets)
                {
                    var dllPath = Path.Combine(krnlDir, dllName);
                    ctx.IncrementFiles();
                    if (File.Exists(dllPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"KRNL Executor DLL: {dllName}",
                            Risk = RiskLevel.Critical,
                            Location = dllPath,
                            FileName = dllName,
                            Reason = "KRNL injection DLL artifact found. This DLL is injected into game processes to enable Lua script execution bypassing normal game restrictions.",
                            Detail = $"Directory: {krnlDir}"
                        });
                    }
                }

                var logPath = Path.Combine(krnlDir, "KRNL_Log.txt");
                ctx.IncrementFiles();
                if (File.Exists(logPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "KRNL Executor Log File",
                        Risk = RiskLevel.Critical,
                        Location = logPath,
                        FileName = "KRNL_Log.txt",
                        Reason = "KRNL script executor log file found. Log persists after executor use and may contain session history.",
                        Detail = $"Directory: {krnlDir}"
                    });
                }

                var workspacePath = Path.Combine(krnlDir, "workspace");
                if (Directory.Exists(workspacePath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "KRNL Workspace Directory",
                        Risk = RiskLevel.Critical,
                        Location = workspacePath,
                        FileName = "workspace",
                        Reason = "KRNL script executor workspace directory found. This directory stores Lua scripts executed by KRNL against FiveM and other game environments.",
                        Detail = $"Parent: {krnlDir}"
                    });
                }

                var autoexecPath = Path.Combine(krnlDir, "autoexec");
                if (Directory.Exists(autoexecPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "KRNL Autoexec Directory",
                        Risk = RiskLevel.Critical,
                        Location = autoexecPath,
                        FileName = "autoexec",
                        Reason = "KRNL autoexec directory found. Scripts in this folder are automatically executed on injection, enabling persistent Lua cheat automation.",
                        Detail = $"Parent: {krnlDir}"
                    });
                }
            }

            if (Directory.Exists(Downloads))
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(Downloads, "KRNL*.exe"))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"KRNL Executor Download: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "KRNL script executor installer found in Downloads directory, indicating recent acquisition of the tool.",
                            Detail = $"Downloads: {Downloads}"
                        });
                    }
                    foreach (var file in Directory.EnumerateFiles(Downloads, "KRNL*.zip"))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"KRNL Executor Archive: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "KRNL script executor archive found in Downloads directory, indicating recent acquisition of the tool.",
                            Detail = $"Downloads: {Downloads}"
                        });
                    }
                }
                catch { }
            }

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\KRNL");
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "KRNL Registry Key Found",
                        Risk = RiskLevel.Critical,
                        Location = @"HKCU\Software\KRNL",
                        Reason = "KRNL script executor registry key found. This key is created during KRNL installation or use.",
                        Detail = $"Values: {string.Join(", ", key.GetValueNames())}"
                    });
                }
            }
            catch { }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckSynapseXArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var synLocalApp = Path.Combine(LocalApp, "Synapse X");
            var synAppData = Path.Combine(AppData, "Synapse X");

            foreach (var synDir in new[] { synLocalApp, synAppData })
            {
                if (!Directory.Exists(synDir)) continue;

                var exeTargets = new[] { "Synapse X.exe", "S^X.exe", "SynapseX.exe" };
                foreach (var exeName in exeTargets)
                {
                    var exePath = Path.Combine(synDir, exeName);
                    ctx.IncrementFiles();
                    if (File.Exists(exePath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Synapse X Executor Executable: {exeName}",
                            Risk = RiskLevel.Critical,
                            Location = exePath,
                            FileName = exeName,
                            Reason = "Synapse X premium script executor executable found. Synapse X is a widely used paid executor for injecting custom Lua scripts into FiveM and Roblox.",
                            Detail = $"Directory: {synDir}"
                        });
                    }
                }

                var authPath = Path.Combine(synDir, "auth.json");
                ctx.IncrementFiles();
                if (File.Exists(authPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Synapse X Authentication File",
                        Risk = RiskLevel.Critical,
                        Location = authPath,
                        FileName = "auth.json",
                        Reason = "Synapse X auth.json license file found. This file proves an active premium Synapse X subscription and persistent executor installation.",
                        Detail = $"Directory: {synDir}"
                    });
                }

                var dllBinDir = Path.Combine(synDir, "bin");
                foreach (var dllName in new[] { "SynExe.dll", "SynLua.dll" })
                {
                    var dllPath = Path.Combine(dllBinDir, dllName);
                    ctx.IncrementFiles();
                    if (File.Exists(dllPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Synapse X DLL Component: {dllName}",
                            Risk = RiskLevel.Critical,
                            Location = dllPath,
                            FileName = dllName,
                            Reason = $"Synapse X core DLL '{dllName}' found. This is the injection and Lua execution payload used to hook into game processes.",
                            Detail = $"Directory: {dllBinDir}"
                        });
                    }
                }

                foreach (var subDir in new[] { "workspace", "autoexec", "scripts" })
                {
                    var subPath = Path.Combine(synDir, subDir);
                    if (Directory.Exists(subPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Synapse X {subDir} Directory",
                            Risk = RiskLevel.Critical,
                            Location = subPath,
                            FileName = subDir,
                            Reason = $"Synapse X '{subDir}' directory found. This directory stores Lua scripts used or auto-executed by the Synapse X executor.",
                            Detail = $"Parent: {synDir}"
                        });
                    }
                }
            }

            if (Directory.Exists(Downloads))
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(Downloads, "Synapse*.zip"))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Synapse X Download Archive: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Synapse X archive found in Downloads, indicating recent acquisition of this premium script executor.",
                            Detail = $"Downloads: {Downloads}"
                        });
                    }
                    foreach (var file in Directory.EnumerateFiles(Downloads, "SynapseX*.exe"))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Synapse X Download Installer: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Synapse X installer found in Downloads, indicating recent acquisition of this premium script executor.",
                            Detail = $"Downloads: {Downloads}"
                        });
                    }
                }
                catch { }
            }

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Synapse X");
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Synapse X Registry Key Found",
                        Risk = RiskLevel.Critical,
                        Location = @"HKCU\Software\Synapse X",
                        Reason = "Synapse X registry key found. This key is written during Synapse X installation or license activation.",
                        Detail = $"Values: {string.Join(", ", key.GetValueNames())}"
                    });
                }
            }
            catch { }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckSentinelArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var sentLocalApp = Path.Combine(LocalApp, "Sentinel");
            var sentAppData = Path.Combine(AppData, "Sentinel");

            foreach (var sentDir in new[] { sentLocalApp, sentAppData })
            {
                if (!Directory.Exists(sentDir)) continue;

                foreach (var exeName in new[] { "Sentinel.exe", "SentinelLauncher.exe" })
                {
                    var exePath = Path.Combine(sentDir, exeName);
                    ctx.IncrementFiles();
                    if (File.Exists(exePath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Sentinel Executor Executable: {exeName}",
                            Risk = RiskLevel.Critical,
                            Location = exePath,
                            FileName = exeName,
                            Reason = "Sentinel script executor executable found. Sentinel is a script executor designed for injecting Lua scripts into FiveM and similar game environments.",
                            Detail = $"Directory: {sentDir}"
                        });
                    }
                }

                var keyPath = Path.Combine(sentDir, "key.txt");
                ctx.IncrementFiles();
                if (File.Exists(keyPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Sentinel License Key File",
                        Risk = RiskLevel.Critical,
                        Location = keyPath,
                        FileName = "key.txt",
                        Reason = "Sentinel executor key.txt license file found. This file stores the product activation key proving purchase and use of this executor.",
                        Detail = $"Directory: {sentDir}"
                    });
                }

                var logPath = Path.Combine(sentDir, "sentinel_log.txt");
                ctx.IncrementFiles();
                if (File.Exists(logPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Sentinel Executor Log File",
                        Risk = RiskLevel.Critical,
                        Location = logPath,
                        FileName = "sentinel_log.txt",
                        Reason = "Sentinel executor log file found. This log persists session activity and script execution history.",
                        Detail = $"Directory: {sentDir}"
                    });
                }

                foreach (var subDir in new[] { "workspace", "bin" })
                {
                    var subPath = Path.Combine(sentDir, subDir);
                    if (Directory.Exists(subPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Sentinel {subDir} Directory",
                            Risk = RiskLevel.Critical,
                            Location = subPath,
                            FileName = subDir,
                            Reason = $"Sentinel executor '{subDir}' directory found. This directory contains scripts or DLL payloads used during injection.",
                            Detail = $"Parent: {sentDir}"
                        });
                    }
                }
            }

            if (Directory.Exists(Downloads))
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(Downloads, "Sentinel*.zip")
                        .Concat(Directory.EnumerateFiles(Downloads, "Sentinel*.exe")))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Sentinel Executor Download: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Sentinel script executor download artifact found in Downloads directory.",
                            Detail = $"Downloads: {Downloads}"
                        });
                    }
                }
                catch { }
            }

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Sentinel");
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Sentinel Registry Key Found",
                        Risk = RiskLevel.Critical,
                        Location = @"HKCU\Software\Sentinel",
                        Reason = "Sentinel script executor registry key found, indicating installation or prior use of this tool.",
                        Detail = $"Values: {string.Join(", ", key.GetValueNames())}"
                    });
                }
            }
            catch { }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckScriptWareArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var swLocalApp = Path.Combine(LocalApp, "Script-Ware");
            var swAppData = Path.Combine(AppData, "Script-Ware");

            foreach (var swDir in new[] { swLocalApp, swAppData })
            {
                if (!Directory.Exists(swDir)) continue;

                var exePath = Path.Combine(swDir, "Script-Ware.exe");
                ctx.IncrementFiles();
                if (File.Exists(exePath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Script-Ware Executor Executable",
                        Risk = RiskLevel.Critical,
                        Location = exePath,
                        FileName = "Script-Ware.exe",
                        Reason = "Script-Ware premium script executor executable found. Script-Ware is a high-end paid executor capable of injecting Lua scripts into FiveM and Roblox.",
                        Detail = $"Directory: {swDir}"
                    });
                }

                var licensePath = Path.Combine(swDir, "sw_license.json");
                ctx.IncrementFiles();
                if (File.Exists(licensePath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Script-Ware License File",
                        Risk = RiskLevel.Critical,
                        Location = licensePath,
                        FileName = "sw_license.json",
                        Reason = "Script-Ware license file found. This proves an active premium subscription to this advanced script executor.",
                        Detail = $"Directory: {swDir}"
                    });
                }

                var swDllPath = Path.Combine(swDir, "bin", "scriptware.dll");
                ctx.IncrementFiles();
                if (File.Exists(swDllPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Script-Ware Injection DLL",
                        Risk = RiskLevel.Critical,
                        Location = swDllPath,
                        FileName = "scriptware.dll",
                        Reason = "Script-Ware injection DLL found. This DLL is the core payload injected into game processes to enable Lua execution.",
                        Detail = $"Directory: {Path.Combine(swDir, "bin")}"
                    });
                }

                foreach (var subDir in new[] { "workspace", "autoexec" })
                {
                    var subPath = Path.Combine(swDir, subDir);
                    if (Directory.Exists(subPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Script-Ware {subDir} Directory",
                            Risk = RiskLevel.Critical,
                            Location = subPath,
                            FileName = subDir,
                            Reason = $"Script-Ware executor '{subDir}' directory found, containing Lua scripts used or auto-executed on injection.",
                            Detail = $"Parent: {swDir}"
                        });
                    }
                }
            }

            if (Directory.Exists(Downloads))
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(Downloads, "Script-Ware*.zip")
                        .Concat(Directory.EnumerateFiles(Downloads, "ScriptWare*.exe")))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Script-Ware Download: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Script-Ware download artifact found in Downloads directory, indicating recent acquisition.",
                            Detail = $"Downloads: {Downloads}"
                        });
                    }
                }
                catch { }
            }

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Script-Ware");
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Script-Ware Registry Key Found",
                        Risk = RiskLevel.Critical,
                        Location = @"HKCU\Software\Script-Ware",
                        Reason = "Script-Ware registry key found, indicating installation or use of this premium executor.",
                        Detail = $"Values: {string.Join(", ", key.GetValueNames())}"
                    });
                }
            }
            catch { }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckElectronExecutorArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var elecAppData = Path.Combine(AppData, "Electron");
            var elecLocalApp = Path.Combine(LocalApp, "Electron Executor");

            foreach (var elecDir in new[] { elecAppData, elecLocalApp })
            {
                if (!Directory.Exists(elecDir)) continue;

                foreach (var exeName in new[] { "Electron.exe", "ElectronExecutor.exe" })
                {
                    var exePath = Path.Combine(elecDir, exeName);
                    ctx.IncrementFiles();
                    if (File.Exists(exePath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Electron Executor Executable: {exeName}",
                            Risk = RiskLevel.Critical,
                            Location = exePath,
                            FileName = exeName,
                            Reason = "Electron script executor executable found. Note: this is the cheat executor named 'Electron', not the Electron application framework. Used to inject Lua scripts into FiveM.",
                            Detail = $"Directory: {elecDir}"
                        });
                    }
                }

                var logPath = Path.Combine(elecDir, "electron_log.txt");
                ctx.IncrementFiles();
                if (File.Exists(logPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Electron Executor Log File",
                        Risk = RiskLevel.Critical,
                        Location = logPath,
                        FileName = "electron_log.txt",
                        Reason = "Electron executor log file found, containing session and script execution history.",
                        Detail = $"Directory: {elecDir}"
                    });
                }

                foreach (var subDir in new[] { "workspace", "scripts" })
                {
                    var subPath = Path.Combine(elecDir, subDir);
                    if (Directory.Exists(subPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Electron Executor {subDir} Directory",
                            Risk = RiskLevel.Critical,
                            Location = subPath,
                            FileName = subDir,
                            Reason = $"Electron executor '{subDir}' directory found, storing Lua scripts used during injection sessions.",
                            Detail = $"Parent: {elecDir}"
                        });
                    }
                }
            }

            if (Directory.Exists(Downloads))
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(Downloads, "Electron*.exe")
                        .Concat(Directory.EnumerateFiles(Downloads, "Electron*.zip")))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        if (fn.Contains("executor", StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains("exploit", StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                            !fn.StartsWith("electron-", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Electron Executor Download: {fn}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fn,
                                Reason = "Electron cheat executor download artifact found in Downloads directory.",
                                Detail = $"Downloads: {Downloads}"
                            });
                        }
                    }
                }
                catch { }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckJJSploitArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var jjLocalApp = Path.Combine(LocalApp, "JJSploit");
            var jjAppData = Path.Combine(AppData, "JJSploit");

            foreach (var jjDir in new[] { jjLocalApp, jjAppData })
            {
                if (!Directory.Exists(jjDir)) continue;

                foreach (var exeName in new[] { "JJSploit.exe", "JJSploit_bootstrapper.exe" })
                {
                    var exePath = Path.Combine(jjDir, exeName);
                    ctx.IncrementFiles();
                    if (File.Exists(exePath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"JJSploit Executor Executable: {exeName}",
                            Risk = RiskLevel.High,
                            Location = exePath,
                            FileName = exeName,
                            Reason = "JJSploit free script executor executable found. JJSploit is a widely distributed free executor used to run Lua scripts in FiveM and Roblox.",
                            Detail = $"Directory: {jjDir}"
                        });
                    }
                }

                var logPath = Path.Combine(jjDir, "jjsploit_log.txt");
                ctx.IncrementFiles();
                if (File.Exists(logPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "JJSploit Log File",
                        Risk = RiskLevel.High,
                        Location = logPath,
                        FileName = "jjsploit_log.txt",
                        Reason = "JJSploit log file found, persisting executor session history after use.",
                        Detail = $"Directory: {jjDir}"
                    });
                }

                foreach (var subDir in new[] { "workspace", "scripts" })
                {
                    var subPath = Path.Combine(jjDir, subDir);
                    if (Directory.Exists(subPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"JJSploit {subDir} Directory",
                            Risk = RiskLevel.High,
                            Location = subPath,
                            FileName = subDir,
                            Reason = $"JJSploit executor '{subDir}' directory found, containing Lua scripts used during executor sessions.",
                            Detail = $"Parent: {jjDir}"
                        });
                    }
                }
            }

            if (Directory.Exists(Downloads))
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(Downloads, "JJSploit*.exe"))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"JJSploit Download: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "JJSploit executor download found in Downloads directory.",
                            Detail = $"Downloads: {Downloads}"
                        });
                    }
                }
                catch { }
            }

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\JJSploit");
                if (key is not null)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "JJSploit Registry Key Found",
                        Risk = RiskLevel.High,
                        Location = @"HKCU\Software\JJSploit",
                        Reason = "JJSploit registry key found, indicating installation or use of this free script executor.",
                        Detail = $"Values: {string.Join(", ", key.GetValueNames())}"
                    });
                }
            }
            catch { }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckCaesiumExecutorArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var caesAppData = Path.Combine(AppData, "Caesium");
            var caesLocalApp = Path.Combine(LocalApp, "Caesium");

            foreach (var caesDir in new[] { caesAppData, caesLocalApp })
            {
                if (!Directory.Exists(caesDir)) continue;

                var exePath = Path.Combine(caesDir, "Caesium.exe");
                ctx.IncrementFiles();
                if (File.Exists(exePath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Caesium Executor Executable",
                        Risk = RiskLevel.Critical,
                        Location = exePath,
                        FileName = "Caesium.exe",
                        Reason = "Caesium script executor executable found. Caesium is a script executor used to inject and run Lua scripts targeting FiveM servers.",
                        Detail = $"Directory: {caesDir}"
                    });
                }

                var dllPath = Path.Combine(caesDir, "CaesiumRE.dll");
                ctx.IncrementFiles();
                if (File.Exists(dllPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Caesium Injection DLL",
                        Risk = RiskLevel.Critical,
                        Location = dllPath,
                        FileName = "CaesiumRE.dll",
                        Reason = "Caesium executor DLL found. This is the injection payload that hooks into game processes for Lua execution.",
                        Detail = $"Directory: {caesDir}"
                    });
                }

                foreach (var subDir in new[] { "workspace", "autoexec" })
                {
                    var subPath = Path.Combine(caesDir, subDir);
                    if (Directory.Exists(subPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Caesium {subDir} Directory",
                            Risk = RiskLevel.Critical,
                            Location = subPath,
                            FileName = subDir,
                            Reason = $"Caesium executor '{subDir}' directory found, containing scripts used during Lua injection sessions.",
                            Detail = $"Parent: {caesDir}"
                        });
                    }
                }

                try
                {
                    foreach (var file in Directory.EnumerateFiles(caesDir, "*.json")
                        .Concat(Directory.EnumerateFiles(caesDir, "*.cfg"))
                        .Concat(Directory.EnumerateFiles(caesDir, "*.ini")))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Caesium Configuration File: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Caesium executor configuration file found, indicating active or prior installation of this script executor.",
                            Detail = $"Directory: {caesDir}"
                        });
                        break;
                    }
                }
                catch { }
            }

            if (Directory.Exists(Downloads))
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(Downloads, "Caesium*.zip"))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Caesium Executor Download: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Caesium executor archive found in Downloads directory.",
                            Detail = $"Downloads: {Downloads}"
                        });
                    }
                }
                catch { }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckOxygénExecutorArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var oxyAppData = Path.Combine(AppData, "Oxygen-U");
            var oxyLocalApp = Path.Combine(LocalApp, "Oxygen");

            foreach (var oxyDir in new[] { oxyAppData, oxyLocalApp })
            {
                if (!Directory.Exists(oxyDir)) continue;

                foreach (var exeName in new[] { "Oxygen.exe", "OxygenU.exe" })
                {
                    var exePath = Path.Combine(oxyDir, exeName);
                    ctx.IncrementFiles();
                    if (File.Exists(exePath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Oxygen Executor Executable: {exeName}",
                            Risk = RiskLevel.Critical,
                            Location = exePath,
                            FileName = exeName,
                            Reason = "Oxygen-U script executor executable found. Oxygen-U is a script executor used to inject Lua scripts into FiveM and Roblox environments.",
                            Detail = $"Directory: {oxyDir}"
                        });
                    }
                }

                var logPath = Path.Combine(oxyDir, "oxygen_log.txt");
                ctx.IncrementFiles();
                if (File.Exists(logPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Oxygen Executor Log File",
                        Risk = RiskLevel.Critical,
                        Location = logPath,
                        FileName = "oxygen_log.txt",
                        Reason = "Oxygen executor log file found, containing persistent session and injection history.",
                        Detail = $"Directory: {oxyDir}"
                    });
                }

                foreach (var subDir in new[] { "workspace", "scripts" })
                {
                    var subPath = Path.Combine(oxyDir, subDir);
                    if (Directory.Exists(subPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Oxygen Executor {subDir} Directory",
                            Risk = RiskLevel.Critical,
                            Location = subPath,
                            FileName = subDir,
                            Reason = $"Oxygen executor '{subDir}' directory found, containing Lua scripts used during injection sessions.",
                            Detail = $"Parent: {oxyDir}"
                        });
                    }
                }
            }

            if (Directory.Exists(Downloads))
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(Downloads, "Oxygen*.zip"))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Oxygen Executor Download: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Oxygen executor archive found in Downloads directory, indicating recent acquisition.",
                            Detail = $"Downloads: {Downloads}"
                        });
                    }
                }
                catch { }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckExecutorWorkspaceScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var searchRoots = new[] { Desktop, Downloads, Documents, Temp }
                .Where(d => !string.IsNullOrEmpty(d) && Directory.Exists(d))
                .ToArray();

            foreach (var root in searchRoots)
            {
                ct.ThrowIfCancellationRequested();
                string[] subdirs;
                try { subdirs = Directory.GetDirectories(root); }
                catch { continue; }

                foreach (var subdir in subdirs)
                {
                    ct.ThrowIfCancellationRequested();
                    var dirName = Path.GetFileName(subdir);
                    if (!dirName.Equals("workspace", StringComparison.OrdinalIgnoreCase) &&
                        !dirName.Equals("autoexec", StringComparison.OrdinalIgnoreCase) &&
                        !dirName.Equals("scripts", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string[] luaFiles;
                    try { luaFiles = Directory.GetFiles(subdir, "*.lua", SearchOption.AllDirectories); }
                    catch { continue; }

                    if (luaFiles.Length == 0) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Executor {dirName} Directory with Lua Scripts",
                        Risk = RiskLevel.Critical,
                        Location = subdir,
                        FileName = dirName,
                        Reason = $"'{dirName}' directory containing {luaFiles.Length} Lua file(s) found in {root}. Script executors store injected scripts in workspace/autoexec/scripts directories.",
                        Detail = $"Lua files: {luaFiles.Length} | Root: {root}"
                    });

                    foreach (var luaFile in luaFiles.Take(20))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            var hitKeywords = FiveMScriptKeywords
                                .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                                .ToList();

                            if (hitKeywords.Count > 0)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"FiveM-Targeted Lua Script in Executor Workspace: {Path.GetFileName(luaFile)}",
                                    Risk = RiskLevel.Critical,
                                    Location = luaFile,
                                    FileName = Path.GetFileName(luaFile),
                                    Reason = $"Lua script in executor workspace directory contains {hitKeywords.Count} FiveM-specific API call(s), indicating this script was written to target FiveM servers.",
                                    Detail = $"Matched FiveM APIs: {string.Join(", ", hitKeywords.Take(5))}"
                                });
                            }
                        }
                        catch { }
                    }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }, ct);

    private Task CheckExecutorLicenseKeyArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var searchDirs = new List<string>();
            foreach (var exDir in ExecutorInstallDirs)
            {
                var la = Path.Combine(LocalApp, exDir);
                var ad = Path.Combine(AppData, exDir);
                if (Directory.Exists(la)) searchDirs.Add(la);
                if (Directory.Exists(ad)) searchDirs.Add(ad);
            }
            if (Directory.Exists(Downloads)) searchDirs.Add(Downloads);

            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var licFileName in LicenseFileNames)
                {
                    var licPath = Path.Combine(dir, licFileName);
                    ctx.IncrementFiles();
                    if (!File.Exists(licPath)) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(licPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch { continue; }

                    var trimmed = content.Trim();
                    bool looksLikeKey = trimmed.Length >= 16 && trimmed.Length <= 128 &&
                        trimmed.All(c => char.IsLetterOrDigit(c) || c == '-' || c == '_' || c == '.' || c == ' ');

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Executor License Key File: {licFileName}",
                        Risk = RiskLevel.High,
                        Location = licPath,
                        FileName = licFileName,
                        Reason = $"Script executor license or activation key file '{licFileName}' found. This proves purchase or possession of a premium script executor product.",
                        Detail = looksLikeKey
                            ? $"Key pattern detected ({trimmed.Length} chars) in: {dir}"
                            : $"Directory: {dir}"
                    });
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }, ct);

    private Task CheckFiveMSpecificExecutorScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var searchDirs = new List<string>();
            foreach (var exDir in ExecutorInstallDirs)
            {
                foreach (var subDir in new[] { "workspace", "autoexec", "scripts" })
                {
                    var la = Path.Combine(LocalApp, exDir, subDir);
                    var ad = Path.Combine(AppData, exDir, subDir);
                    if (Directory.Exists(la)) searchDirs.Add(la);
                    if (Directory.Exists(ad)) searchDirs.Add(ad);
                }
            }
            foreach (var d in new[] { Desktop, Downloads, Documents })
            {
                if (Directory.Exists(d)) searchDirs.Add(d);
            }

            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                string[] luaFiles;
                try { luaFiles = Directory.GetFiles(dir, "*.lua", SearchOption.AllDirectories); }
                catch { continue; }

                foreach (var luaFile in luaFiles.Take(50))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        if (new FileInfo(luaFile).Length > 1024 * 1024) continue;

                        using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        var fivemHits = FiveMScriptKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        var exploitHits = FiveMExploitScriptKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (fivemHits.Count == 0) continue;

                        var risk = exploitHits.Count > 0 ? RiskLevel.Critical : RiskLevel.Critical;
                        var fn = Path.GetFileName(luaFile);

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM-Targeted Executor Script: {fn}",
                            Risk = risk,
                            Location = luaFile,
                            FileName = fn,
                            Reason = $"Lua script contains {fivemHits.Count} FiveM-specific API call(s)" +
                                (exploitHits.Count > 0 ? $" and {exploitHits.Count} exploit keyword(s)" : "") +
                                $", indicating it was written specifically to target FiveM server environments via a script executor.",
                            Detail = $"FiveM APIs: {string.Join(", ", fivemHits.Take(4))}" +
                                (exploitHits.Count > 0 ? $" | Exploit keywords: {string.Join(", ", exploitHits.Take(3))}" : "")
                        });
                    }
                    catch { }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }, ct);

    private Task CheckExecutorAutoexecScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var autoexecDirs = new List<string>();
            foreach (var exDir in ExecutorInstallDirs)
            {
                var la = Path.Combine(LocalApp, exDir, "autoexec");
                var ad = Path.Combine(AppData, exDir, "autoexec");
                if (Directory.Exists(la)) autoexecDirs.Add(la);
                if (Directory.Exists(ad)) autoexecDirs.Add(ad);
            }

            foreach (var searchRoot in new[] { Desktop, Downloads, Documents })
            {
                if (!Directory.Exists(searchRoot)) continue;
                try
                {
                    foreach (var subdir in Directory.GetDirectories(searchRoot))
                    {
                        var autoexecPath = Path.Combine(subdir, "autoexec");
                        if (Directory.Exists(autoexecPath))
                            autoexecDirs.Add(autoexecPath);
                    }
                }
                catch { }
            }

            foreach (var autoexecDir in autoexecDirs)
            {
                ct.ThrowIfCancellationRequested();
                string[] luaFiles;
                try { luaFiles = Directory.GetFiles(autoexecDir, "*.lua", SearchOption.AllDirectories); }
                catch { continue; }

                if (luaFiles.Length == 0) continue;

                foreach (var luaFile in luaFiles.Take(20))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        var cheatHits = AutoexecCheatKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        var fn = Path.GetFileName(luaFile);
                        if (cheatHits.Count > 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Autoexec Cheat Script: {fn}",
                                Risk = RiskLevel.Critical,
                                Location = luaFile,
                                FileName = fn,
                                Reason = $"Script executor autoexec Lua file contains {cheatHits.Count} cheat-related keyword(s). Autoexec scripts run automatically on injection, enabling persistent cheat activation.",
                                Detail = $"Cheat keywords: {string.Join(", ", cheatHits.Take(5))} | Directory: {autoexecDir}"
                            });
                        }
                        else
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Script Executor Autoexec Script: {fn}",
                                Risk = RiskLevel.Critical,
                                Location = luaFile,
                                FileName = fn,
                                Reason = "Lua script found in executor autoexec directory. Autoexec scripts are automatically executed upon injection into the game process.",
                                Detail = $"Directory: {autoexecDir}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }, ct);

    private Task CheckExecutorRegistryTraces(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            foreach (var regKey in ExecutorRegistryKeys)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(regKey);
                    if (key is null) continue;
                    ctx.IncrementRegistryKeys();
                    var displayName = regKey.Replace("Software\\", "", StringComparison.OrdinalIgnoreCase);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Script Executor Registry Key: {displayName}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKCU\{regKey}",
                        Reason = $"Registry key for script executor '{displayName}' found. This key is created during executor installation or configuration.",
                        Detail = $"Values: {string.Join(", ", key.GetValueNames().Take(5))}"
                    });
                }
                catch { }
            }

            try
            {
                using var runKey = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run");
                if (runKey is not null)
                {
                    ctx.IncrementRegistryKeys();
                    foreach (var valName in runKey.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var valData = runKey.GetValue(valName)?.ToString() ?? string.Empty;
                        var matched = ExecutorExeNames.FirstOrDefault(exe =>
                            valData.Contains(exe, StringComparison.OrdinalIgnoreCase) ||
                            valName.Contains(exe.Replace(".exe", "", StringComparison.OrdinalIgnoreCase),
                                StringComparison.OrdinalIgnoreCase));
                        if (matched is null)
                        {
                            matched = ExecutorInstallDirs.FirstOrDefault(dir =>
                                valData.Contains(dir, StringComparison.OrdinalIgnoreCase));
                        }
                        if (matched is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Script Executor Autostart Entry: {valName}",
                                Risk = RiskLevel.Critical,
                                Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                                FileName = valName,
                                Reason = $"Script executor '{matched}' is registered as an autostart entry in the Windows Run registry key, ensuring it launches automatically at user login.",
                                Detail = $"Value: {valName} = {valData.Length > 120 ? valData[..120] + "..." : valData}"
                            });
                        }
                    }
                }
            }
            catch { }

            try
            {
                using var mruKey = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU");
                if (mruKey is not null)
                {
                    ctx.IncrementRegistryKeys();
                    foreach (var valName in mruKey.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        if (valName.Equals("MRUList", StringComparison.OrdinalIgnoreCase)) continue;
                        var valData = mruKey.GetValue(valName)?.ToString() ?? string.Empty;
                        var matched = ExecutorExeNames.FirstOrDefault(exe =>
                            valData.Contains(exe, StringComparison.OrdinalIgnoreCase));
                        if (matched is null)
                        {
                            matched = ExecutorInstallDirs.FirstOrDefault(dir =>
                                valData.Contains(dir, StringComparison.OrdinalIgnoreCase));
                        }
                        if (matched is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Script Executor in Run MRU: {matched}",
                                Risk = RiskLevel.Critical,
                                Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                                Reason = $"Script executor '{matched}' path found in Run dialog MRU list, indicating the executor was launched via the Run dialog.",
                                Detail = $"MRU entry: {valData.Length > 120 ? valData[..120] + "..." : valData}"
                            });
                        }
                    }
                }
            }
            catch { }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckExecutorPrefetchArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var prefetchDir = Path.Combine("C:\\Windows", "Prefetch");
            if (Directory.Exists(prefetchDir))
            {
                var executorPrefetchPatterns = new[]
                {
                    ("KRNL", "KRNL"), ("KRNL_BOOTSTRAPPER", "KRNL"),
                    ("SYNAPSEX", "Synapse X"), ("S^X", "Synapse X"),
                    ("SENTINELLAUNCHER", "Sentinel"), ("SENTINEL", "Sentinel"),
                    ("SCRIPTWARE", "Script-Ware"), ("SCRIPT-WARE", "Script-Ware"),
                    ("ELECTRON", "Electron Executor"), ("ELECTRONEXECUTOR", "Electron Executor"),
                    ("JJSPLOIT", "JJSploit"),
                    ("CAESIUM", "Caesium"),
                    ("OXYGEN", "Oxygen-U"), ("OXYGENU", "Oxygen-U")
                };

                string[] pfFiles;
                try { pfFiles = Directory.GetFiles(prefetchDir, "*.pf"); }
                catch { pfFiles = Array.Empty<string>(); }

                foreach (var pfFile in pfFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var pfName = Path.GetFileNameWithoutExtension(pfFile).ToUpperInvariant();
                    var dashIdx = pfName.LastIndexOf('-');
                    var exePart = dashIdx > 0 && pfName.Length - dashIdx == 9 ? pfName[..dashIdx] : pfName;

                    foreach (var (pattern, executorName) in executorPrefetchPatterns)
                    {
                        if (!exePart.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                        DateTime lastWrite = default;
                        try { lastWrite = File.GetLastWriteTime(pfFile); } catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Executor Prefetch Artifact: {Path.GetFileName(pfFile)}",
                            Risk = RiskLevel.High,
                            Location = pfFile,
                            FileName = Path.GetFileName(pfFile),
                            Reason = $"Windows Prefetch entry for script executor '{executorName}' found. Prefetch files are created when an executable is run and persist after deletion, proving the executor was launched on this system.",
                            Detail = lastWrite != default
                                ? $"Executor: {executorName} | Last executed: {lastWrite:yyyy-MM-dd HH:mm:ss}"
                                : $"Executor: {executorName}"
                        });
                        break;
                    }
                }
            }

            try
            {
                using var uaKey = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
                if (uaKey is not null)
                {
                    ctx.IncrementRegistryKeys();
                    foreach (var subKeyName in uaKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var countKey = uaKey.OpenSubKey(Path.Combine(subKeyName, "Count"));
                            if (countKey is null) continue;
                            foreach (var valName in countKey.GetValueNames())
                            {
                                var decoded = DecodeRot13(valName);
                                var matched = ExecutorExeNames.FirstOrDefault(exe =>
                                    decoded.Contains(exe, StringComparison.OrdinalIgnoreCase));
                                if (matched is null)
                                {
                                    matched = ExecutorInstallDirs.FirstOrDefault(dir =>
                                        decoded.Contains(dir, StringComparison.OrdinalIgnoreCase));
                                }
                                if (matched is not null)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"Executor UserAssist Entry: {matched}",
                                        Risk = RiskLevel.High,
                                        Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                                        Reason = $"Script executor '{matched}' found in UserAssist registry, confirming it was launched by the user. UserAssist tracks GUI application launches with run counts.",
                                        Detail = $"Decoded path: {(decoded.Length > 120 ? decoded[..120] + "..." : decoded)}"
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckExecutorDLLArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var searchDirs = new List<string> { Temp };
            foreach (var exDir in ExecutorInstallDirs)
            {
                var la = Path.Combine(LocalApp, exDir);
                var ad = Path.Combine(AppData, exDir);
                if (Directory.Exists(la)) searchDirs.Add(la);
                if (Directory.Exists(ad)) searchDirs.Add(ad);
            }

            var fivemAppDir = Path.Combine(LocalApp, "FiveM", "FiveM.app");
            if (Directory.Exists(fivemAppDir)) searchDirs.Add(fivemAppDir);

            var windowsTempDir = Path.Combine("C:\\Windows", "Temp");
            if (Directory.Exists(windowsTempDir)) searchDirs.Add(windowsTempDir);

            foreach (var dir in searchDirs)
            {
                ct.ThrowIfCancellationRequested();
                string[] dllFiles;
                try { dllFiles = Directory.GetFiles(dir, "*.dll", SearchOption.AllDirectories); }
                catch { continue; }

                foreach (var dllFile in dllFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(dllFile);
                    var matched = ExecutorDLLNames.FirstOrDefault(dll =>
                        fn.Equals(dll, StringComparison.OrdinalIgnoreCase));
                    if (matched is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Script Executor DLL Artifact: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = dllFile,
                        FileName = fn,
                        Reason = $"Script executor injection DLL '{fn}' found. This DLL is injected into FiveM or game processes to enable Lua script execution and game API hooking.",
                        Detail = $"Directory: {dir}"
                    });
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckExecutorCrashDumps(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var fivemCrashDirs = new[]
            {
                Path.Combine(LocalApp, "FiveM", "FiveM.app", "crashes"),
                Path.Combine(AppData, "citizenfx", "FiveM", "FiveM.app", "crashes")
            };

            foreach (var crashDir in fivemCrashDirs)
            {
                if (!Directory.Exists(crashDir)) continue;
                string[] dmpFiles;
                try { dmpFiles = Directory.GetFiles(crashDir, "*.dmp"); }
                catch { continue; }

                foreach (var dmpFile in dmpFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        var fileInfo = new FileInfo(dmpFile);
                        if (fileInfo.Length < 64) continue;

                        using var fs = new FileStream(dmpFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        var header = new byte[Math.Min(512, (int)fileInfo.Length)];
                        int bytesRead = await fs.ReadAsync(header, 0, header.Length, ct);
                        var headerText = Encoding.ASCII.GetString(header, 0, bytesRead);

                        var matched = ExecutorExeNames.FirstOrDefault(exe =>
                            headerText.Contains(exe.Replace(".exe", "", StringComparison.OrdinalIgnoreCase),
                                StringComparison.OrdinalIgnoreCase));
                        if (matched is null)
                        {
                            matched = ExecutorInstallDirs.FirstOrDefault(dir =>
                                headerText.Contains(dir, StringComparison.OrdinalIgnoreCase));
                        }

                        if (matched is not null)
                        {
                            DateTime lastWrite = default;
                            try { lastWrite = File.GetLastWriteTime(dmpFile); } catch { }

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Executor Crash Dump in FiveM Crashes: {Path.GetFileName(dmpFile)}",
                                Risk = RiskLevel.High,
                                Location = dmpFile,
                                FileName = Path.GetFileName(dmpFile),
                                Reason = $"FiveM crash dump appears to reference script executor '{matched}' in its header. Executors commonly crash FiveM when the anti-cheat detects and terminates them.",
                                Detail = lastWrite != default
                                    ? $"Executor: {matched} | Crash date: {lastWrite:yyyy-MM-dd HH:mm:ss}"
                                    : $"Executor: {matched}"
                            });
                        }
                    }
                    catch { }
                }
            }

            var werArchiveDir = Path.Combine(AppData, "Microsoft", "Windows", "WER", "ReportArchive");
            if (Directory.Exists(werArchiveDir))
            {
                try
                {
                    foreach (var reportDir in Directory.GetDirectories(werArchiveDir))
                    {
                        ct.ThrowIfCancellationRequested();
                        var reportDirName = Path.GetFileName(reportDir);
                        var matched = ExecutorExeNames.FirstOrDefault(exe =>
                            reportDirName.Contains(exe.Replace(".exe", "", StringComparison.OrdinalIgnoreCase),
                                StringComparison.OrdinalIgnoreCase));

                        if (matched is not null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Executor WER Crash Report: {reportDirName}",
                                Risk = RiskLevel.High,
                                Location = reportDir,
                                FileName = reportDirName,
                                Reason = $"Windows Error Reporting crash report folder found for script executor '{matched}'. WER crash reports survive process and file deletion, providing forensic evidence of executor execution and crash events.",
                                Detail = $"WER Archive: {werArchiveDir}"
                            });
                        }
                    }
                }
                catch { }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }, ct);

    private Task CheckScriptRepositoryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var chromiumHistoryPaths = new List<string>();
            var profileBases = new[]
            {
                Path.Combine(LocalApp, "Google", "Chrome", "User Data"),
                Path.Combine(LocalApp, "Microsoft", "Edge", "User Data"),
                Path.Combine(LocalApp, "BraveSoftware", "Brave-Browser", "User Data"),
                Path.Combine(AppData, "Opera Software", "Opera Stable")
            };

            foreach (var profileBase in profileBases)
            {
                if (!Directory.Exists(profileBase)) continue;
                var defaultHistory = Path.Combine(profileBase, "Default", "History");
                if (File.Exists(defaultHistory)) chromiumHistoryPaths.Add(defaultHistory);
                try
                {
                    foreach (var dir in Directory.GetDirectories(profileBase, "Profile*"))
                    {
                        var ph = Path.Combine(dir, "History");
                        if (File.Exists(ph)) chromiumHistoryPaths.Add(ph);
                    }
                }
                catch { }
            }

            foreach (var historyDb in chromiumHistoryPaths)
            {
                ct.ThrowIfCancellationRequested();
                var tempCopy = Path.Combine(
                    Path.GetTempPath(),
                    $"zt_hist_{Path.GetRandomFileName()}.tmp");
                try
                {
                    File.Copy(historyDb, tempCopy, overwrite: true);
                    ctx.IncrementFiles();

                    using var fs = new FileStream(tempCopy, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var site in ScriptRepoSites)
                    {
                        if (!content.Contains(site, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Script Repository Site in Browser History: {site}",
                            Risk = RiskLevel.High,
                            Location = historyDb,
                            Reason = $"Browser history contains visits to '{site}', a known FiveM/Roblox Lua script repository or hosting site. Cheaters commonly source executor scripts from these sites.",
                            Detail = $"Site: {site} | History: {historyDb}"
                        });
                    }
                }
                catch { }
                finally
                {
                    try { if (File.Exists(tempCopy)) File.Delete(tempCopy); } catch { }
                }
            }

            foreach (var searchDir in new[] { Downloads, Documents, Desktop })
            {
                if (!Directory.Exists(searchDir)) continue;
                string[] txtFiles;
                try { txtFiles = Directory.GetFiles(searchDir, "*.txt", SearchOption.TopDirectoryOnly); }
                catch { continue; }

                foreach (var txtFile in txtFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        if (new FileInfo(txtFile).Length > 512 * 1024) continue;

                        using var fs = new FileStream(txtFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        var fivemHits = FiveMScriptKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (fivemHits.Count >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Text File with FiveM Lua Code: {Path.GetFileName(txtFile)}",
                                Risk = RiskLevel.High,
                                Location = txtFile,
                                FileName = Path.GetFileName(txtFile),
                                Reason = $"Text file in user directory contains {fivemHits.Count} FiveM Lua API references, suggesting it is a script downloaded from a script repository site.",
                                Detail = $"FiveM APIs found: {string.Join(", ", fivemHits.Take(4))}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }, ct);

    private Task CheckExecutorBrowserHistoryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            var chromiumProfiles = new List<(string browser, string historyPath)>();
            var browserBases = new[]
            {
                ("Chrome", Path.Combine(LocalApp, "Google", "Chrome", "User Data")),
                ("Edge", Path.Combine(LocalApp, "Microsoft", "Edge", "User Data")),
                ("Brave", Path.Combine(LocalApp, "BraveSoftware", "Brave-Browser", "User Data")),
                ("Opera", Path.Combine(AppData, "Opera Software", "Opera Stable")),
                ("Vivaldi", Path.Combine(LocalApp, "Vivaldi", "User Data"))
            };

            foreach (var (browserName, basePath) in browserBases)
            {
                if (!Directory.Exists(basePath)) continue;
                var defaultHistory = Path.Combine(basePath, "Default", "History");
                if (File.Exists(defaultHistory)) chromiumProfiles.Add((browserName, defaultHistory));
                try
                {
                    foreach (var dir in Directory.GetDirectories(basePath, "Profile*"))
                    {
                        var ph = Path.Combine(dir, "History");
                        if (File.Exists(ph)) chromiumProfiles.Add((browserName, ph));
                    }
                }
                catch { }
            }

            var firefoxProfiles = new List<string>();
            var ffProfileBase = Path.Combine(AppData, "Mozilla", "Firefox", "Profiles");
            if (Directory.Exists(ffProfileBase))
            {
                try
                {
                    foreach (var dir in Directory.GetDirectories(ffProfileBase))
                    {
                        var ph = Path.Combine(dir, "places.sqlite");
                        if (File.Exists(ph)) firefoxProfiles.Add(ph);
                    }
                }
                catch { }
            }

            var allHistoryFiles = chromiumProfiles
                .Select(p => (p.browser, p.historyPath))
                .Concat(firefoxProfiles.Select(p => ("Firefox", p)))
                .ToList();

            foreach (var (browserName, historyPath) in allHistoryFiles)
            {
                ct.ThrowIfCancellationRequested();
                var tempCopy = Path.Combine(
                    Path.GetTempPath(),
                    $"zt_bh_{Path.GetRandomFileName()}.tmp");
                try
                {
                    File.Copy(historyPath, tempCopy, overwrite: true);
                    ctx.IncrementFiles();

                    using var fs = new FileStream(tempCopy, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var domain in ExecutorWebDomains)
                    {
                        if (!content.Contains(domain, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Script Executor Site in Browser History: {domain}",
                            Risk = RiskLevel.High,
                            Location = historyPath,
                            Reason = $"Browser history ({browserName}) contains visits to '{domain}', the official website of a known FiveM/Roblox script executor. This indicates active research or acquisition of this cheat tool.",
                            Detail = $"Domain: {domain} | Browser: {browserName} | History: {historyPath}"
                        });
                    }

                    foreach (var site in ScriptRepoSites)
                    {
                        if (!content.Contains(site, StringComparison.OrdinalIgnoreCase)) continue;

                        bool hasLuaContext = content.Contains("lua", StringComparison.OrdinalIgnoreCase) &&
                            content.IndexOf(site, StringComparison.OrdinalIgnoreCase) >= 0;

                        if (!hasLuaContext) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Script Repository Visited: {site}",
                            Risk = RiskLevel.High,
                            Location = historyPath,
                            Reason = $"Browser history ({browserName}) shows visits to '{site}' in a Lua script context. This site is used for hosting and sharing FiveM executor scripts.",
                            Detail = $"Site: {site} | Browser: {browserName}"
                        });
                    }
                }
                catch { }
                finally
                {
                    try { if (File.Exists(tempCopy)) File.Delete(tempCopy); } catch { }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }, ct);

    private static string DecodeRot13(string input)
    {
        var sb = new StringBuilder(input.Length);
        foreach (char c in input)
        {
            if (c >= 'a' && c <= 'z')
                sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else if (c >= 'A' && c <= 'Z')
                sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else
                sb.Append(c);
        }
        return sb.ToString();
    }
}
