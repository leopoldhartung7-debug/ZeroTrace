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

public sealed class RootKitUserModeArtifactScanModule : IScanModule
{
    public string Name => "User-Mode Rootkit Artifact Detection";
    public double Weight => 4.6;
    public int ParallelGroup => 3;

    private static readonly string[] KnownRootkitExeNames =
    [
        "rootkit.exe", "usermode_rootkit.exe", "r3_rootkit.exe",
        "ring3_rootkit.exe", "ring3rootkit.exe", "user_rootkit.exe",
        "process_hider.exe", "proc_hider.exe", "pid_hider.exe",
        "dll_hider.exe", "file_hider.exe", "network_hider.exe",
        "connection_hider.exe", "port_hider.exe", "registry_hider.exe",
        "reg_hider.exe", "thread_hider.exe", "handle_hider.exe",
        "module_hider.exe", "driver_hider.exe", "service_hider.exe",
        "inject_rootkit.exe", "rootkit_inject.exe", "rootkit_loader.exe",
        "rootkit_patcher.exe", "rootkit_installer.exe",
        "stealth_process.exe", "hidden_process.exe", "invisible_process.exe",
        "ghost_process.exe", "phantom_process.exe", "shadow_process.exe",
        "process_cloak.exe", "process_mask.exe", "process_spoof.exe",
        "procmon_bypass.exe", "procexp_bypass.exe", "task_manager_bypass.exe",
        "taskman_bypass.exe", "taskmgr_bypass.exe",
        "hook_engine.exe", "hook_framework.exe", "hook_library.exe",
        "api_hook.exe", "iat_hook.exe", "eat_hook.exe",
        "inline_hook.exe", "detour_hook.exe", "hook_patcher.exe",
        "ntapi_hook.exe", "syscall_hook.exe", "syscall_redirect.exe",
        "heap_encrypt.exe", "memory_encrypt.exe", "string_encrypt.exe",
        "string_obfuscate.exe", "pe_obfuscate.exe", "pe_morph.exe",
        "metamorphic.exe", "polymorphic.exe",
    ];

    private static readonly string[] KnownRootkitDllNames =
    [
        "rootkit.dll", "usermode_rootkit.dll", "r3_rootkit.dll",
        "ring3_rootkit.dll", "process_hider.dll", "pid_hider.dll",
        "dll_hider.dll", "file_hider.dll", "network_hider.dll",
        "registry_hider.dll", "thread_hider.dll", "handle_hider.dll",
        "module_hider.dll", "hook_engine.dll", "hook_framework.dll",
        "hook_library.dll", "api_hook.dll", "iat_hook.dll",
        "eat_hook.dll", "inline_hook.dll", "detour_hook.dll",
        "minhook.dll", "minhook32.dll", "minhook64.dll",
        "deviare.dll", "deviare32.dll", "deviare64.dll",
        "easyhook.dll", "easyhook32.dll", "easyhook64.dll",
        "polyhook.dll", "polyhook2.dll",
        "ntapi_hook.dll", "syscall_hook.dll", "syscall_redirect.dll",
        "stealth_process.dll", "hidden_process.dll", "ghost_process.dll",
        "phantom_process.dll", "shadow_process.dll", "process_cloak.dll",
        "process_mask.dll", "process_spoof.dll",
        "heap_encrypt.dll", "memory_encrypt.dll", "string_encrypt.dll",
        "pe_obfuscate.dll", "pe_morph.dll", "metamorphic.dll",
    ];

    private static readonly string[] HookFrameworkDirNames =
    [
        "minhook", "min_hook", "polyhook", "poly_hook",
        "easyhook", "easy_hook", "deviare", "deviare_hook",
        "hook_engine", "hook_framework", "hook_library",
        "api_hook", "iat_hook", "eat_hook", "inline_hook",
        "detour", "detour_hook", "microsoft_detours",
        "ntapi_hook", "syscall_hook", "ring3_rootkit",
        "usermode_rootkit", "r3_rootkit", "process_hider",
        "dll_hider", "file_hider", "stealth_lib",
        "ghost_lib", "phantom_lib", "shadow_lib",
    ];

    private static readonly string[] RootkitConfigKeywords =
    [
        "hide_process", "hide_pid", "hide_dll", "hide_file",
        "hide_network", "hide_connection", "hide_port",
        "hide_registry", "hide_thread", "hide_handle",
        "hide_module", "hide_driver", "hide_service",
        "process_hide", "pid_hide", "dll_hide", "file_hide",
        "network_hide", "connection_hide", "port_hide",
        "registry_hide", "thread_hide", "handle_hide",
        "module_hide", "driver_hide", "service_hide",
        "hook_api", "hook_iat", "hook_eat", "hook_inline",
        "hook_syscall", "hook_ntapi", "hook_ntdll",
        "syscall_redirect", "syscall_hook", "nt_hook",
        "rootkit_mode", "stealth_mode", "invisible_mode",
        "ghost_mode", "phantom_mode", "shadow_mode",
        "procmon_bypass", "procexp_bypass", "taskmgr_bypass",
        "process_monitor_bypass", "process_explorer_bypass",
        "evasion_mode", "detection_bypass", "scan_bypass",
        "heap_encrypt", "memory_encrypt", "string_obfuscate",
        "pe_morph", "metamorphic_code", "polymorphic_code",
    ];

    private static readonly string[] AppInitDllHijackIndicators =
    [
        "bypass", "hook", "cheat", "hack", "inject", "rootkit",
        "stealth", "hidden", "ghost", "phantom", "shadow",
        "loader", "payload", "exploit", "patch", "spoof",
    ];

    private static readonly string[] UserDirs;

    static RootKitUserModeArtifactScanModule()
    {
        var dirs = new List<string>();
        string? profile = Environment.GetEnvironmentVariable("USERPROFILE");
        string? appData = Environment.GetEnvironmentVariable("APPDATA");
        string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        string? temp = Environment.GetEnvironmentVariable("TEMP");
        string? desktop = profile != null ? Path.Combine(profile, "Desktop") : null;
        string? downloads = profile != null ? Path.Combine(profile, "Downloads") : null;
        string? documents = profile != null ? Path.Combine(profile, "Documents") : null;

        foreach (var d in new[] { appData, localAppData, temp, desktop, downloads, documents })
            if (d != null) dirs.Add(d);

        UserDirs = [.. dirs];
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            ScanForRootkitExes(ctx, ct),
            ScanForRootkitDlls(ctx, ct),
            ScanForHookFrameworkDirs(ctx, ct),
            ScanConfigsForRootkitKeywords(ctx, ct),
            CheckAppInitDllHijack(ctx, ct),
            CheckLsaPluginHijack(ctx, ct),
            CheckWindowsMessageFilterHijack(ctx, ct),
            CheckShellHijackKeys(ctx, ct),
            CheckSuspiciousLoadedDlls(ctx, ct),
            ScanMuiCacheForRootkitTools(ctx, ct)
        ).ConfigureAwait(false);
    }

    private Task ScanForRootkitExes(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string rkExe in KnownRootkitExeNames)
                        {
                            if (fn.Equals(rkExe, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "User-Mode Rootkit Executable Found",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known user-mode rootkit/process hider tool detected",
                                    Detail = $"Rootkit tool '{fn}' found at: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanForRootkitDlls(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string rkDll in KnownRootkitDllNames)
                        {
                            if (fn.Equals(rkDll, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "User-Mode Rootkit/Hook DLL Found",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known user-mode rootkit/API hook library found in user directory",
                                    Detail = $"Rootkit DLL '{fn}' found at: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanForHookFrameworkDirs(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string dir in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string dn = Path.GetFileName(dir);
                        foreach (string rkDir in HookFrameworkDirNames)
                        {
                            if (dn.Equals(rkDir, StringComparison.OrdinalIgnoreCase)
                                || dn.Contains(rkDir, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Hook Framework / Rootkit Directory Found",
                                    Risk = Risk.High,
                                    Location = dir,
                                    FileName = dn,
                                    Reason = $"Directory '{dn}' matches known API hook/rootkit framework pattern",
                                    Detail = $"Hook framework directory: {dir}"
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

    private Task ScanConfigsForRootkitKeywords(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string ext = Path.GetExtension(file).ToLowerInvariant();
                        if (ext != ".json" && ext != ".cfg" && ext != ".ini" && ext != ".txt"
                            && ext != ".yaml" && ext != ".toml") continue;
                        if (new FileInfo(file).Length > 500_000) continue;

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            foreach (string kw in RootkitConfigKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "User-Mode Rootkit Config Keyword Found",
                                        Risk = Risk.High,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Config file contains rootkit/hiding keyword: '{kw}'",
                                        Detail = $"Rootkit config: {file}"
                                    });
                                    ctx.IncrementFiles();
                                    break;
                                }
                            }
                        }
                        catch (IOException) { }
                        catch (UnauthorizedAccessException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckAppInitDllHijack(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string[] appInitKeys =
            [
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                @"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
            ];

            foreach (string keyPath in appInitKeys)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(keyPath);
                    if (key == null) continue;

                    string? appInitDlls = key.GetValue("AppInit_DLLs") as string;
                    if (!string.IsNullOrWhiteSpace(appInitDlls))
                    {
                        object? loadAppInit = key.GetValue("LoadAppInit_DLLs");
                        bool isEnabled = loadAppInit is int loadInt && loadInt != 0;

                        if (isEnabled)
                        {
                            foreach (string indicator in AppInitDllHijackIndicators)
                            {
                                if (appInitDlls.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "AppInit_DLLs Contains Suspicious Hook/Cheat DLL",
                                        Risk = Risk.Critical,
                                        Location = $@"HKLM\{keyPath}",
                                        FileName = "registry",
                                        Reason = $"AppInit_DLLs has suspicious keyword '{indicator}' — DLL is injected into every process",
                                        Detail = $"AppInit_DLLs = '{appInitDlls}'"
                                    });
                                    ctx.IncrementRegistryKeys();
                                    break;
                                }
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckLsaPluginHijack(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using RegistryKey? lsaKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Lsa");
                if (lsaKey == null) return;

                object? authPkg = lsaKey.GetValue("Authentication Packages");
                if (authPkg is string[] authPkgArr)
                {
                    foreach (string pkg in authPkgArr)
                    {
                        ct.ThrowIfCancellationRequested();
                        if (string.IsNullOrWhiteSpace(pkg)) continue;
                        foreach (string indicator in AppInitDllHijackIndicators)
                        {
                            if (pkg.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Suspicious LSA Authentication Package Registered",
                                    Risk = Risk.Critical,
                                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                                    FileName = "registry",
                                    Reason = $"LSA authentication package '{pkg}' contains suspicious keyword '{indicator}'",
                                    Detail = $"LSA Auth Package: {pkg} — this DLL is loaded by lsass.exe"
                                });
                                ctx.IncrementRegistryKeys();
                                break;
                            }
                        }
                    }
                }

                object? notifPkg = lsaKey.GetValue("Notification Packages");
                if (notifPkg is string[] notifArr)
                {
                    foreach (string pkg in notifArr)
                    {
                        ct.ThrowIfCancellationRequested();
                        if (string.IsNullOrWhiteSpace(pkg)) continue;
                        foreach (string indicator in AppInitDllHijackIndicators)
                        {
                            if (pkg.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Suspicious LSA Notification Package Registered",
                                    Risk = Risk.Critical,
                                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                                    FileName = "registry",
                                    Reason = $"LSA notification package '{pkg}' contains suspicious keyword '{indicator}'",
                                    Detail = $"LSA Notification Package: {pkg}"
                                });
                                ctx.IncrementRegistryKeys();
                                break;
                            }
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task CheckWindowsMessageFilterHijack(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using RegistryKey? whKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows");
                if (whKey == null) return;

                object? userFonts = whKey.GetValue("AppInit_DLLs");
                if (userFonts is string userFontsStr && !string.IsNullOrWhiteSpace(userFontsStr))
                {
                    foreach (string rkDll in KnownRootkitDllNames)
                    {
                        ct.ThrowIfCancellationRequested();
                        if (userFontsStr.Contains(rkDll, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Known Rootkit DLL in AppInit_DLLs",
                                Risk = Risk.Critical,
                                Location = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                                FileName = "registry",
                                Reason = $"Known rootkit DLL '{rkDll}' registered in AppInit_DLLs",
                                Detail = $"AppInit_DLLs = '{userFontsStr}'"
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

    private Task CheckShellHijackKeys(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string[] shellHijackKeys =
            [
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            ];

            string[] shellHijackValues =
            [
                "Shell", "Userinit", "UIHost",
            ];

            string[] expectedShellValues =
            [
                "explorer.exe",
                "userinit.exe,",
                "logonui.exe",
            ];

            foreach (string keyPath in shellHijackKeys)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(keyPath);
                    if (key == null) continue;

                    foreach (string valName in shellHijackValues)
                    {
                        string? valData = key.GetValue(valName) as string;
                        if (string.IsNullOrWhiteSpace(valData)) continue;

                        bool isExpected = expectedShellValues.Any(e =>
                            valData.Contains(e, StringComparison.OrdinalIgnoreCase));

                        if (!isExpected)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Winlogon '{valName}' Value Hijacked",
                                Risk = Risk.Critical,
                                Location = $@"HKLM\{keyPath}",
                                FileName = "registry",
                                Reason = $"Winlogon '{valName}' set to unexpected value — rootkit persistence technique",
                                Detail = $"Winlogon {valName} = '{valData}'"
                            });
                            ctx.IncrementRegistryKeys();
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckSuspiciousLoadedDlls(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string system32 = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");

            foreach (string rkDll in KnownRootkitDllNames)
            {
                ct.ThrowIfCancellationRequested();
                string dllPath = Path.Combine(system32, rkDll);
                if (File.Exists(dllPath))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "User-Mode Rootkit DLL Found in System32",
                        Risk = Risk.Critical,
                        Location = dllPath,
                        FileName = rkDll,
                        Reason = "Known rootkit/hook DLL found in System32 — persistence installation detected",
                        Detail = $"Rootkit DLL installed in System32: {dllPath}"
                    });
                    ctx.IncrementFiles();
                }
            }

            string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (localAppData != null)
            {
                string tempDir = Path.Combine(localAppData, "Temp");
                if (Directory.Exists(tempDir))
                {
                    try
                    {
                        foreach (string file in Directory.EnumerateFiles(tempDir, "*.dll", SearchOption.AllDirectories))
                        {
                            ct.ThrowIfCancellationRequested();
                            string fn = Path.GetFileName(file);
                            foreach (string rkDll in KnownRootkitDllNames)
                            {
                                if (fn.Equals(rkDll, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Rootkit DLL Staged in Temp Directory",
                                        Risk = Risk.Critical,
                                        Location = file,
                                        FileName = fn,
                                        Reason = "Rootkit DLL found staged in Local\\Temp — pre-injection staging",
                                        Detail = $"Staged rootkit DLL: {file}"
                                    });
                                    ctx.IncrementFiles();
                                    break;
                                }
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
        }, ct);
    }

    private Task ScanMuiCacheForRootkitTools(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using RegistryKey? muiCache = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
                if (muiCache == null) return;

                foreach (string valName in muiCache.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (string rkExe in KnownRootkitExeNames)
                    {
                        if (valName.Contains(rkExe, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "User-Mode Rootkit Tool Execution Evidence in MUICache",
                                Risk = Risk.Critical,
                                Location = @"HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                                FileName = "registry",
                                Reason = "MUICache records previous execution of rootkit/process hider tool",
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
