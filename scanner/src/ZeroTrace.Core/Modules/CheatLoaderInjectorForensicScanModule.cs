using System.Runtime.Versioning;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class CheatLoaderInjectorForensicScanModule : IScanModule
{
    public string Name => "Cheat Loader / Injector Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] KnownInjectorNames =
    [
        "injector", "inject", "loader", "load", "dropper", "drop",
        "launcher", "launch", "executor", "execute", "runner", "run",
        "kiddion_injector", "eulen_injector", "2take1_injector",
        "stand_injector", "cherax_injector", "outbreak_injector",
        "impulse_injector", "fivem_injector", "gta_injector",
        "gtav_injector", "dll_injector", "dll_loader", "dll_inject",
        "process_injector", "proc_injector", "meminjector",
        "remoteinjector", "remote_inject", "shellcode_injector",
        "reflective_loader", "reflective_inject", "manual_mapper",
        "manualmapper", "manual_map", "manualmap",
        "kernelinjector", "kernel_inject", "driver_inject",
        "um_injector", "um_inject", "usermode_inject",
        "xenos", "extreme_injector", "extreme injector",
        "process_hacker", "cheat_engine", "cheatengine",
        "artmoney", "tsearch", "scanmem",
        "themida_unpack", "vmprotect_unpack", "asprotect_unpack",
    ];

    private static readonly string[] CheatEngineArtifacts =
    [
        "cheatengine-x86_64.exe", "cheatengine-i386.exe", "cheatengine.exe",
        "cheat engine", "cheatengine", "ce.exe",
        "artmoney", "l337games", "gamehack",
    ];

    private static readonly string[] BypassDriverNames =
    [
        "iqvw64e", "dbutil_2_3", "mhyprot2", "rtcore64", "gdrv",
        "winring0x64", "winring0", "rzpnk", "cpuz141_x64", "kprocesshacker",
        "physmem", "rawdisk64", "procexp152", "procexp", "pmdrvr",
        "speedfan", "asmmap64", "gmer", "ntiolib_x64", "winio64",
        "inpout32", "drvsupport", "msio64", "msio32", "lha",
        "driver7", "driver8", "novac", "nicm", "namedpipeserver",
        "capcomdrv", "capcom", "zamane", "sysdrv3s",
        "nvoclock", "sandra", "atillk64", "atillk",
    ];

    private static readonly string[] InjectionTechniqueKeywords =
    [
        "createremotethread", "virtualallocex", "writeprocessmemory",
        "readprocessmemory", "openprocess", "loadlibrary", "getprocaddress",
        "ntcreatethread", "ntwritevirtualmemory", "ntmapviewofsection",
        "setthreadcontext", "getthreadcontext", "suspendthread",
        "resumethread", "rtlcreateuserthread", "process_hollow",
        "processhollow", "process hollowing", "reflective dll",
        "reflective_dll", "manual map", "manual_map", "manualmapping",
        "thread hijack", "threadhijack", "apc inject", "apc_inject",
        "apcinjection", "atombombing", "atom bombing", "com hijack",
        "comhijack", "dll search order", "dll_hijack", "dllhijack",
        "setwindowshookex", "hook injection", "hook_inject",
        "kernel callback", "kernelcallback", "dkm_notify",
        "patchguard bypass", "dse bypass", "driver signing",
    ];

    private static readonly string[] KernelBypassIndicators =
    [
        "dse_bypass", "testsigning", "bcdedit", "nointegritychecks",
        "bootdebug", "nt!pspnotifyroutines", "patchguard", "pg_bypass",
        "kpp_bypass", "kpatch", "kpatchguard", "hypervisor",
        "hv_bypass", "kdnet", "windbg", "kd_disable",
        "secureboot_bypass", "uefi_bypass", "tpm_bypass",
    ];

    private static readonly string[] WERCrashPatterns =
    [
        "access violation", "stack overflow", "heap corruption",
        "invalid handle", "invalid parameter", "buffer overrun",
        "write protected", "write to readonly",
    ];

    private static readonly string[] CheatKeywords =
    [
        "cheat", "hack", "inject", "bypass", "spoof", "aimbot",
        "esp", "wallhack", "triggerbot", "speedhack", "noclip",
        "godmode", "modmenu", "trainer", "exploit",
        "kiddion", "eulen", "2take1", "stand", "cherax",
        "outbreak", "impulse", "nightfall", "emperor",
    ];

    private static readonly string[] ProcessHollowingIndicators =
    [
        "zwunmapviewofsection", "ntallocatevirtualmemory",
        "ntwritevirtualmemory", "zwresumepthread", "setthreadcontext",
        "ntresumethread", "createprocess suspended",
        "create_suspended", "process_creation_flags",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckInjectorToolArtifacts(ctx, ct),
            CheckCheatEngineArtifacts(ctx, ct),
            CheckByovdDriverHistory(ctx, ct),
            CheckWERCrashDumpsForInjection(ctx, ct),
            CheckMiniDumpInjectionArtifacts(ctx, ct),
            CheckPrefetchInjectorArtifacts(ctx, ct),
            CheckReflectiveDllArtifacts(ctx, ct),
            CheckKernelBypassArtifacts(ctx, ct),
            CheckDSEBypassArtifacts(ctx, ct),
            CheckInjectorRegistryArtifacts(ctx, ct),
            CheckManualMapArtifacts(ctx, ct),
            CheckDllSearchOrderHijackArtifacts(ctx, ct),
            CheckKernelDriverLoadHistory(ctx, ct),
            CheckCheatEngineRegistryArtifacts(ctx, ct),
            CheckLoadedModuleArtifacts(ctx, ct),
            CheckCodeCaveArtifacts(ctx, ct),
            CheckAppCompatLayerInjection(ctx, ct),
            CheckProcessDumpArtifacts(ctx, ct)
        );
    }

    private Task CheckInjectorToolArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var searchPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            Path.GetTempPath(),
            @"C:\",
        };

        foreach (var root in searchPaths)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    if (ext is not (".exe" or ".dll" or ".sys" or ".drv")) continue;
                    foreach (var injName in KnownInjectorNames)
                    {
                        if (name.Contains(injName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Injector Tool: Known DLL Injector Artifact",
                                Risk = RiskLevel.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Known injector tool name '{injName}' found — used to inject cheat DLLs into game process",
                                Detail = $"Path: {file}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
        return Task.CompletedTask;
    }, ct);

    private Task CheckCheatEngineArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };
        using var hklm = Registry.LocalMachine;
        using var hkcu = Registry.CurrentUser;

        foreach (var hive in new[] { hklm, hkcu })
        {
            foreach (var uninstallPath in uninstallPaths)
            {
                try
                {
                    using var uninstallKey = hive.OpenSubKey(uninstallPath);
                    if (uninstallKey == null) continue;
                    foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var appKey = uninstallKey.OpenSubKey(subKeyName);
                            if (appKey == null) continue;
                            ctx.IncrementRegistryKeys();
                            var displayName = appKey.GetValue("DisplayName")?.ToString() ?? string.Empty;
                            foreach (var ce in CheatEngineArtifacts)
                            {
                                if (displayName.Contains(ce, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name, Title = "Cheat Engine: Memory Editor Installed",
                                        Risk = RiskLevel.Critical,
                                        Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                        FileName = displayName,
                                        Reason = $"Cheat Engine / memory editor '{displayName}' installed — used to hack game memory",
                                        Detail = $"Install date: {appKey.GetValue("InstallDate") ?? "unknown"}"
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }

        var prefetchPath = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchPath)) return Task.CompletedTask;
        try
        {
            foreach (var pf in Directory.EnumerateFiles(prefetchPath, "*.pf"))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var pfName = Path.GetFileNameWithoutExtension(pf).ToLowerInvariant();
                foreach (var ce in CheatEngineArtifacts)
                {
                    if (pfName.Contains(ce.Replace(" ", ""), StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Cheat Engine: Execution Prefetch Entry",
                            Risk = RiskLevel.Critical, Location = pf,
                            FileName = Path.GetFileName(pf),
                            Reason = $"Cheat Engine execution prefetch '{pfName}' — confirms Cheat Engine was run",
                            Detail = $"Prefetch: {pf}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
        return Task.CompletedTask;
    }, ct);

    private Task CheckByovdDriverHistory(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var servicesPath = @"SYSTEM\CurrentControlSet\Services";

        try
        {
            using var servicesKey = hklm.OpenSubKey(servicesPath);
            if (servicesKey == null) return Task.CompletedTask;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                foreach (var driverName in BypassDriverNames)
                {
                    if (svcName.Equals(driverName, StringComparison.OrdinalIgnoreCase) ||
                        svcName.Contains(driverName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementRegistryKeys();
                        try
                        {
                            using var svcKey = servicesKey.OpenSubKey(svcName);
                            var imagePath = svcKey?.GetValue("ImagePath")?.ToString() ?? string.Empty;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "BYOVD Service: Vulnerable Driver Service Entry",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{servicesPath}\{svcName}",
                                FileName = svcName,
                                Reason = $"Known BYOVD (Bring Your Own Vulnerable Driver) service '{svcName}' in registry — used to disable kernel protections",
                                Detail = $"ImagePath: {imagePath}"
                            });
                        }
                        catch
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "BYOVD Service: Vulnerable Driver Service Entry",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{servicesPath}\{svcName}",
                                FileName = svcName,
                                Reason = $"Known BYOVD driver service '{svcName}' in registry",
                                Detail = $"Service key: {svcName}"
                            });
                        }
                        break;
                    }
                }
            }
        }
        catch { }

        var driversDir = @"C:\Windows\System32\drivers";
        if (!Directory.Exists(driversDir)) return Task.CompletedTask;
        try
        {
            foreach (var sysFile in Directory.EnumerateFiles(driversDir, "*.sys"))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var sysName = Path.GetFileNameWithoutExtension(sysFile).ToLowerInvariant();
                foreach (var driverName in BypassDriverNames)
                {
                    if (sysName.Equals(driverName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "BYOVD Driver: Vulnerable Driver File in System32",
                            Risk = RiskLevel.Critical, Location = sysFile,
                            FileName = Path.GetFileName(sysFile),
                            Reason = $"Known BYOVD vulnerable driver '{sysName}.sys' in System32/drivers — enables kernel-level bypass",
                            Detail = $"Path: {sysFile}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
        return Task.CompletedTask;
    }, ct);

    private Task CheckWERCrashDumpsForInjection(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var werPaths = new[]
        {
            @"C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
            @"C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Microsoft\Windows\WER\ReportQueue"),
        };

        foreach (var werRoot in werPaths)
        {
            if (!Directory.Exists(werRoot)) continue;
            try
            {
                foreach (var reportDir in Directory.EnumerateDirectories(werRoot))
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (var file in Directory.EnumerateFiles(reportDir, "*.wer", SearchOption.TopDirectoryOnly))
                    {
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            var content = await sr.ReadToEndAsync(ct);

                            foreach (var kw in CheatKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name, Title = "WER Crash Report: Cheat Module in Crash",
                                        Risk = RiskLevel.High, Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Cheat keyword '{kw}' in Windows Error Report — process crashed with cheat module loaded",
                                        Detail = content.Length > 500 ? content[..500] : content
                                    });
                                    break;
                                }
                            }

                            foreach (var inj in InjectionTechniqueKeywords)
                            {
                                if (content.Contains(inj, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name, Title = "WER Crash Report: Injection Technique Indicator",
                                        Risk = RiskLevel.Critical, Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Injection technique keyword '{inj}' in WER crash report",
                                        Detail = content.Length > 500 ? content[..500] : content
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckMiniDumpInjectionArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var miniDumpPaths = new[]
        {
            @"C:\Windows\Minidump",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Microsoft\Windows\WER\ReportQueue"),
        };

        foreach (var dumpRoot in miniDumpPaths)
        {
            if (!Directory.Exists(dumpRoot)) continue;
            try
            {
                foreach (var dmpFile in Directory.EnumerateFiles(dumpRoot, "*.dmp", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(dmpFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        var headerBuffer = new byte[Math.Min(65536, fs.Length)];
                        await fs.ReadAsync(headerBuffer, ct);
                        var headerStr = System.Text.Encoding.ASCII.GetString(headerBuffer);

                        foreach (var kw in CheatKeywords)
                        {
                            if (headerStr.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Minidump: Cheat Module Name in Dump Header",
                                    Risk = RiskLevel.Critical, Location = dmpFile,
                                    FileName = Path.GetFileName(dmpFile),
                                    Reason = $"Cheat keyword '{kw}' in minidump header — indicates injected cheat DLL in crashed process",
                                    Detail = $"Dump: {dmpFile}"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckPrefetchInjectorArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var prefetchPath = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchPath)) return Task.CompletedTask;

        try
        {
            foreach (var pf in Directory.EnumerateFiles(prefetchPath, "*.pf"))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var pfName = Path.GetFileNameWithoutExtension(pf).ToLowerInvariant();

                foreach (var injName in KnownInjectorNames)
                {
                    if (pfName.Contains(injName.Replace("_", "").Replace(" ", ""), StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Prefetch: Injector Tool Execution History",
                            Risk = RiskLevel.Critical, Location = pf,
                            FileName = Path.GetFileName(pf),
                            Reason = $"Injector tool '{injName}' execution prefetch — confirms injector was run",
                            Detail = $"Prefetch: {pf}"
                        });
                        break;
                    }
                }

                foreach (var driverName in BypassDriverNames)
                {
                    if (pfName.Contains(driverName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Prefetch: BYOVD Loader Execution",
                            Risk = RiskLevel.Critical, Location = pf,
                            FileName = Path.GetFileName(pf),
                            Reason = $"BYOVD driver loader '{driverName}' in prefetch — vulnerable driver was executed",
                            Detail = $"Prefetch: {pf}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
        return Task.CompletedTask;
    }, ct);

    private Task CheckReflectiveDllArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            Path.GetTempPath(),
        };

        foreach (var root in searchPaths)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        var peHeader = new byte[Math.Min(4096, fs.Length)];
                        await fs.ReadAsync(peHeader, ct);

                        if (peHeader.Length >= 2 && peHeader[0] == 0x4D && peHeader[1] == 0x5A)
                        {
                            var headerStr = System.Text.Encoding.ASCII.GetString(peHeader);
                            if (headerStr.Contains("ReflectiveDll", StringComparison.OrdinalIgnoreCase) ||
                                headerStr.Contains("ReflectiveLoader", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Reflective DLL: Reflective Loader Signature",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = "DLL contains ReflectiveDll/ReflectiveLoader signature — self-loading injection technique",
                                    Detail = $"Path: {file}"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckKernelBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var psHistoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
        if (!File.Exists(psHistoryPath)) return;
        ctx.IncrementFiles();

        try
        {
            using var fs = new FileStream(psHistoryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            var content = await sr.ReadToEndAsync(ct);

            foreach (var kw in KernelBypassIndicators)
            {
                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "PS History: Kernel Bypass Command",
                        Risk = RiskLevel.Critical, Location = psHistoryPath,
                        FileName = Path.GetFileName(psHistoryPath),
                        Reason = $"Kernel bypass keyword '{kw}' in PowerShell history — indicates kernel security bypass",
                        Detail = content.Length > 500 ? content[..500] : content
                    });
                    break;
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckDSEBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var codeIntegrityPath = @"SYSTEM\CurrentControlSet\Control\CI\Config";
        try
        {
            using var key = hklm.OpenSubKey(codeIntegrityPath);
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                var ciEnabled = key.GetValue("VulnerableDriverBlocklistEnable")?.ToString();
                var umciEnabled = key.GetValue("UMCIEnabled")?.ToString();

                if (ciEnabled == "0")
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "DSE Bypass: Vulnerable Driver Blocklist Disabled",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{codeIntegrityPath}",
                        FileName = "VulnerableDriverBlocklistEnable",
                        Reason = "Windows vulnerable driver blocklist is DISABLED — enables BYOVD attacks",
                        Detail = $"VulnerableDriverBlocklistEnable = {ciEnabled}"
                    });
                }
            }
        }
        catch { }

        var codeIntegrityPath2 = @"SYSTEM\CurrentControlSet\Control\CI\Protected";
        try
        {
            using var key = hklm.OpenSubKey(codeIntegrityPath2);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            var ciState = key.GetValue("Licensed")?.ToString();
            var disableState = key.GetValue("Disabled")?.ToString();
            if (disableState == "1")
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "DSE Bypass: Code Integrity Protected Disabled",
                    Risk = RiskLevel.Critical,
                    Location = $@"HKLM\{codeIntegrityPath2}",
                    FileName = "Disabled",
                    Reason = "Code Integrity protected state is disabled — Driver Signature Enforcement may be bypassed",
                    Detail = $"Disabled = {disableState}"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckInjectorRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var muiCachePath = @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
        using var hkcu = Registry.CurrentUser;

        try
        {
            using var key = hkcu.OpenSubKey(muiCachePath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                foreach (var injName in KnownInjectorNames)
                {
                    if (valueName.Contains(injName, StringComparison.OrdinalIgnoreCase))
                    {
                        var val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "MUICache: Injector Tool Execution History",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\{muiCachePath}",
                            FileName = Path.GetFileName(valueName.Split('.')[0]),
                            Reason = $"Injector tool '{injName}' in MUICache — confirms tool was executed on this system",
                            Detail = $"Key: {valueName}, Value: {val}"
                        });
                        break;
                    }
                }

                foreach (var driverName in BypassDriverNames)
                {
                    if (valueName.Contains(driverName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "MUICache: BYOVD Driver Loader Execution",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\{muiCachePath}",
                            FileName = valueName,
                            Reason = $"BYOVD driver '{driverName}' in MUICache — vulnerable driver tool was executed",
                            Detail = $"Key: {valueName}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckManualMapArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            Path.GetTempPath(),
        };

        foreach (var root in searchPaths)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();

                    if (name.Contains("manualmapper") || name.Contains("manual_map") || name.Contains("manualmap"))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Manual Mapper: Tool Artifact Found",
                            Risk = RiskLevel.Critical, Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Manual mapping tool artifact — bypasses module enumeration and hides injected DLL from game/AC",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext is ".log" or ".txt" or ".json")
                    {
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            var content = await sr.ReadToEndAsync(ct);
                            if (content.Contains("manual map", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("manualmapping", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Manual Map: Injection Technique Referenced in File",
                                    Risk = RiskLevel.High, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = "Manual mapping injection technique referenced in file",
                                    Detail = content.Length > 400 ? content[..400] : content
                                });
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckDllSearchOrderHijackArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var systemPath = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var windowsPath = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var suspiciousDlls = new[]
        {
            "cryptbase.dll", "cryptsp.dll", "dwmapi.dll", "CRYPTBASE.DLL",
            "DPAPI.DLL", "RpcRtRemote.dll", "secur32.dll", "sspicli.dll",
            "wtsapi32.dll", "uxtheme.dll", "wer.dll", "wbemcomn.dll",
            "devobj.dll", "setupapi.dll",
        };

        var checkPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
        };

        foreach (var checkRoot in checkPaths)
        {
            if (!Directory.Exists(checkRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(checkRoot, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var dllName = Path.GetFileName(file);
                    if (suspiciousDlls.Any(s => s.Equals(dllName, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "DLL Search Order Hijack: System DLL in User Directory",
                            Risk = RiskLevel.High, Location = file,
                            FileName = dllName,
                            Reason = $"System DLL '{dllName}' found in user directory — DLL search order hijacking artifact",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
        return Task.CompletedTask;
    }, ct);

    private Task CheckKernelDriverLoadHistory(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var servicesPath = @"SYSTEM\CurrentControlSet\Services";
        var suspiciousServiceKeywords = new[]
        {
            "byovd", "bypassdriver", "bypass_driver", "kernpatch", "kpatch",
            "hvci_bypass", "ci_bypass", "dse_bypass", "pg_bypass",
            "patchguard_bypass", "eac_driver", "be_driver",
            "inject_driver", "hook_driver",
        };

        try
        {
            using var servicesKey = hklm.OpenSubKey(servicesPath);
            if (servicesKey == null) return;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                foreach (var kw in suspiciousServiceKeywords)
                {
                    if (svcName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Kernel Driver: Suspicious Bypass Service",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{servicesPath}\{svcName}",
                            FileName = svcName,
                            Reason = $"Suspicious kernel driver service '{svcName}' — potential PatchGuard/DSE/HVCI bypass driver",
                            Detail = $"Service: {svcName}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckCheatEngineRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var ceRegPaths = new[]
        {
            @"SOFTWARE\Cheat Engine",
            @"SOFTWARE\CheatEngine",
            @"SOFTWARE\Dark Byte",
            @"SOFTWARE\DarkByte",
        };
        using var hkcu = Registry.CurrentUser;
        using var hklm = Registry.LocalMachine;

        foreach (var regPath in ceRegPaths)
        {
            foreach (var hive in new[] { hkcu, hklm })
            {
                try
                {
                    using var key = hive.OpenSubKey(regPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "Cheat Engine Registry: Memory Editor Artifact",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKCU\{regPath}",
                        FileName = regPath.Split('\\').Last(),
                        Reason = $"Cheat Engine registry artifact '{regPath}' — memory editor was installed/used",
                        Detail = $"Keys: {string.Join(", ", key.GetValueNames().Take(5))}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckLoadedModuleArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var eventLogPath = @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-CodeIntegrity%4Operational.evtx";
        if (!File.Exists(eventLogPath)) return;
        ctx.IncrementFiles();

        var cbsLogPath = @"C:\Windows\Logs\CBS\CBS.log";
        if (!File.Exists(cbsLogPath)) return;
        ctx.IncrementFiles();

        try
        {
            using var fs = new FileStream(cbsLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            var content = await sr.ReadToEndAsync(ct);
            foreach (var driverName in BypassDriverNames)
            {
                if (content.Contains(driverName, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "CBS Log: BYOVD Driver Installation",
                        Risk = RiskLevel.Critical, Location = cbsLogPath,
                        FileName = "CBS.log",
                        Reason = $"BYOVD driver '{driverName}' referenced in CBS.log — driver was installed via CBS",
                        Detail = content.Length > 500 ? content[..500] : content
                    });
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckCodeCaveArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var werPaths = new[]
        {
            @"C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
        };

        foreach (var werRoot in werPaths)
        {
            if (!Directory.Exists(werRoot)) continue;
            try
            {
                foreach (var reportDir in Directory.EnumerateDirectories(werRoot))
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (var file in Directory.EnumerateFiles(reportDir, "Report.wer", SearchOption.TopDirectoryOnly))
                    {
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            var content = await sr.ReadToEndAsync(ct);
                            if (content.Contains("GTA5.exe", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("GTAVLauncher.exe", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("FiveM.exe", StringComparison.OrdinalIgnoreCase))
                            {
                                foreach (var kw in InjectionTechniqueKeywords)
                                {
                                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = Name, Title = "WER: GTA/FiveM Crash with Injection Indicators",
                                            Risk = RiskLevel.Critical, Location = file,
                                            FileName = Path.GetFileName(file),
                                            Reason = $"GTA/FiveM crash report contains injection keyword '{kw}' — cheat injection caused crash",
                                            Detail = content.Length > 500 ? content[..500] : content
                                        });
                                        break;
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckAppCompatLayerInjection(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var appCompatPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";
        using var hkcu = Registry.CurrentUser;
        using var hklm = Registry.LocalMachine;

        foreach (var hive in new[] { hkcu, hklm })
        {
            try
            {
                using var key = hive.OpenSubKey(appCompatPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();
                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var val = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    foreach (var kw in new[] { "cheat", "hack", "inject", "bypass", "kiddion", "eulen" })
                    {
                        if (valueName.Contains(kw, StringComparison.OrdinalIgnoreCase) ||
                            val.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "AppCompat Layer: Cheat Tool Compatibility Flag",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{appCompatPath}",
                                FileName = Path.GetFileName(valueName),
                                Reason = $"AppCompat layer set for cheat-related path '{valueName}'",
                                Detail = $"Layers: {val}"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckProcessDumpArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localDumpsPath = @"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps";
        using var hklm = Registry.LocalMachine;
        try
        {
            using var key = hklm.OpenSubKey(localDumpsPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();

            var dumpFolder = key.GetValue("DumpFolder")?.ToString() ?? string.Empty;
            if (!string.IsNullOrEmpty(dumpFolder) && Directory.Exists(dumpFolder))
            {
                foreach (var dumpFile in Directory.EnumerateFiles(dumpFolder, "*.dmp", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(dumpFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        var buf = new byte[Math.Min(32768, fs.Length)];
                        await fs.ReadAsync(buf, ct);
                        var headerStr = System.Text.Encoding.ASCII.GetString(buf);
                        foreach (var kw in CheatKeywords)
                        {
                            if (headerStr.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Local Dump: Cheat Module in Process Dump",
                                    Risk = RiskLevel.Critical, Location = dumpFile,
                                    FileName = Path.GetFileName(dumpFile),
                                    Reason = $"Cheat keyword '{kw}' in local dump — game process was dumped with cheat loaded",
                                    Detail = $"Dump: {dumpFile}"
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
    }, ct);
}
