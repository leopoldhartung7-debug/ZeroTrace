using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class KernelBypassRootkitForensicScanModule : IScanModule
{
    public string Name => "Kernel Bypass / Rootkit Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] ByovdDriverNames = new[]
    {
        "kdmapper", "gdrv", "cpuz141", "elbycdio", "rtcore64", "ntiolib_x64",
        "msio64", "msio32", "winring0x64", "winring0", "rwdrv",
        "dbk32", "dbk64", "nal", "inpoutx64", "speedfan",
        "aswrvrt", "procexp152", "procexp", "winio", "glbhook",
        "physmem", "amifldrv", "nvaudio", "sendhlp",
        "iqvw64e", "nvflash", "bsflash", "lenovodiagnosticsdriver",
        "acpiex", "mahimahi", "ene", "dh_kernel",
        "gmer", "aswarpot", "truesight",
        "ginadll", "vrnetstack", "kprocesshacker",
        "pchdtvdrv", "fiddrv", "fiddrv64", "atillk", "atillk64",
    };

    private static readonly string[] KernelCheatToolNames = new[]
    {
        "kdmapper.exe", "drvmap.exe", "kdmapper64.exe",
        "gdrv_exploit", "rtcore_exploit",
        "dsepatch", "dsefix", "dse_bypass",
        "kdu.exe", "kexploit",
        "patchguard_bypass", "pg_bypass",
        "testmode_enable", "bcdedit_testsigning",
        "procexp64.exe",
    };

    private static readonly string[] ETWPatchKeywords = new[]
    {
        "EtwpProcessPrivilege", "EtwRegister", "NtTraceEvent",
        "etw_patch", "etw_bypass", "etw_disable",
        "PatchETW", "DisableETW", "BlindETW",
        "EtwEventWrite", "EtwEventWriteFull",
        "ntdll!EtwEventWrite",
    };

    private static readonly string[] SSDTHookKeywords = new[]
    {
        "SSDT", "KeServiceDescriptorTable", "NtSystemCall",
        "ssdt_hook", "ssdt_patch", "system_call_table",
        "NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
        "NtCreateThreadEx", "NtMapViewOfSection",
        "ZwOpenProcess", "ZwAllocateVirtualMemory",
    };

    private static readonly string[] TestSigningArtifacts = new[]
    {
        "testsigning", "TESTSIGNING", "test signing",
        "nointegritychecks", "NOINTEGRITYCHECKS",
        "loadoptions", "advancedoptions",
    };

    private static readonly string[] KernelExploitFiles = new[]
    {
        "kdmapper.exe", "kdu.exe", "drvmap.exe", "dse_fix.exe",
        "gdrv_exploit.exe", "rtcore_exploit.exe", "cpuz_exploit.exe",
        "physmem_exploit.exe", "winring_exploit.exe",
        "kernel_exploit", "ring0_exploit", "kernel_cheat",
        "patchguard_bypass", "dse_bypass", "ci_bypass",
        "driver_exploit", "byovd_tool", "byovd_loader",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckByovdDriverFiles(ctx, ct),
            CheckByovdDriverServices(ctx, ct),
            CheckKernelExploitTools(ctx, ct),
            CheckTestSigningEnabled(ctx, ct),
            CheckDSEBypassArtifacts(ctx, ct),
            CheckETWPatchArtifacts(ctx, ct),
            CheckSSDTHookArtifacts(ctx, ct),
            CheckKernelModeShellcodeArtifacts(ctx, ct),
            CheckSecureBootDisabled(ctx, ct),
            CheckHypervisorCheatArtifacts(ctx, ct),
            CheckProcessHollowingArtifacts(ctx, ct),
            CheckKernelCallbackArtifacts(ctx, ct),
            CheckPrefetchKernelExploit(ctx, ct),
            CheckRegistryKernelBypass(ctx, ct),
            CheckMaliciousBootConfig(ctx, ct),
            CheckDriverSignatureBypassRegistry(ctx, ct),
            CheckRootkitPresistenceServices(ctx, ct),
            CheckKernelDebuggerArtifacts(ctx, ct)
        );
    }

    private Task CheckByovdDriverFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string[] searchPaths = new[]
        {
            @"C:\Windows\System32\drivers",
            @"C:\Windows\SysWOW64\drivers",
            @"C:\Windows\System32",
        };

        foreach (string searchPath in searchPaths)
        {
            if (!Directory.Exists(searchPath)) continue;
            foreach (string drvName in ByovdDriverNames)
            {
                foreach (string ext in new[] { ".sys", ".dll", ".exe" })
                {
                    string drvPath = Path.Combine(searchPath, drvName + ext);
                    if (File.Exists(drvPath))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "BYOVD Driver File Found",
                            Risk = Risk.Critical,
                            Location = drvPath,
                            FileName = drvName + ext,
                            Reason = $"Known vulnerable/BYOVD driver found: '{drvName}{ext}'",
                            Detail = "BYOVD (Bring Your Own Vulnerable Driver) technique uses known-vulnerable drivers to disable kernel protection and inject cheats at ring-0"
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckByovdDriverServices(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey == null) return;

            foreach (string serviceName in servicesKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                bool matchesByovd = ByovdDriverNames.Any(d =>
                    serviceName.Contains(d, StringComparison.OrdinalIgnoreCase));

                if (matchesByovd)
                {
                    try
                    {
                        using var svcKey = servicesKey.OpenSubKey(serviceName);
                        string imagePath = svcKey?.GetValue("ImagePath")?.ToString() ?? string.Empty;
                        int serviceType = (int)(svcKey?.GetValue("Type") ?? 0);

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "BYOVD Driver Service Registration",
                            Risk = Risk.Critical,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{serviceName}",
                            FileName = serviceName,
                            Reason = $"Kernel service matching BYOVD driver name registered: '{serviceName}'",
                            Detail = $"Service image path: '{imagePath}' — BYOVD drivers are registered as kernel services to gain ring-0 access"
                        });
                    }
                    catch { }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckKernelExploitTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
            Path.Combine(userProfile, @"AppData\Local\Temp"),
            @"C:\Windows\Temp",
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string file in Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                string fileName = Path.GetFileName(file).ToLowerInvariant();
                foreach (string exploitName in KernelExploitFiles)
                {
                    if (fileName.Contains(exploitName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Kernel Exploit Tool Found",
                            Risk = Risk.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Kernel exploit or BYOVD tool found: '{exploitName}'",
                            Detail = "Kernel exploit tools are used to load unsigned/cheat drivers by exploiting vulnerable signed drivers"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckTestSigningEnabled(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            string bcdEditOutput = string.Empty;
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Config");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                object? vuln = key.GetValue("VulnerableDriverBlocklistEnable");
                if (vuln is int vulnInt && vulnInt == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Vulnerable Driver Blocklist Disabled",
                        Risk = Risk.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable",
                        FileName = "VulnerableDriverBlocklistEnable",
                        Reason = "Microsoft vulnerable driver blocklist is disabled — BYOVD attacks fully enabled",
                        Detail = "Disabling the vulnerable driver blocklist allows all known-exploitable drivers to load without Windows blocking them"
                    });
                }
            }
        }
        catch { }

        try
        {
            using var testKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management");
            if (testKey != null)
            {
                ctx.IncrementRegistryKeys();
                object? clearPageFileAtShutdown = testKey.GetValue("VerifyDrivers");
                if (clearPageFileAtShutdown?.ToString() == "0")
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Driver Verification Disabled",
                        Risk = Risk.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\VerifyDrivers",
                        FileName = "VerifyDrivers",
                        Reason = "Kernel driver verification disabled via registry",
                        Detail = "Disabling driver verification reduces detection of unsigned/malicious kernel drivers"
                    });
                }
            }
        }
        catch { }

        try
        {
            using var bootKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            if (bootKey != null)
            {
                ctx.IncrementRegistryKeys();
                object? enabled = bootKey.GetValue("UEFISecureBootEnabled");
                if (enabled is int enabledInt && enabledInt == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Secure Boot Disabled",
                        Risk = Risk.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled",
                        FileName = "UEFISecureBootEnabled",
                        Reason = "UEFI Secure Boot is disabled — allows unsigned bootloaders and kernel drivers",
                        Detail = "Secure Boot must be disabled for some BYOVD attacks and kernel-level cheat installations"
                    });
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckDSEBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, @"AppData\Local\Temp"),
        };

        string[] dseBypassKeywords = new[]
        {
            "DSE", "CiOptions", "g_CiEnabled", "ci.dll",
            "PatchCiOptions", "DisableCodeIntegrity",
            "nt!g_CiEnabled", "CiPolicy",
            "DSEFix", "DSEPatch", "DSE bypass",
            "nt!SeValidateImageData", "PsIsProtectedProcess",
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string file in Directory.GetFiles(dir, "*.txt", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(dir, "*.log", SearchOption.TopDirectoryOnly))
                .Concat(Directory.GetFiles(dir, "*.bat", SearchOption.TopDirectoryOnly))
                .Concat(Directory.GetFiles(dir, "*.ps1", SearchOption.TopDirectoryOnly)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string dseKw in dseBypassKeywords)
                    {
                        if (content.Contains(dseKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "DSE Bypass Artifact Found",
                                Risk = Risk.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"File contains Driver Signature Enforcement bypass keyword: '{dseKw}'",
                                Detail = "DSE bypass allows loading of unsigned kernel drivers — prerequisite for kernel-level cheats"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckETWPatchArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string psHistory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");

        if (!File.Exists(psHistory)) return;
        ctx.IncrementFiles();
        try
        {
            using var fs = new FileStream(psHistory, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            string content = await sr.ReadToEndAsync(ct);

            foreach (string etwKw in ETWPatchKeywords)
            {
                if (content.Contains(etwKw, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PowerShell History — ETW Patch Command",
                        Risk = Risk.Critical,
                        Location = psHistory,
                        FileName = Path.GetFileName(psHistory),
                        Reason = $"PowerShell history contains ETW patching keyword: '{etwKw}'",
                        Detail = "ETW (Event Tracing for Windows) patching disables telemetry and kernel event logging — used to hide cheat activity"
                    });
                    break;
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckSSDTHookArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, @"AppData\Local\Temp"),
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string file in Directory.GetFiles(dir, "*.txt", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(dir, "*.log", SearchOption.TopDirectoryOnly)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string ssdtKw in SSDTHookKeywords)
                    {
                        if (content.Contains(ssdtKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "SSDT Hook Artifact Found",
                                Risk = Risk.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"File contains SSDT hook-related keyword: '{ssdtKw}'",
                                Detail = "SSDT (System Service Descriptor Table) hooks intercept kernel API calls — used for advanced cheat injection"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckKernelModeShellcodeArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, @"AppData\Local\Temp"),
        };

        string[] shellcodeKeywords = new[]
        {
            "shellcode", "ring0_shellcode", "kernel_shellcode",
            "code_cave", "codecave", "kernel_payload",
            "MmAllocateNonCachedMemory", "ExAllocatePoolWithTag",
            "KeStackAttachProcess", "ZwAllocateVirtualMemory",
            "NtAllocateVirtualMemory", "MmCopyMemory",
            "RtlCopyMemory.*kernel", "memcpy.*kernel",
            "PsCreateSystemThread", "IoCreateDriver",
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string file in Directory.GetFiles(dir, "*.txt", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(dir, "*.log", SearchOption.TopDirectoryOnly))
                .Concat(Directory.GetFiles(dir, "*.h", SearchOption.TopDirectoryOnly))
                .Concat(Directory.GetFiles(dir, "*.cpp", SearchOption.TopDirectoryOnly)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string scKw in shellcodeKeywords)
                    {
                        if (content.Contains(scKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Kernel Shellcode Artifact Found",
                                Risk = Risk.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"File contains kernel-mode shellcode keyword: '{scKw}'",
                                Detail = "Kernel-mode shellcode artifacts indicate development or use of ring-0 cheat injection techniques"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckSecureBootDisabled(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            object? sbEnabled = key.GetValue("UEFISecureBootEnabled");
            if (sbEnabled is int sbInt && sbInt == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "UEFI Secure Boot Disabled",
                    Risk = Risk.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled",
                    FileName = "UEFISecureBootEnabled",
                    Reason = "Secure Boot is disabled — prerequisite for unsigned kernel cheat drivers",
                    Detail = "UEFI Secure Boot must be disabled to allow loading of unsigned kernel-mode cheat drivers"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckHypervisorCheatArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] hvCheatTools = new[]
        {
            "hyperv_cheat", "vmhypervisor_cheat", "hvci_bypass",
            "hypervise", "vt_cheat", "vmx_cheat",
            "hypervisor_cheat", "ring-1_cheat", "smm_cheat",
        };

        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string file in Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                string fileName = Path.GetFileName(file).ToLowerInvariant();
                foreach (string hvTool in hvCheatTools)
                {
                    if (fileName.Contains(hvTool, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Hypervisor-Based Cheat Tool",
                            Risk = Risk.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Hypervisor-based cheat tool found: '{hvTool}'",
                            Detail = "Hypervisor cheats operate below the OS kernel (ring-1/-2) making them undetectable by conventional AC"
                        });
                        break;
                    }
                }
            }
        }

        try
        {
            using var hvKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
            if (hvKey != null)
            {
                ctx.IncrementRegistryKeys();
                object? enabled = hvKey.GetValue("Enabled");
                if (enabled is int enabledInt && enabledInt == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "HVCI (Hypervisor-Protected Code Integrity) Disabled",
                        Risk = Risk.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                        FileName = "Enabled",
                        Reason = "HVCI is disabled — allows non-WHQL drivers and kernel memory manipulation",
                        Detail = "HVCI protects kernel memory integrity — disabling it is required for most kernel-level cheat drivers"
                    });
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckProcessHollowingArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, @"AppData\Local\Temp"),
        };

        string[] hollowingKeywords = new[]
        {
            "process hollow", "process hollowing", "ProcessHollowing",
            "CreateProcessSuspended", "NtUnmapViewOfSection",
            "ZwUnmapViewOfSection", "NtWriteVirtualMemory",
            "NtResumeThread", "RunPE", "runpe", "run_pe",
            "hollow_inject", "process_replace",
            "WriteProcessMemory.*CREATE_SUSPENDED",
            "inject.*svchost", "inject.*explorer",
        };

        foreach (string dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (string file in Directory.GetFiles(dir, "*.txt", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(dir, "*.cpp", SearchOption.TopDirectoryOnly))
                .Concat(Directory.GetFiles(dir, "*.cs", SearchOption.TopDirectoryOnly)))
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (string phKw in hollowingKeywords)
                    {
                        if (content.Contains(phKw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Process Hollowing Artifact",
                                Risk = Risk.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"File contains process hollowing keyword: '{phKw}'",
                                Detail = "Process hollowing artifacts indicate code injection into legitimate processes to hide cheat execution"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckKernelCallbackArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string psHistory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
        if (!File.Exists(psHistory)) return;
        ctx.IncrementFiles();
        try
        {
            using var fs = new FileStream(psHistory, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            string content = await sr.ReadToEndAsync(ct);

            string[] callbackKeywords = new[]
            {
                "PsSetCreateProcessNotifyRoutine", "PsSetLoadImageNotifyRoutine",
                "ObRegisterCallbacks", "CmRegisterCallback",
                "remove_callback", "unregister_callback",
                "PatchGuard", "PG bypass", "pg_bypass",
                "KeBugCheckEx", "bypass_patchguard",
            };

            foreach (string cbKw in callbackKeywords)
            {
                if (content.Contains(cbKw, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PowerShell History — Kernel Callback Manipulation",
                        Risk = Risk.Critical,
                        Location = psHistory,
                        FileName = Path.GetFileName(psHistory),
                        Reason = $"PowerShell history contains kernel callback keyword: '{cbKw}'",
                        Detail = "Kernel callback manipulation is used to remove AC driver notifications and hide cheat process creation"
                    });
                    break;
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckPrefetchKernelExploit(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string prefetchPath = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchPath)) return;

        foreach (string pfFile in Directory.GetFiles(prefetchPath, "*.pf", SearchOption.TopDirectoryOnly))
        {
            if (ct.IsCancellationRequested) return;
            string fileName = Path.GetFileName(pfFile).ToLowerInvariant();

            foreach (string exploitTool in KernelCheatToolNames)
            {
                string toolName = Path.GetFileNameWithoutExtension(exploitTool).ToLowerInvariant();
                if (fileName.Contains(toolName, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Prefetch — Kernel Exploit Tool Execution",
                        Risk = Risk.Critical,
                        Location = pfFile,
                        FileName = Path.GetFileName(pfFile),
                        Reason = $"Prefetch proves kernel exploit tool was executed: '{exploitTool}'",
                        Detail = "Windows Prefetch records prove the kernel exploit tool was run on this system"
                    });
                    break;
                }
            }

            foreach (string byovdName in ByovdDriverNames.Take(20))
            {
                if (fileName.Contains(byovdName, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Prefetch — BYOVD Driver Tool Execution",
                        Risk = Risk.Critical,
                        Location = pfFile,
                        FileName = Path.GetFileName(pfFile),
                        Reason = $"Prefetch proves BYOVD driver mapper was executed: '{byovdName}'",
                        Detail = "Prefetch records prove the BYOVD driver exploitation tool was run on this system"
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckRegistryKernelBypass(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management");
            if (key == null) return;
            ctx.IncrementRegistryKeys();

            object? clearPageFile = key.GetValue("ClearPageFileAtShutdown");
            if (clearPageFile is int cpfInt && cpfInt == 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Page File Cleared at Shutdown",
                    Risk = Risk.Medium,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown",
                    FileName = "ClearPageFileAtShutdown",
                    Reason = "Page file cleared at shutdown — destroys kernel memory forensic evidence",
                    Detail = "Clearing the page file removes memory artifacts including cheat code that was swapped out"
                });
            }
        }
        catch { }

        try
        {
            using var ciKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI\Config");
            if (ciKey == null) return;
            ctx.IncrementRegistryKeys();

            object? options = ciKey.GetValue("Options");
            if (options is int optInt && (optInt & 0x4) != 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Code Integrity Policy Weakened",
                    Risk = Risk.Critical,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\Options",
                    FileName = "Options",
                    Reason = $"Code integrity options modified: {optInt:X8}",
                    Detail = "Code integrity policy modification allows loading of unsigned or specially-crafted kernel drivers"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckMaliciousBootConfig(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var bootKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Boot Execute");
            if (bootKey == null) return;
            ctx.IncrementRegistryKeys();
            string[] bootExecute = (string[])(bootKey.GetValue("BootExecute") ?? Array.Empty<string>());
            foreach (string entry in bootExecute)
            {
                if (entry.Equals("autocheck autochk *", StringComparison.OrdinalIgnoreCase)) continue;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Boot Execute — Suspicious Entry",
                    Risk = Risk.Critical,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
                    FileName = "BootExecute",
                    Reason = $"Non-standard Boot Execute entry: '{entry}'",
                    Detail = "Boot Execute entries run before Windows fully loads — used for persistent kernel-level cheat installation"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckDriverSignatureBypassRegistry(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string[] dseRegistryPaths = new[]
        {
            @"SYSTEM\CurrentControlSet\Control\CI",
            @"SYSTEM\CurrentControlSet\Control\CI\Protected",
        };

        foreach (string regPath in dseRegistryPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();

                foreach (string valueName in key.GetValueNames())
                {
                    object? val = key.GetValue(valueName);
                    if (valueName.Equals("g_CiEnabled", StringComparison.OrdinalIgnoreCase) ||
                        valueName.Equals("CiEnabled", StringComparison.OrdinalIgnoreCase))
                    {
                        if (val is int valInt && valInt == 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Code Integrity Disabled via Registry",
                                Risk = Risk.Critical,
                                Location = $@"HKLM\{regPath}\{valueName}",
                                FileName = valueName,
                                Reason = $"Code integrity disabled via registry key: '{valueName}=0'",
                                Detail = "Disabling code integrity via g_CiEnabled/CiEnabled is the primary DSE bypass technique for unsigned driver loading"
                            });
                        }
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckRootkitPresistenceServices(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string[] rootkitServicePatterns = new[]
        {
            "hook", "rootkit", "stealth", "hidden", "invisible",
            "dkom", "direct_kernel", "patchguard", "pg_bypass",
            "kernel_cheat", "ring0", "ring_zero",
            "inject_drv", "injdrv", "drvinject",
            "bypass_drv", "drvbypass",
        };

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey == null) return;

            foreach (string serviceName in servicesKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();
                string serviceNameLower = serviceName.ToLowerInvariant();

                foreach (string pattern in rootkitServicePatterns)
                {
                    if (serviceNameLower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            using var svcKey = servicesKey.OpenSubKey(serviceName);
                            int serviceType = (int)(svcKey?.GetValue("Type") ?? 0);
                            if (serviceType == 1 || serviceType == 2 || serviceType == 4)
                            {
                                string imagePath = svcKey?.GetValue("ImagePath")?.ToString() ?? string.Empty;
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Kernel Rootkit/Hook Service",
                                    Risk = Risk.Critical,
                                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{serviceName}",
                                    FileName = serviceName,
                                    Reason = $"Kernel-mode service with rootkit-related name: '{serviceName}'",
                                    Detail = $"Service type: {serviceType} (kernel driver), image: '{imagePath}'"
                                });
                            }
                        }
                        catch { }
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckKernelDebuggerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var dbgKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter");
            if (dbgKey != null)
            {
                ctx.IncrementRegistryKeys();
                object? default_val = dbgKey.GetValue("Default");
                if (default_val is int defInt && defInt == 0xFFFFFFFF)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Kernel Debug Output Enabled at Max Level",
                        Risk = Risk.Medium,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter\Default",
                        FileName = "Default",
                        Reason = "Kernel debug print filter set to maximum — may indicate kernel debugging for cheat development",
                        Detail = "Maximum kernel debug output is typically only set during driver/kernel exploit development"
                    });
                }
            }
        }
        catch { }

        try
        {
            using var lsaKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
            if (lsaKey == null) return;
            ctx.IncrementRegistryKeys();

            object? runAsPPL = lsaKey.GetValue("RunAsPPL");
            if (runAsPPL is int pplInt && pplInt == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "LSA Protected Process Disabled",
                    Risk = Risk.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL",
                    FileName = "RunAsPPL",
                    Reason = "LSA protected process light disabled — allows credential dumping via kernel access",
                    Detail = "Disabling LSA PPL allows reading LSASS memory — commonly done alongside kernel-level cheat tools for account access"
                });
            }
        }
        catch { }
    }, ct);
}
