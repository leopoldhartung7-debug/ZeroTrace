using Microsoft.Win32;
using System.Runtime.Versioning;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class KernelCheatDriverDeepForensicScanModule : IScanModule
{
    public string Name => "Kernel Cheat Driver Deep Forensic";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] KernelSourceKeywords = new[]
    {
        "MmCopyMemory", "PsGetCurrentProcess", "PsLookupProcessByProcessId",
        "KeServiceDescriptorTable", "MmGetSystemRoutineAddress", "ObReferenceObjectByName",
        "ZwQuerySystemInformation", "KeStackAttachProcess", "MmMapLockedPagesSpecifyCache",
        "ExAllocatePoolWithTag", "IoCreateDevice", "IoCreateSymbolicLink",
        "PsCreateSystemThread", "RtlInitUnicodeString", "IoDeleteDevice"
    };

    private static readonly string[] KdmapperArtifactNames = new[]
    {
        "kdmapper.exe", "kdmapper64.exe", "kdmapper32.exe",
        "TDL4_loader.exe", "KDU.exe", "kdu.exe",
        "kernel_mapper.exe", "kmap.exe", "drvmap.exe",
        "ldrload.exe", "kmod_loader.exe", "winload_kdmap.exe"
    };

    private static readonly string[] KdmapperBuildArtifacts = new[]
    {
        "kdmapper", "kdmapper64", "kdu", "kernel_mapper", "drvmap"
    };

    private static readonly string[] ByovdSysNames = new[]
    {
        "RTCore64.sys", "mhyprot2.sys", "gdrv.sys", "dbutil_2_3.sys",
        "cpuz143_x64.sys", "cpuz141_x64.sys", "cpuz134_x64.sys",
        "AsIO3.sys", "AsIO2.sys", "AsUpIO.sys",
        "HWiNFO64.sys", "HWiNFO32.sys",
        "Kprocesshacker.sys", "kprocesshacker.sys",
        "WinRing0x64.sys", "WinRing0.sys",
        "ntiolib_x64.sys", "ntiolib_x86.sys",
        "iQVM64.sys", "atillk64.sys",
        "bs_i2c_spi_WDM.sys", "bs_hwmio64_w10.sys",
        "phymemx64.sys", "lv561av.sys",
        "DirectIo32.sys", "DirectIo64.sys",
        "msio32.sys", "msio64.sys",
        "EneTechIo64.sys", "EneTechIo32.sys",
        "ene2.sys", "ene3.sys",
        "asmmap.sys", "asmmap64.sys",
        "rzpnk.sys"
    };

    private static readonly string[] KernelCheatDeviceNames = new[]
    {
        @"\\.\KMDFDriver", @"\\.\RTCore64", @"\\.\MalDriver",
        @"\\.\HWMonitor", @"\\.\PhyMem", @"\\.\GIO",
        @"\\.\ProcExp", @"\\.\KernelAccess", @"\\.\MemDrv",
        @"\\.\KCDriver", @"\\.\CheatDrv", @"\\.\AimDriver",
        @"\\.\WallhackDrv", @"\\.\OverlayDrv", @"\\.\ESP_Driver"
    };

    private static readonly string[] CheatDllIndicators = new[]
    {
        "DeviceIoControl", "CreateFile", @"\\.\", "IOCTL_",
        "kernel_read", "kernel_write", "km_read", "km_write",
        "driver_read", "driver_write", "read_physical", "write_physical"
    };

    private static readonly string[] DriverInstallScriptKeywords = new[]
    {
        "sc create", "sc.exe create", "sc start", "binPath=",
        "type= kernel", "type=kernel", "start= boot", "start=boot",
        "OSR Driver Loader", "OsrLoader", "OSRLOADER",
        "testsigning", "test signing", "bcdedit /set testsigning",
        "bcdedit.exe /set testsigning", "TESTSIGNING ON",
        "disable integrity checks", "nointegritychecks"
    };

    private static readonly string[] KernelDebuggerArtifacts = new[]
    {
        "kdnet.exe", "kd.exe", "ntkd.exe", "livekd.exe",
        "windbg.exe", "windbgx.exe", "cdb.exe", "ntsd.exe"
    };

    private static readonly string[] KernelDebugWorkspaceExtensions = new[]
    {
        ".wew", ".wes", ".kdmp", ".dmp", ".mdmp"
    };

    private static readonly string[] KernelSymbolFileNames = new[]
    {
        "ntoskrnl.pdb", "ntkrnlmp.pdb", "ntkrnlpa.pdb", "ntkrpamp.pdb",
        "hal.pdb", "halacpi.pdb", "halmacpi.pdb",
        "win32k.pdb", "win32kfull.pdb", "win32kbase.pdb",
        "ci.pdb", "cng.pdb", "ksecdd.pdb"
    };

    private static readonly string[] NtoskrnlCopyNames = new[]
    {
        "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe", "ntkrpamp.exe",
        "ntoskrnl_copy.exe", "nt_kernel.exe"
    };

    private static readonly string[] HollowProcessDumpNames = new[]
    {
        "svchost", "lsass", "csrss", "winlogon", "services",
        "wininit", "smss", "explorer"
    };

    private static readonly string[] KernelExploitSourceKeywords = new[]
    {
        "EternalBlue", "MS17-010", "PrintSpooler", "PrintNightmare",
        "CVE-2021-1675", "CVE-2021-34527", "CVE-2020-1472", "ZeroLogon",
        "CVE-2019-0708", "BlueKeep", "CVE-2018-8120",
        "CVE-2021-21551", "CVE-2022-21882", "CVE-2022-21999",
        "token_stealing_shellcode", "privilege_escalation_kernel",
        "kernel_exploit_stub", "smep_bypass", "kvas_bypass"
    };

    private static readonly string[] SigningBypassArtifacts = new[]
    {
        "SelfCert.exe", "selfcert.exe", "MakeCert.exe", "makecert.exe",
        "disableIntegrity.cmd", "disable_integrity.bat", "disable_dse.bat",
        "enable_testsigning.bat", "enable_testsigning.cmd",
        "sign_driver.bat", "sign_driver.cmd",
        "test_sign.bat", "BCD_modify.bat"
    };

    private static readonly string[] SigningBypassScriptKeywords = new[]
    {
        "MakeCert", "makecert", "SelfCert", "test certificate",
        "bcdedit /set nointegritychecks", "bcdedit /set testsigning on",
        "disable driver signing", "DSEfix", "DSE bypass",
        "integrity check bypass", "ci.dll", "g_CiEnabled",
        "SeLoadDriverPrivilege"
    };

    private static readonly string[] SsdtHookKeywords = new[]
    {
        "KeServiceDescriptorTable", "KiServiceTable", "SSDT",
        "ssdt_hook", "SSDTHook", "SSDT_hook",
        "IRP_MJ_", "IRP hook", "irp_hook",
        "NtQuerySystemInformation hook", "syscall hook",
        "dkom", "DKOM", "direct kernel object manipulation",
        "PspCidTable", "HandleTable"
    };

    private static readonly string[] SsdtToolNames = new[]
    {
        "SSHook.exe", "SSDTHook.exe", "sshook.exe", "ssdthook.exe",
        "SSDTView.exe", "ssdt_view.exe", "SyscallMon.exe",
        "IrpTracker.exe", "IrpMon.exe"
    };

    private static readonly string[] PoolTagToolNames = new[]
    {
        "PoolTag.exe", "pooltag.exe", "PoolMon.exe", "poolmon.exe",
        "PoolViewer.exe", "pool_viewer.exe", "PoolMonitor.exe",
        "pooltagger.exe", "WinPoolMon.exe"
    };

    private static readonly string[] PoolTagToolKeywords = new[]
    {
        "SystemPoolTagInformation", "PoolTagInformation",
        "SYSTEM_POOL_TAG_INFORMATION", "ExAllocatePoolWithTag",
        "PoolTag", "pool tag", "ExFreePoolWithTag",
        "NonPagedPool", "PagedPool", "PoolType"
    };

    private static readonly string[] CheatDriverServiceKeywords = new[]
    {
        "KMDFDriver", "RTCore64", "MalDriver", "CheatDrv",
        "AimDriver", "WallhackDriver", "KernelCheat", "GameCheat",
        "EspDriver", "RagehookKernel", "KernelAccess",
        "MemDriver", "PhysMemDrv", "DirectPhysMem"
    };

    private static readonly string[] IfeoDumperValues = new[]
    {
        "ntsd", "cdb", "windbg", "x64dbg", "ollydbg",
        "idaq", "idaq64", "ida64", "radare2"
    };

    private static readonly string[] PrefetchCheatToolNames = new[]
    {
        "KDMAPPER.EXE", "KDMAPPER64.EXE", "KDU.EXE",
        "OSRLOADER.EXE", "WINOBJ.EXE", "DRVMAP.EXE",
        "KPROCESSHACKER.EXE", "PROCEXP64.EXE",
        "SSDTHOOK.EXE", "POOLTAG.EXE", "POOLMON.EXE",
        "DSEFIX.EXE", "DSEBYPASS.EXE", "TDLSCAN.EXE"
    };

    private static readonly string[] AmcacheCheatToolKeywords = new[]
    {
        "kdmapper", "kernel_mapper", "drvmap", "byovd",
        "dsefix", "dsebypass", "ssdthook", "kdu.exe"
    };

    private static readonly string[] VmDiskImageNames = new[]
    {
        "cheat_vm.vmdk", "driver_test.vmdk", "kernel_dev.vmdk",
        "cheat_test.vmdk", "bypass_vm.vmdk", "ac_bypass.vmdk",
        "cheat_vm.vdi", "driver_test.vdi", "kernel_dev.vdi",
        "cheat_test.vdi", "bypass_vm.vdi",
        "cheat_vm.vhd", "driver_test.vhd",
        "cheat_vm.vhdx", "driver_test.vhdx"
    };

    private static readonly string[] VmSnapshotKeywords = new[]
    {
        "before driver install", "before_driver_install",
        "pre_driver", "pre-driver", "clean_state",
        "before cheat", "before_cheat", "cheat_baseline",
        "before ac bypass", "before_ac_bypass"
    };

    private static readonly string[] CheatIpcKeywords = new[]
    {
        @"\\.\pipe\cheat", @"\\.\pipe\driver", @"\\.\pipe\km",
        @"\pipe\cheat", @"\pipe\cheat_pipe", @"\pipe\km_pipe",
        @"\BaseNamedObjects\CheatMem", @"\BaseNamedObjects\KernelMem",
        @"\BaseNamedObjects\SharedMem", @"\BaseNamedObjects\GameMem",
        "IoCreateSymbolicLink", "RtlCreateSecurityDescriptor",
        "NtCreateSection", "ZwCreateSection",
        @"\\Device\\cheat", @"\\Device\\KMDFDriver",
        "named_pipe_cheat", "shared_memory_cheat"
    };

    private static readonly string[] WdkProjectKeywords = new[]
    {
        "WindowsKernelModeDriver8.0", "WindowsKernelModeDriver10.0",
        "WindowsKernelModeDriver", "WDKKernelModeDriver",
        "$(KernelBufferSecurityCheck)", "$(DDK_LIB_PATH)",
        "ntddk.h", "wdm.h", "ndis.h",
        "km\\default.props", "WindowsDriver.Default.props",
        "NtDdk", "NtKernelMode"
    };

    private static readonly string[] NtDdkPathKeywords = new[]
    {
        "C:\\WinDDK", "C:\\WINDDK", "%WINDDK%",
        "C:\\Program Files (x86)\\Windows Kits",
        "$(DDKROOT)", "$(WDKContentRoot)",
        "km\\ntddk.h", "km\\wdm.h",
        "\\km\\", "/km/", "NtDdk_x64"
    };

    private static readonly string[] AntiCheatDriverDbNames = new[]
    {
        "BEDaisy.idb", "BEDaisy.i64", "EasyAntiCheat.idb", "EasyAntiCheat.i64",
        "EasyAntiCheat_x64.idb", "EasyAntiCheat_x64.i64",
        "vgk.idb", "vgk.i64", "vanguard.idb", "vanguard.i64",
        "mhyprot.idb", "mhyprot.i64", "mhyprot2.idb", "mhyprot2.i64",
        "xigncode3.idb", "xigncode3.i64", "GameGuard.idb", "GameGuard.i64",
        "BEDaisy.bndb", "EasyAntiCheat.bndb", "vgk.bndb",
        "BEDaisy.gzf", "EasyAntiCheat.gzf", "vgk.gzf"
    };

    private static readonly string[] AntiCheatGhidraKeywords = new[]
    {
        "BEDaisy", "EasyAntiCheat", "EasyAntiCheat_x64",
        "vgk", "vanguard", "mhyprot", "mhyprot2",
        "xigncode", "GameGuard", "nProtect",
        "anti_cheat_analysis", "ac_driver_re"
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct) =>
        Task.WhenAll(
            CheckKernelDriverSourceRepos(ctx, ct),
            CheckKdmapperArtifacts(ctx, ct),
            CheckByovdSysFiles(ctx, ct),
            CheckKernelCheatDllArtifacts(ctx, ct),
            CheckDriverInstallScripts(ctx, ct),
            CheckKernelDebuggerArtifacts(ctx, ct),
            CheckKernelSymbolFiles(ctx, ct),
            CheckProcessHollowingDumps(ctx, ct),
            CheckKernelExploitSource(ctx, ct),
            CheckDriverSigningBypassTools(ctx, ct),
            CheckSsdtHookArtifacts(ctx, ct),
            CheckKernelPoolTagTools(ctx, ct),
            CheckRegistryTracesForDrivers(ctx, ct),
            CheckPrefetchAndExecutionHistory(ctx, ct),
            CheckVirtualMachineArtifacts(ctx, ct),
            CheckCheatDriverIpcArtifacts(ctx, ct),
            CheckKernelCheatCompilationArtifacts(ctx, ct),
            CheckAntiCheatDriverAnalysisTools(ctx, ct)
        );

    private Task CheckKernelDriverSourceRepos(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = GetUserSearchRoots();
        var sourceExtensions = new[] { ".c", ".h", ".cpp", ".hpp" };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root))
                continue;

            IEnumerable<string> dirs;
            try
            {
                dirs = Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories);
            }
            catch
            {
                continue;
            }

            foreach (var dir in dirs)
            {
                ct.ThrowIfCancellationRequested();

                bool hasDriverC = false;
                bool hasDriverH = false;
                bool hasKdmapperSrc = false;

                try
                {
                    var files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly);
                    foreach (var file in files)
                    {
                        var name = Path.GetFileName(file);
                        if (name.Equals("driver.c", StringComparison.OrdinalIgnoreCase)) hasDriverC = true;
                        if (name.Equals("driver.h", StringComparison.OrdinalIgnoreCase)) hasDriverH = true;
                        if (name.Contains("kdmapper", StringComparison.OrdinalIgnoreCase)) hasKdmapperSrc = true;
                    }
                }
                catch
                {
                    continue;
                }

                if (hasKdmapperSrc)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "kdmapper Source Code Repository Detected",
                        Risk = RiskLevel.Critical,
                        Location = dir,
                        FileName = Path.GetFileName(dir),
                        Reason = "Directory contains kdmapper kernel mapper source code files",
                        Detail = $"kdmapper source artifacts found in: {dir}"
                    });
                    ctx.IncrementFiles();
                    continue;
                }

                if (hasDriverC || hasDriverH)
                {
                    foreach (var ext in sourceExtensions)
                    {
                        string[] srcFiles;
                        try
                        {
                            srcFiles = Directory.GetFiles(dir, $"*{ext}", SearchOption.TopDirectoryOnly);
                        }
                        catch
                        {
                            continue;
                        }

                        foreach (var srcFile in srcFiles)
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementFiles();

                            string content;
                            try
                            {
                                using var fs = new FileStream(srcFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                content = await sr.ReadToEndAsync(ct);
                            }
                            catch
                            {
                                continue;
                            }

                            var matchedKeywords = KernelSourceKeywords
                                .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                .ToList();

                            if (matchedKeywords.Count >= 2)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Kernel Cheat Driver Source Code Detected",
                                    Risk = RiskLevel.Critical,
                                    Location = srcFile,
                                    FileName = Path.GetFileName(srcFile),
                                    Reason = $"Source file contains {matchedKeywords.Count} kernel API references indicative of cheat driver development",
                                    Detail = $"Matched APIs: {string.Join(", ", matchedKeywords.Take(5))}"
                                });
                            }
                        }
                    }
                }

                try
                {
                    var subDirName = Path.GetFileName(dir);
                    if (subDirName.Contains("rootkit", StringComparison.OrdinalIgnoreCase) ||
                        subDirName.Contains("kernel_cheat", StringComparison.OrdinalIgnoreCase) ||
                        subDirName.Contains("km_cheat", StringComparison.OrdinalIgnoreCase) ||
                        subDirName.Contains("driver_cheat", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Kernel Rootkit Project Directory Detected",
                            Risk = RiskLevel.Critical,
                            Location = dir,
                            FileName = subDirName,
                            Reason = "Directory name matches known kernel rootkit/cheat driver project naming convention",
                            Detail = $"Suspicious project directory: {dir}"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckKdmapperArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Environment.GetEnvironmentVariable("TEMP") ?? string.Empty,
            Environment.GetEnvironmentVariable("TMP") ?? string.Empty,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
        };

        foreach (var dir in searchDirs.Where(d => !string.IsNullOrEmpty(d) && Directory.Exists(d)))
        {
            foreach (var artifactName in KdmapperArtifactNames)
            {
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> found;
                try
                {
                    found = Directory.EnumerateFiles(dir, artifactName, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var filePath in found)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "kdmapper / Kernel Mapper Executable Found",
                        Risk = RiskLevel.Critical,
                        Location = filePath,
                        FileName = Path.GetFileName(filePath),
                        Reason = $"Known kernel mapper executable '{artifactName}' found in user-accessible location",
                        Detail = $"kdmapper and similar tools are used to load unsigned kernel drivers, bypassing Windows Driver Signature Enforcement. Path: {filePath}"
                    });
                }
            }

            foreach (var buildName in KdmapperBuildArtifacts)
            {
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> dirs;
                try
                {
                    dirs = Directory.EnumerateDirectories(dir, $"*{buildName}*", SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var buildDir in dirs)
                {
                    bool hasSys = false;
                    bool hasExe = false;
                    try
                    {
                        hasSys = Directory.GetFiles(buildDir, "*.sys", SearchOption.AllDirectories).Length > 0;
                        hasExe = Directory.GetFiles(buildDir, "*.exe", SearchOption.AllDirectories).Length > 0;
                    }
                    catch { }

                    if (hasSys || hasExe)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "kdmapper Build Artifact Directory Detected",
                            Risk = RiskLevel.Critical,
                            Location = buildDir,
                            FileName = Path.GetFileName(buildDir),
                            Reason = "Directory matching kdmapper build output naming found containing compiled binaries",
                            Detail = $"Build directory: {buildDir} — contains .sys={hasSys}, .exe={hasExe}"
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckByovdSysFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var userDirs = GetUserSearchRoots();

        foreach (var root in userDirs)
        {
            if (!Directory.Exists(root))
                continue;

            IEnumerable<string> sysFiles;
            try
            {
                sysFiles = Directory.EnumerateFiles(root, "*.sys", SearchOption.AllDirectories);
            }
            catch
            {
                continue;
            }

            foreach (var sysFile in sysFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var sysName = Path.GetFileName(sysFile);
                var match = ByovdSysNames.FirstOrDefault(n =>
                    n.Equals(sysName, StringComparison.OrdinalIgnoreCase));

                if (match != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "BYOVD Vulnerable Driver File Detected",
                        Risk = RiskLevel.Critical,
                        Location = sysFile,
                        FileName = sysName,
                        Reason = $"Known Bring Your Own Vulnerable Driver (BYOVD) target '{match}' found in user directory",
                        Detail = $"This driver has known vulnerabilities exploited by cheat software to gain kernel-level privileges. Path: {sysFile}"
                    });
                    continue;
                }

                if (!sysFile.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.System), StringComparison.OrdinalIgnoreCase) &&
                    !sysFile.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase))
                {
                    var parentDir = Path.GetDirectoryName(sysFile) ?? string.Empty;
                    var dirName = Path.GetFileName(parentDir);
                    if (dirName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Contains("driver", StringComparison.OrdinalIgnoreCase) ||
                        dirName.Contains("bypass", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Suspicious .sys Driver File in User Directory",
                            Risk = RiskLevel.High,
                            Location = sysFile,
                            FileName = sysName,
                            Reason = "Kernel driver (.sys) file found in user directory with suspicious parent folder name",
                            Detail = $"Driver file outside system directories in suspicious context: {sysFile}"
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckKernelCheatDllArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var userDirs = GetUserSearchRoots();

        foreach (var root in userDirs)
        {
            if (!Directory.Exists(root))
                continue;

            IEnumerable<string> dllFiles;
            try
            {
                dllFiles = Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories);
            }
            catch
            {
                continue;
            }

            foreach (var dllFile in dllFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(dllFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, System.Text.Encoding.Latin1);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch
                {
                    continue;
                }

                var matchedDeviceNames = KernelCheatDeviceNames
                    .Where(d => content.Contains(d, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matchedDeviceNames.Count > 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "DLL with Kernel Cheat Driver Communication Detected",
                        Risk = RiskLevel.Critical,
                        Location = dllFile,
                        FileName = Path.GetFileName(dllFile),
                        Reason = "DLL contains strings referencing known cheat driver device names used for kernel-level game manipulation",
                        Detail = $"Matched device names: {string.Join(", ", matchedDeviceNames)}"
                    });
                    continue;
                }

                var matchedCheatIndicators = CheatDllIndicators
                    .Where(i => content.Contains(i, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matchedCheatIndicators.Count >= 3 &&
                    content.Contains(@"\\.\", StringComparison.Ordinal))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "DLL with Kernel Driver I/O Communication Pattern",
                        Risk = RiskLevel.High,
                        Location = dllFile,
                        FileName = Path.GetFileName(dllFile),
                        Reason = "DLL contains multiple indicators of kernel driver communication (DeviceIoControl + device path patterns)",
                        Detail = $"Matched indicators: {string.Join(", ", matchedCheatIndicators.Take(5))}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckDriverInstallScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scriptExtensions = new[] { "*.bat", "*.cmd", "*.ps1", "*.psm1" };
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root))
                continue;

            foreach (var ext in scriptExtensions)
            {
                IEnumerable<string> scripts;
                try
                {
                    scripts = Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var script in scripts)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(script, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch
                    {
                        continue;
                    }

                    var matched = DriverInstallScriptKeywords
                        .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matched.Count >= 2)
                    {
                        bool hasTestSigning = content.Contains("testsigning", StringComparison.OrdinalIgnoreCase);
                        bool hasScCreate = content.Contains("sc create", StringComparison.OrdinalIgnoreCase) ||
                                           content.Contains("sc.exe create", StringComparison.OrdinalIgnoreCase);

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Driver Installation Script Detected",
                            Risk = hasTestSigning && hasScCreate ? RiskLevel.Critical : RiskLevel.High,
                            Location = script,
                            FileName = Path.GetFileName(script),
                            Reason = $"Script contains {matched.Count} keywords associated with kernel driver installation and test signing bypass",
                            Detail = $"Matched: {string.Join(", ", matched.Take(5))}"
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckKernelDebuggerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var userDirs = GetUserSearchRoots();

        foreach (var root in userDirs)
        {
            if (!Directory.Exists(root))
                continue;

            foreach (var dbgExe in KernelDebuggerArtifacts)
            {
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> found;
                try
                {
                    found = Directory.EnumerateFiles(root, dbgExe, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var filePath in found)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Kernel Debugger Executable Found in User Directory",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = dbgExe,
                        Reason = $"Kernel debugger executable '{dbgExe}' found outside standard installation paths",
                        Detail = $"Kernel debuggers are used in driver development and cheat driver testing. Path: {filePath}"
                    });
                }
            }

            foreach (var ext in KernelDebugWorkspaceExtensions)
            {
                IEnumerable<string> wsFiles;
                try
                {
                    wsFiles = Directory.EnumerateFiles(root, $"*{ext}", SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var wsFile in wsFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(wsFile);

                    if (ext.Equals(".kdmp", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".dmp", StringComparison.OrdinalIgnoreCase))
                    {
                        if (fileName.Contains("kernel", StringComparison.OrdinalIgnoreCase) ||
                            fileName.Contains("driver", StringComparison.OrdinalIgnoreCase) ||
                            fileName.Contains("kd_", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Kernel Crash Dump from Driver Development Found",
                                Risk = RiskLevel.Medium,
                                Location = wsFile,
                                FileName = fileName,
                                Reason = "Kernel crash dump file with driver development naming pattern found in user directory",
                                Detail = $"Kernel dump files indicate driver development or testing activity. Path: {wsFile}"
                            });
                        }
                    }
                    else if (ext.Equals(".wew", StringComparison.OrdinalIgnoreCase) ||
                             ext.Equals(".wes", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "WinDBG Workspace File Found",
                            Risk = RiskLevel.Medium,
                            Location = wsFile,
                            FileName = fileName,
                            Reason = "WinDBG workspace file found in user directory, indicating kernel debugging sessions",
                            Detail = $"WinDBG workspaces are used for kernel driver debugging and development. Path: {wsFile}"
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckKernelSymbolFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var userDirs = GetUserSearchRoots();
        var systemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";

        foreach (var root in userDirs)
        {
            if (!Directory.Exists(root))
                continue;

            foreach (var pdbName in KernelSymbolFileNames)
            {
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> found;
                try
                {
                    found = Directory.EnumerateFiles(root, pdbName, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var filePath in found)
                {
                    ctx.IncrementFiles();
                    if (!filePath.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Kernel Symbol PDB File Found Outside System Directory",
                            Risk = RiskLevel.High,
                            Location = filePath,
                            FileName = pdbName,
                            Reason = $"Kernel PDB symbol file '{pdbName}' found in non-standard user directory, indicating kernel driver development",
                            Detail = $"Kernel symbol files are downloaded by cheat developers to resolve kernel function addresses. Path: {filePath}"
                        });
                    }
                }
            }

            foreach (var ntoskrnlName in NtoskrnlCopyNames)
            {
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> found;
                try
                {
                    found = Directory.EnumerateFiles(root, ntoskrnlName, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var filePath in found)
                {
                    ctx.IncrementFiles();
                    if (!filePath.StartsWith(systemRoot, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "ntoskrnl.exe Copy Found in User Directory",
                            Risk = RiskLevel.Critical,
                            Location = filePath,
                            FileName = Path.GetFileName(filePath),
                            Reason = $"Windows kernel executable '{ntoskrnlName}' found outside Windows system directories",
                            Detail = $"Cheat developers copy ntoskrnl.exe to extract kernel structure offsets offline. Path: {filePath}"
                        });
                    }
                }
            }

            IEnumerable<string> symsrvDirs;
            try
            {
                symsrvDirs = Directory.EnumerateDirectories(root, "symbols", SearchOption.AllDirectories);
            }
            catch
            {
                continue;
            }

            foreach (var symDir in symsrvDirs)
            {
                ct.ThrowIfCancellationRequested();
                bool hasNtoskrnlSyms = false;
                try
                {
                    hasNtoskrnlSyms = Directory.EnumerateDirectories(symDir, "ntoskrnl*", SearchOption.TopDirectoryOnly).Any() ||
                                      Directory.EnumerateDirectories(symDir, "ntkrnl*", SearchOption.TopDirectoryOnly).Any();
                }
                catch { }

                if (hasNtoskrnlSyms)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Kernel Symbol Server Cache in Non-Standard Path",
                        Risk = RiskLevel.High,
                        Location = symDir,
                        FileName = Path.GetFileName(symDir),
                        Reason = "Symbol server cache containing ntoskrnl symbols found in user directory",
                        Detail = $"Symbol cache path: {symDir}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckProcessHollowingDumps(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var tempDirs = new[]
        {
            Environment.GetEnvironmentVariable("TEMP") ?? string.Empty,
            Environment.GetEnvironmentVariable("TMP") ?? string.Empty,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "Local", "Temp")
        };

        foreach (var tempDir in tempDirs.Where(d => !string.IsNullOrEmpty(d) && Directory.Exists(d)))
        {
            IEnumerable<string> dmpFiles;
            try
            {
                dmpFiles = Directory.EnumerateFiles(tempDir, "*.dmp", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(tempDir, "*.mdmp", SearchOption.AllDirectories));
            }
            catch
            {
                continue;
            }

            foreach (var dmpFile in dmpFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var dmpName = Path.GetFileNameWithoutExtension(dmpFile);
                var matchedProcess = HollowProcessDumpNames.FirstOrDefault(p =>
                    dmpName.Contains(p, StringComparison.OrdinalIgnoreCase));

                if (matchedProcess != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Process Dump of System Process in Temp Directory",
                        Risk = RiskLevel.Critical,
                        Location = dmpFile,
                        FileName = Path.GetFileName(dmpFile),
                        Reason = $"Memory dump of system process '{matchedProcess}' found in Temp directory, indicating possible process hollowing for driver loading",
                        Detail = $"Attackers hollow system processes to load kernel drivers undetected. Dump path: {dmpFile}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckKernelExploitSource(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var sourceExtensions = new[] { "*.c", "*.cpp", "*.h", "*.hpp", "*.py", "*.asm", "*.nasm" };
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root))
                continue;

            foreach (var ext in sourceExtensions)
            {
                IEnumerable<string> srcFiles;
                try
                {
                    srcFiles = Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var srcFile in srcFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(srcFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch
                    {
                        continue;
                    }

                    var matchedExploits = KernelExploitSourceKeywords
                        .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchedExploits.Count >= 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Kernel Exploit Source Code Detected",
                            Risk = RiskLevel.Critical,
                            Location = srcFile,
                            FileName = Path.GetFileName(srcFile),
                            Reason = $"Source file contains references to known kernel exploits: {string.Join(", ", matchedExploits.Take(3))}",
                            Detail = $"Full matched exploit references: {string.Join(", ", matchedExploits)}"
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckDriverSigningBypassTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root))
                continue;

            foreach (var toolName in SigningBypassArtifacts)
            {
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> found;
                try
                {
                    found = Directory.EnumerateFiles(root, toolName, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var filePath in found)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Driver Signing Bypass Tool Detected",
                        Risk = RiskLevel.Critical,
                        Location = filePath,
                        FileName = Path.GetFileName(filePath),
                        Reason = $"Known driver signing bypass tool '{toolName}' found in user directory",
                        Detail = $"These tools are used to bypass Windows Driver Signature Enforcement (DSE) to load cheat drivers. Path: {filePath}"
                    });
                }
            }

            var scriptExtensions = new[] { "*.bat", "*.cmd", "*.ps1" };
            foreach (var ext in scriptExtensions)
            {
                IEnumerable<string> scripts;
                try
                {
                    scripts = Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var script in scripts)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(script, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch
                    {
                        continue;
                    }

                    var matched = SigningBypassScriptKeywords
                        .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matched.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Driver Signing Bypass Script Detected",
                            Risk = RiskLevel.Critical,
                            Location = script,
                            FileName = Path.GetFileName(script),
                            Reason = $"Script contains {matched.Count} indicators of driver signing bypass operations",
                            Detail = $"Matched keywords: {string.Join(", ", matched.Take(5))}"
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckSsdtHookArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root))
                continue;

            foreach (var toolName in SsdtToolNames)
            {
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> found;
                try
                {
                    found = Directory.EnumerateFiles(root, toolName, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var filePath in found)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "SSDT Hook Tool Executable Found",
                        Risk = RiskLevel.Critical,
                        Location = filePath,
                        FileName = Path.GetFileName(filePath),
                        Reason = $"Known SSDT hooking tool '{toolName}' found in user directory",
                        Detail = $"SSDT hook tools manipulate the System Service Descriptor Table to intercept kernel calls, used in kernel-level cheats. Path: {filePath}"
                    });
                }
            }

            var sourceExtensions = new[] { "*.c", "*.cpp", "*.h", "*.hpp", "*.asm" };
            foreach (var ext in sourceExtensions)
            {
                IEnumerable<string> srcFiles;
                try
                {
                    srcFiles = Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var srcFile in srcFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(srcFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch
                    {
                        continue;
                    }

                    var matched = SsdtHookKeywords
                        .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matched.Count >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "SSDT/IRP Hook Implementation Source Code Detected",
                            Risk = RiskLevel.Critical,
                            Location = srcFile,
                            FileName = Path.GetFileName(srcFile),
                            Reason = $"Source file contains {matched.Count} SSDT/IRP hook-related kernel API references",
                            Detail = $"Matched: {string.Join(", ", matched.Take(6))}"
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckKernelPoolTagTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root))
                continue;

            foreach (var toolName in PoolTagToolNames)
            {
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> found;
                try
                {
                    found = Directory.EnumerateFiles(root, toolName, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var filePath in found)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Kernel Pool Tag Analysis Tool Found",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = Path.GetFileName(filePath),
                        Reason = $"Kernel pool tag analysis tool '{toolName}' found in user directory",
                        Detail = $"Pool tag tools are used by cheat developers to verify kernel driver allocation cleanup and evade detection. Path: {filePath}"
                    });
                }
            }

            var sourceExtensions = new[] { "*.c", "*.cpp", "*.h", "*.hpp" };
            foreach (var ext in sourceExtensions)
            {
                IEnumerable<string> srcFiles;
                try
                {
                    srcFiles = Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var srcFile in srcFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(srcFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch
                    {
                        continue;
                    }

                    var matched = PoolTagToolKeywords
                        .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matched.Count >= 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Kernel Pool Tag Analysis Source Code Detected",
                            Risk = RiskLevel.High,
                            Location = srcFile,
                            FileName = Path.GetFileName(srcFile),
                            Reason = $"Source file contains {matched.Count} kernel pool tag analysis API references, indicating driver cleanup code",
                            Detail = $"Matched: {string.Join(", ", matched.Take(5))}"
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckRegistryTracesForDrivers(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string servicesKey = @"SYSTEM\CurrentControlSet\Services";
        try
        {
            using var servicesRoot = Registry.LocalMachine.OpenSubKey(servicesKey, writable: false);
            if (servicesRoot != null)
            {
                foreach (var subKeyName in servicesRoot.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    var matchedDriverName = CheatDriverServiceKeywords.FirstOrDefault(n =>
                        subKeyName.Contains(n, StringComparison.OrdinalIgnoreCase));

                    if (matchedDriverName != null)
                    {
                        string? imagePath = null;
                        try
                        {
                            using var svcKey = servicesRoot.OpenSubKey(subKeyName, writable: false);
                            imagePath = svcKey?.GetValue("ImagePath") as string;
                        }
                        catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Driver Service Registry Entry Detected",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{servicesKey}\{subKeyName}",
                            FileName = subKeyName,
                            Reason = $"Windows Services registry key matching cheat driver name pattern '{matchedDriverName}' found",
                            Detail = $"Service: {subKeyName}, ImagePath: {imagePath ?? "(not set)"}"
                        });
                    }
                }
            }
        }
        catch { }

        const string ifeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        var gameExeNames = new[]
        {
            "csgo.exe", "cs2.exe", "valorant.exe", "VALORANT-Win64-Shipping.exe",
            "EscapeFromTarkov.exe", "FortniteClient-Win64-Shipping.exe",
            "r5apex.exe", "RainbowSix.exe", "Warzone.exe", "ModernWarfare.exe",
            "pubg.exe", "TslGame.exe", "ac_client.exe", "cod.exe"
        };

        try
        {
            using var ifeoRoot = Registry.LocalMachine.OpenSubKey(ifeoKey, writable: false);
            if (ifeoRoot != null)
            {
                foreach (var subKeyName in ifeoRoot.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    var isGameExe = gameExeNames.Any(g =>
                        subKeyName.Equals(g, StringComparison.OrdinalIgnoreCase));

                    if (isGameExe)
                    {
                        string? debugger = null;
                        try
                        {
                            using var ifeoSubKey = ifeoRoot.OpenSubKey(subKeyName, writable: false);
                            debugger = ifeoSubKey?.GetValue("Debugger") as string;
                        }
                        catch { }

                        if (!string.IsNullOrEmpty(debugger))
                        {
                            bool isSuspiciousDebugger = IfeoDumperValues.Any(d =>
                                debugger.Contains(d, StringComparison.OrdinalIgnoreCase));

                            if (isSuspiciousDebugger)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "IFEO Debugger Set on Game Executable",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKLM\{ifeoKey}\{subKeyName}",
                                    FileName = subKeyName,
                                    Reason = $"Image File Execution Options Debugger value set on game executable '{subKeyName}' to '{debugger}'",
                                    Detail = "IFEO Debugger hijacking by kernel driver allows intercepting game launch to inject cheat components"
                                });
                            }
                        }
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckPrefetchAndExecutionHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var prefetchDir = Path.Combine(
            Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows",
            "Prefetch");

        if (Directory.Exists(prefetchDir))
        {
            IEnumerable<string> pfFiles;
            try
            {
                pfFiles = Directory.EnumerateFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly);
            }
            catch
            {
                pfFiles = Array.Empty<string>();
            }

            foreach (var pfFile in pfFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var pfName = Path.GetFileName(pfFile);
                var matched = PrefetchCheatToolNames.FirstOrDefault(tool =>
                    pfName.StartsWith(tool, StringComparison.OrdinalIgnoreCase));

                if (matched != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Kernel Cheat Tool Execution Trace in Prefetch",
                        Risk = RiskLevel.Critical,
                        Location = pfFile,
                        FileName = pfName,
                        Reason = $"Windows Prefetch file for kernel cheat tool '{matched}' found, proving prior execution",
                        Detail = $"Prefetch file proves the kernel tool was previously executed on this system. Path: {pfFile}"
                    });
                }
            }
        }

        var amcachePath = Path.Combine(
            Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows",
            "AppCompat", "Programs", "Amcache.hve");

        if (File.Exists(amcachePath))
        {
            ctx.IncrementFiles();
            ctx.IncrementRegistryKeys();

            string content;
            try
            {
                using var fs = new FileStream(amcachePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs, System.Text.Encoding.Unicode);
                content = await sr.ReadToEndAsync(ct);
            }
            catch
            {
                content = string.Empty;
            }

            if (!string.IsNullOrEmpty(content))
            {
                var matched = AmcacheCheatToolKeywords
                    .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matched.Count > 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Kernel Cheat Tool References in Amcache",
                        Risk = RiskLevel.High,
                        Location = amcachePath,
                        FileName = "Amcache.hve",
                        Reason = $"Amcache execution history contains references to kernel cheat tools: {string.Join(", ", matched)}",
                        Detail = "Amcache records program execution history and can prove prior use of kernel driver tools"
                    });
                }
            }
        }
    }, ct);

    private Task CheckVirtualMachineArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root))
                continue;

            foreach (var diskName in VmDiskImageNames)
            {
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> found;
                try
                {
                    found = Directory.EnumerateFiles(root, diskName, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var filePath in found)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "VM Disk Image for Kernel Cheat Testing Found",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = diskName,
                        Reason = $"Virtual machine disk image '{diskName}' with cheat/driver testing naming convention found",
                        Detail = $"Cheat developers test kernel drivers in VMs before deploying to live systems. Path: {filePath}"
                    });
                }
            }

            var vmxFiles = Array.Empty<string>();
            var vboxFiles = Array.Empty<string>();
            try
            {
                vmxFiles = Directory.GetFiles(root, "*.vmx", SearchOption.AllDirectories);
            }
            catch { }
            try
            {
                vboxFiles = Directory.GetFiles(root, "*.vbox", SearchOption.AllDirectories);
            }
            catch { }

            var allVmConfigFiles = vmxFiles.Concat(vboxFiles);

            foreach (var vmConfigFile in allVmConfigFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string vmContent;
                try
                {
                    using var fs = new FileStream(vmConfigFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    vmContent = sr.ReadToEnd();
                }
                catch
                {
                    continue;
                }

                var matchedSnapshots = VmSnapshotKeywords
                    .Where(kw => vmContent.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matchedSnapshots.Count > 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "VM Snapshot Named for Pre-Driver-Install State Found",
                        Risk = RiskLevel.High,
                        Location = vmConfigFile,
                        FileName = Path.GetFileName(vmConfigFile),
                        Reason = $"VM configuration contains snapshots named for pre-driver-installation states: {string.Join(", ", matchedSnapshots)}",
                        Detail = $"VM config path: {vmConfigFile}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckCheatDriverIpcArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var sourceExtensions = new[] { "*.c", "*.cpp", "*.h", "*.hpp", "*.cs", "*.asm" };
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root))
                continue;

            foreach (var ext in sourceExtensions)
            {
                IEnumerable<string> srcFiles;
                try
                {
                    srcFiles = Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var srcFile in srcFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(srcFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch
                    {
                        continue;
                    }

                    var matchedIpc = CheatIpcKeywords
                        .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchedIpc.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Kernel Cheat Driver IPC Pattern Detected in Source",
                            Risk = RiskLevel.Critical,
                            Location = srcFile,
                            FileName = Path.GetFileName(srcFile),
                            Reason = $"Source code contains {matchedIpc.Count} indicators of kernel cheat driver IPC mechanisms (named pipes, shared memory sections)",
                            Detail = $"Matched IPC patterns: {string.Join(", ", matchedIpc.Take(5))}"
                        });
                    }
                }
            }

            var executableExtensions = new[] { "*.exe", "*.dll" };
            foreach (var ext in executableExtensions)
            {
                IEnumerable<string> exeFiles;
                try
                {
                    exeFiles = Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var exeFile in exeFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(exeFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, System.Text.Encoding.Latin1);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch
                    {
                        continue;
                    }

                    bool hasCheatPipe = content.Contains(@"\\.\pipe\cheat", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains(@"\\pipe\cheat", StringComparison.OrdinalIgnoreCase);
                    bool hasCheatSection = content.Contains(@"\BaseNamedObjects\CheatMem", StringComparison.OrdinalIgnoreCase) ||
                                          content.Contains(@"\BaseNamedObjects\KernelMem", StringComparison.OrdinalIgnoreCase);

                    if (hasCheatPipe || hasCheatSection)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Executable with Kernel Cheat IPC Strings Found",
                            Risk = RiskLevel.Critical,
                            Location = exeFile,
                            FileName = Path.GetFileName(exeFile),
                            Reason = "Executable contains named pipe or shared memory section names associated with kernel cheat driver communication",
                            Detail = $"IPC indicators — pipe: {hasCheatPipe}, section: {hasCheatSection}. Path: {exeFile}"
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckKernelCheatCompilationArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root))
                continue;

            IEnumerable<string> vcxprojFiles;
            try
            {
                vcxprojFiles = Directory.EnumerateFiles(root, "*.vcxproj", SearchOption.AllDirectories);
            }
            catch
            {
                continue;
            }

            foreach (var vcxproj in vcxprojFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(vcxproj, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch
                {
                    continue;
                }

                var matchedWdk = WdkProjectKeywords
                    .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matchedWdk.Count >= 2)
                {
                    bool hasNtDdk = NtDdkPathKeywords.Any(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "WDK Kernel Mode Driver Project File Detected",
                        Risk = hasNtDdk ? RiskLevel.Critical : RiskLevel.High,
                        Location = vcxproj,
                        FileName = Path.GetFileName(vcxproj),
                        Reason = $"Visual Studio project configured for kernel-mode driver compilation (WDK toolset) — {matchedWdk.Count} WDK indicators found",
                        Detail = $"WDK indicators: {string.Join(", ", matchedWdk.Take(5))}"
                    });

                    var projectDir = Path.GetDirectoryName(vcxproj) ?? string.Empty;
                    if (!string.IsNullOrEmpty(projectDir))
                    {
                        var binDirs = new[] { "x64\\Release", "x64\\Debug", "Release", "Debug", "bin" };
                        foreach (var binSubDir in binDirs)
                        {
                            var binPath = Path.Combine(projectDir, binSubDir);
                            if (!Directory.Exists(binPath))
                                continue;

                            IEnumerable<string> compiledSys;
                            try
                            {
                                compiledSys = Directory.EnumerateFiles(binPath, "*.sys", SearchOption.AllDirectories);
                            }
                            catch
                            {
                                continue;
                            }

                            foreach (var sysBin in compiledSys)
                            {
                                ctx.IncrementFiles();
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Compiled Kernel Driver Output in WDK Project",
                                    Risk = RiskLevel.Critical,
                                    Location = sysBin,
                                    FileName = Path.GetFileName(sysBin),
                                    Reason = "Compiled .sys kernel driver found in WDK project output directory",
                                    Detail = $"Compiled kernel driver binary output from project: {vcxproj}"
                                });
                            }
                        }
                    }
                }
            }

            IEnumerable<string> makefiles;
            try
            {
                makefiles = Directory.EnumerateFiles(root, "Makefile", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(root, "makefile", SearchOption.AllDirectories))
                    .Concat(Directory.EnumerateFiles(root, "GNUmakefile", SearchOption.AllDirectories));
            }
            catch
            {
                continue;
            }

            foreach (var makefile in makefiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(makefile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch
                {
                    continue;
                }

                var matched = NtDdkPathKeywords
                    .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matched.Count >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Makefile with NT DDK Kernel Build Paths Detected",
                        Risk = RiskLevel.High,
                        Location = makefile,
                        FileName = Path.GetFileName(makefile),
                        Reason = $"Makefile references NT DDK/WDK kernel build paths ({matched.Count} matches), indicating kernel driver compilation",
                        Detail = $"Matched DDK paths: {string.Join(", ", matched.Take(4))}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckAntiCheatDriverAnalysisTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var searchRoots = GetUserSearchRoots();

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root))
                continue;

            foreach (var dbName in AntiCheatDriverDbNames)
            {
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> found;
                try
                {
                    found = Directory.EnumerateFiles(root, dbName, SearchOption.AllDirectories);
                }
                catch
                {
                    continue;
                }

                foreach (var filePath in found)
                {
                    ctx.IncrementFiles();

                    var ext = Path.GetExtension(filePath).ToUpperInvariant();
                    string toolName = ext switch
                    {
                        ".IDB" or ".I64" => "IDA Pro",
                        ".BNDB" => "Binary Ninja",
                        ".GZF" => "Ghidra",
                        _ => "Reverse Engineering Tool"
                    };

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"{toolName} Database Targeting Anti-Cheat Driver Detected",
                        Risk = RiskLevel.Critical,
                        Location = filePath,
                        FileName = dbName,
                        Reason = $"{toolName} database file targeting known anti-cheat kernel driver found",
                        Detail = $"Reverse engineering databases for anti-cheat drivers are used to develop bypasses. Path: {filePath}"
                    });
                }
            }

            IEnumerable<string> ghidraProjectDirs;
            try
            {
                ghidraProjectDirs = Directory.EnumerateDirectories(root, "*.rep", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateDirectories(root, "*.gpr", SearchOption.AllDirectories));
            }
            catch
            {
                ghidraProjectDirs = Array.Empty<string>();
            }

            foreach (var ghidraDir in ghidraProjectDirs)
            {
                ct.ThrowIfCancellationRequested();

                var dirName = Path.GetFileName(ghidraDir);
                var matchedAcDriver = AntiCheatGhidraKeywords.FirstOrDefault(kw =>
                    dirName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                if (matchedAcDriver != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Ghidra Project Targeting Anti-Cheat Driver Detected",
                        Risk = RiskLevel.Critical,
                        Location = ghidraDir,
                        FileName = dirName,
                        Reason = $"Ghidra reverse engineering project targeting anti-cheat driver '{matchedAcDriver}' found",
                        Detail = $"Project path: {ghidraDir}"
                    });
                }
            }

            IEnumerable<string> idaDbFiles;
            try
            {
                idaDbFiles = Directory.EnumerateFiles(root, "*.idb", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(root, "*.i64", SearchOption.AllDirectories));
            }
            catch
            {
                idaDbFiles = Array.Empty<string>();
            }

            foreach (var idaDb in idaDbFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var idaName = Path.GetFileNameWithoutExtension(idaDb);
                var matchedAc = AntiCheatGhidraKeywords.FirstOrDefault(kw =>
                    idaName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                if (matchedAc != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "IDA Pro Database Targeting Anti-Cheat Kernel Driver",
                        Risk = RiskLevel.Critical,
                        Location = idaDb,
                        FileName = Path.GetFileName(idaDb),
                        Reason = $"IDA Pro database targeting anti-cheat driver component '{matchedAc}' found",
                        Detail = $"IDA database path: {idaDb}"
                    });
                }
            }

            IEnumerable<string> binaryNinjaFiles;
            try
            {
                binaryNinjaFiles = Directory.EnumerateFiles(root, "*.bndb", SearchOption.AllDirectories);
            }
            catch
            {
                binaryNinjaFiles = Array.Empty<string>();
            }

            foreach (var bndb in binaryNinjaFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var bndbName = Path.GetFileNameWithoutExtension(bndb);
                var matchedAc = AntiCheatGhidraKeywords.FirstOrDefault(kw =>
                    bndbName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                if (matchedAc != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Binary Ninja Database Targeting Anti-Cheat Driver",
                        Risk = RiskLevel.Critical,
                        Location = bndb,
                        FileName = Path.GetFileName(bndb),
                        Reason = $"Binary Ninja database targeting anti-cheat driver '{matchedAc}' found",
                        Detail = $"Binary Ninja database path: {bndb}"
                    });
                }
            }
        }
    }, ct);

    private static List<string> GetUserSearchRoots()
    {
        var roots = new List<string>();

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrEmpty(profile))
            roots.Add(profile);

        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        if (!string.IsNullOrEmpty(desktop) && !desktop.StartsWith(profile, StringComparison.OrdinalIgnoreCase))
            roots.Add(desktop);

        var downloads = Path.Combine(profile, "Downloads");
        roots.Add(downloads);

        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        if (!string.IsNullOrEmpty(documents))
            roots.Add(documents);

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrEmpty(localAppData))
        {
            roots.Add(localAppData);
            roots.Add(Path.Combine(localAppData, "Temp"));
        }

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (!string.IsNullOrEmpty(appData))
            roots.Add(appData);

        var temp = Environment.GetEnvironmentVariable("TEMP");
        if (!string.IsNullOrEmpty(temp))
            roots.Add(temp);

        var tmp = Environment.GetEnvironmentVariable("TMP");
        if (!string.IsNullOrEmpty(tmp) &&
            !string.Equals(tmp, temp, StringComparison.OrdinalIgnoreCase))
            roots.Add(tmp);

        var drives = DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
            .Select(d => d.RootDirectory.FullName);

        foreach (var drive in drives)
        {
            var usersDir = Path.Combine(drive, "Users");
            if (Directory.Exists(usersDir) &&
                !roots.Any(r => r.StartsWith(usersDir, StringComparison.OrdinalIgnoreCase)))
            {
                roots.Add(usersDir);
            }

            var cheatDir = Path.Combine(drive, "cheat");
            if (Directory.Exists(cheatDir))
                roots.Add(cheatDir);

            var hackDir = Path.Combine(drive, "hack");
            if (Directory.Exists(hackDir))
                roots.Add(hackDir);

            var driverDevDir = Path.Combine(drive, "driver_dev");
            if (Directory.Exists(driverDevDir))
                roots.Add(driverDevDir);

            var kernelDir = Path.Combine(drive, "kernel");
            if (Directory.Exists(kernelDir))
                roots.Add(kernelDir);
        }

        return roots.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
