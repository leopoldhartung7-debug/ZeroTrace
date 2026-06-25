using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class MappingDriverForensicScanModule : IScanModule
{
    public string Name => "Manual Mapping Driver Forensic Scan";
    public double Weight => 4.5;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    // -------------------------------------------------------------------------
    // Known mapper executable filenames (65+)
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> KnownMapperExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        "kdmapper.exe",
        "kdmapper_v2.exe",
        "phydm_mapper.exe",
        "gdrv_mapper.exe",
        "iqvw64_mapper.exe",
        "physmem_mapper.exe",
        "winring0_mapper.exe",
        "cpuz_mapper.exe",
        "msio64_mapper.exe",
        "dbutildrv2_mapper.exe",
        "dbutil_mapper.exe",
        "atikmpag_mapper.exe",
        "rttusb_mapper.exe",
        "bsod_mapper.exe",
        "vulfpeck_mapper.exe",
        "directio64_mapper.exe",
        "passmark_mapper.exe",
        "semav6msr64_mapper.exe",
        "elby_mapper.exe",
        "elby_clonedrive_mapper.exe",
        "evga_mapper.exe",
        "msi_mapper.exe",
        "gigabyte_mapper.exe",
        "asus_mapper.exe",
        "hp_mapper.exe",
        "dell_mapper.exe",
        "intel_mapper.exe",
        "amd_mapper.exe",
        "nv_mapper.exe",
        "manual_mapper.exe",
        "kernel_mapper.exe",
        "driver_mapper.exe",
        "ring0_mapper.exe",
        "kmapper.exe",
        "kdmap.exe",
        "physmap.exe",
        "loadlib_mapper.exe",
        "alloc_mapper.exe",
        "bypass_mapper.exe",
        "inject_mapper.exe",
        "usermode_mapper.exe",
        "shellcode_mapper.exe",
        "pe_mapper.exe",
        "dll_mapper.exe",
        "raw_mapper.exe",
        "memory_mapper.exe",
        "map_driver.exe",
        "map_kernel.exe",
        "map_process.exe",
        "syscall_mapper.exe",
        "vtdh_mapper.exe",
        "mhyprot_mapper.exe",
        "hyperion_mapper.exe",
        "be_mapper.exe",
        "vac_mapper.exe",
        "eac_mapper.exe",
        "ac_mapper.exe",
        "anticheat_bypass_mapper.exe",
        "game_mapper.exe",
        "cheat_mapper.exe",
        "hack_mapper.exe",
        "exploit_mapper.exe",
        "mapper_tool.exe",
        "mapper_v2.exe",
        "mapper_v3.exe",
        "mapper_x64.exe",
    };

    // -------------------------------------------------------------------------
    // Known vulnerable driver filenames — BYOVD (55+)
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> KnownVulnerableDriverFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        "iqvw64e.sys",
        "gdrv.sys",
        "gdrv2.sys",
        "physmem.sys",
        "phydm.sys",
        "cpuz_x64.sys",
        "winring0x64.sys",
        "winio64.sys",
        "msio64.sys",
        "dbutil_2_3.sys",
        "dbutil_3_0.sys",
        "dbutildrv2.sys",
        "atikmpag.sys",
        "rttusb.sys",
        "vulfpeck.sys",
        "directio64.sys",
        "PassmarkOSDS64.sys",
        "semav6msr64.sys",
        "elby.sys",
        "elby_cdrom.sys",
        "evga_eleet.sys",
        "HwRwDrv.sys",
        "glckio2.sys",
        "Asrdrv104.sys",
        "AsrDrv106.sys",
        "ASUS_drivers.sys",
        "RTCore64.sys",
        "MHYPROT2.sys",
        "mhyprot.sys",
        "mhyprot3.sys",
        "ProcExp152.sys",
        "ProcExp.sys",
        "aswSP.sys",
        "AsUpIO.sys",
        "AsUpIO64.sys",
        "MsIo64.sys",
        "LgCoreTemp.sys",
        "TdkLib64.sys",
        "IOmap64.sys",
        "MagniComp.sys",
        "nsiom.sys",
        "nsiom64.sys",
        "SentinelAgent.sys",
        "sfc64.sys",
        "kprocesshacker.sys",
        "kprocesshacker3.sys",
        "MiniDriverUnlocker.sys",
        "vmdrv.sys",
        "vmdrv64.sys",
        "netfilterdrv.sys",
        "TrueSight.sys",
        "inpoutx64.sys",
        "inpout32.sys",
        "winpmem.sys",
        "pmem.sys",
        "DumpIt.sys",
    };

    // -------------------------------------------------------------------------
    // Known mapper DLL filenames (45+)
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> KnownMapperDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "mapper.dll",
        "kdmapper.dll",
        "physmem.dll",
        "byovd.dll",
        "manual_map.dll",
        "kernel_map.dll",
        "ring0_map.dll",
        "driver_map.dll",
        "inject_map.dll",
        "bypass_map.dll",
        "pe_inject.dll",
        "shellcode_inject.dll",
        "raw_inject.dll",
        "memory_inject.dll",
        "process_inject.dll",
        "usermode_map.dll",
        "syscall_map.dll",
        "mhyprot_map.dll",
        "eac_bypass.dll",
        "be_bypass.dll",
        "vac_bypass.dll",
        "ac_bypass.dll",
        "driver_bypass.dll",
        "kernel_bypass.dll",
        "ring0_bypass.dll",
        "sign_bypass.dll",
        "dse_bypass.dll",
        "integrity_bypass.dll",
        "signature_bypass.dll",
        "driver_loader.dll",
        "kernel_loader.dll",
        "ring0_loader.dll",
        "driver_inject.dll",
        "kernel_inject.dll",
        "process_hollow.dll",
        "process_ghost.dll",
        "process_doppel.dll",
        "pe_hollow.dll",
        "pe_ghost.dll",
        "pe_doppel.dll",
        "section_map.dll",
        "memory_map.dll",
        "viewbase_map.dll",
        "alloc_map.dll",
        "loadlib_map.dll",
    };

    // -------------------------------------------------------------------------
    // Known BYOVD service names (35+)
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> ByovdServiceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "iqvw64e",
        "gdrv",
        "gdrv2",
        "physmem",
        "phydm",
        "cpuz",
        "winring0",
        "winio64",
        "msio64",
        "dbutil",
        "dbutildrv2",
        "atikmpag",
        "rttusb",
        "vulfpeck",
        "directio64",
        "passmark",
        "semav6msr64",
        "elby",
        "evga_eleet",
        "HwRwDrv",
        "glckio2",
        "Asrdrv",
        "RTCore64",
        "MHYPROT",
        "MHYPROT2",
        "ProcExp",
        "aswSP",
        "AsUpIO",
        "MsIo64",
        "LgCoreTemp",
        "TdkLib64",
        "IOmap64",
        "nsiom",
        "MagniComp",
        "netfilterdrv",
        "TrueSight",
        "inpoutx64",
        "inpout32",
        "winpmem",
        "pmem",
    };

    // -------------------------------------------------------------------------
    // Mapper config file names
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> MapperConfigFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "mapper.ini",
        "mapper.cfg",
        "mapper.json",
        "kdmapper.cfg",
        "physmem.cfg",
        "byovd.cfg",
        "byovd.json",
        "byovd.ini",
        "mapper_config.json",
        "driver_config.json",
        "mapping_config.json",
        "kernel_config.json",
        "inject_config.json",
        "bypass_config.json",
    };

    // Keywords that confirm a config file is mapper-related
    private static readonly string[] MapperConfigKeywords = new[]
    {
        "driver", "offset", "base", "signature", "bypass", "kernel", "ring0",
    };

    // -------------------------------------------------------------------------
    // Load script detection keywords (require 4+ matches)
    // -------------------------------------------------------------------------

    private static readonly string[] LoadScriptKeywords = new[]
    {
        "sc create",
        "sc start",
        "NtLoadDriver",
        "ZwLoadDriver",
        "kdmapper",
        "physmem",
        "byovd",
        "LoadDriver",
        "CreateService",
        "map_driver",
        "kernel_map",
        "ring0",
        "bypass_driver",
        "disable_dse",
        "dse_bypass",
        "sign_bypass",
        "bcdedit /set",
        "testsigning",
        "DriverEntry",
        "MmMapIoSpace",
        "MmAllocateNonCachedMemory",
    };

    // -------------------------------------------------------------------------
    // Known mapper download archive filenames (50+)
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> KnownMapperArchives = new(StringComparer.OrdinalIgnoreCase)
    {
        "kdmapper.zip",
        "kdmapper.rar",
        "physmem_mapper.zip",
        "byovd_toolkit.zip",
        "byovd_toolkit.rar",
        "manual_mapper.zip",
        "manual_mapper.rar",
        "driver_mapper.zip",
        "driver_mapper.rar",
        "mapper_tool.zip",
        "vulnerable_driver.zip",
        "vulnerable_driver.rar",
        "byovd_driver.zip",
        "byovd_driver.rar",
        "eac_bypass_driver.zip",
        "eac_bypass_driver.rar",
        "be_bypass_driver.zip",
        "vac_bypass_driver.zip",
        "ac_bypass_driver.zip",
        "kernel_mapper.zip",
        "kernel_mapper.rar",
        "mhyprot_mapper.zip",
        "ring0_mapper.zip",
        "pe_mapper.zip",
        "shellcode_mapper.zip",
        "gdrv_mapper.zip",
        "iqvw64_mapper.zip",
        "rtcore_mapper.zip",
        "byovd_pack.zip",
        "byovd_pack.rar",
        "driver_exploit.zip",
        "driver_exploit.rar",
        "kernel_exploit.zip",
        "kernel_exploit.rar",
        "ring0_toolkit.zip",
        "ring0_toolkit.rar",
        "driver_loader.zip",
        "driver_loader.rar",
        "kernel_loader.zip",
        "kernel_loader.rar",
        "map_driver.zip",
        "map_driver.rar",
        "physmem_driver.zip",
        "physmem_driver.rar",
        "vulnerable_sys.zip",
        "vulnerable_sys.rar",
        "kdm_tool.zip",
        "kdm_tool.rar",
        "bypass_driver_pack.zip",
        "byovd_collection.zip",
        "byovd_collection.rar",
    };

    // -------------------------------------------------------------------------
    // Prefetch stem keywords for mapper detection
    // -------------------------------------------------------------------------

    private static readonly string[] MapperPrefetchKeywords = new[]
    {
        "KDMAPPER",
        "PHYSMEM",
        "GDRV",
        "BYOVD",
        "DRVMAP",
        "DRIVERMAPPER",
        "KERNELMAPPER",
        "MHYPROT",
        "RTCORE",
        "IQVW",
        "CPUZBYPASS",
        "DSEFIXER",
        "DSEBYPASS",
        "KSBYPASS",
        "KPPBYPASS",
        "TESTMODEBYPASS",
        "MAP_DRIVER",
        "MAP_KERNEL",
        "LOADDRIVER",
        "BYPASSDRV",
        "KERNELBYPASS",
        "DRIVERBYPASS",
        "SIGBYPASS",
        "SIGNBYPASS",
        "PATCHGUARD",
        "NTOSKRNLPATCH",
        "KDMAP",
        "PHYSMAP",
        "MAPDRV",
        "MANUALMAP",
        "MANUALMAPPER",
        "RING0LOADER",
        "KERNELLOAD",
        "DRIVERLOAD",
        "BYPDRV",
        "GDRVSCAN",
        "MSIO64BYPASS",
        "NTIOLIB64",
        "WINIO64",
        "WINRING0",
        "INPOUT",
        "CPUZSYS",
        "ASWSP",
        "RTCOREPATCH",
        "MHYPROT2",
        "PROCEXP",
        "WINPMEM",
        "DUMPIT",
        "MAPPER",
        "RING0",
    };

    // -------------------------------------------------------------------------
    // UserAssist mapper executable names (ROT13 encoded in registry)
    // -------------------------------------------------------------------------

    private static readonly HashSet<string> MapperUserAssistNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "kdmapper.exe",
        "kdmapper_v2.exe",
        "physmem_mapper.exe",
        "gdrv_mapper.exe",
        "manual_mapper.exe",
        "kernel_mapper.exe",
        "driver_mapper.exe",
        "ring0_mapper.exe",
        "kmapper.exe",
        "kdmap.exe",
        "physmap.exe",
        "bypass_mapper.exe",
        "inject_mapper.exe",
        "mhyprot_mapper.exe",
        "be_mapper.exe",
        "vac_mapper.exe",
        "eac_mapper.exe",
        "mapper_tool.exe",
        "mapper_v2.exe",
        "mapper_v3.exe",
        "mapper_x64.exe",
        "map_driver.exe",
        "map_kernel.exe",
    };

    // -------------------------------------------------------------------------
    // Directory paths
    // -------------------------------------------------------------------------

    private static string System32Dir =>
        Environment.GetFolderPath(Environment.SpecialFolder.System);

    private static string System32Drivers =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers");

    private static string WindowsTempDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp");

    private static string UserTempDir => Path.GetTempPath();

    private static string DesktopDir =>
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

    private static string DownloadsDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

    private static string LocalAppDataDir =>
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static string RoamingAppDataDir =>
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    private static string PrefetchDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

    private static string WinEvtLogsDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"winevt\Logs");

    // -------------------------------------------------------------------------
    // RunAsync — all 10 checks in parallel
    // -------------------------------------------------------------------------

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting manual mapping driver forensic scan...");

        return Task.WhenAll(
            CheckKnownMapperExecutables(ctx, ct),
            CheckKnownVulnerableDriverFiles(ctx, ct),
            CheckMapperConfigArtifacts(ctx, ct),
            CheckMapperLoadScripts(ctx, ct),
            CheckByovdRegistryArtifacts(ctx, ct),
            CheckMapperDownloadArtifacts(ctx, ct),
            CheckMapperPrefetchArtifacts(ctx, ct),
            CheckMapperEventLogArtifacts(ctx, ct),
            CheckKnownMapperDlls(ctx, ct),
            CheckMapperTemporaryArtifacts(ctx, ct)
        );
    }

    // -------------------------------------------------------------------------
    // Check 1: Known mapper executables
    // -------------------------------------------------------------------------

    private Task CheckKnownMapperExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                System32Dir,
                UserTempDir,
                WindowsTempDir,
                DesktopDir,
                DownloadsDir,
                LocalAppDataDir,
                RoamingAppDataDir,
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try
                {
                    files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }
                catch (IOException)
                {
                    continue;
                }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file);
                    if (!KnownMapperExecutables.Contains(fn)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known Mapper Executable Found: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"The file '{fn}' matches a known manual-mapping or BYOVD driver mapper tool. " +
                                 "These tools are used to load unsigned kernel drivers by exploiting vulnerable " +
                                 "signed drivers, bypassing Driver Signature Enforcement (DSE).",
                        Detail = $"Path: {file} | Directory: {dir}"
                    });
                }

                await Task.Yield();
            }

            // Check AppData subdirectories one level deep
            foreach (var baseDir in new[] { LocalAppDataDir, RoamingAppDataDir })
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(baseDir)) continue;

                string[] subDirs;
                try { subDirs = Directory.GetDirectories(baseDir); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var sub in subDirs)
                {
                    if (ct.IsCancellationRequested) return;

                    string[] subFiles;
                    try { subFiles = Directory.GetFiles(sub, "*.exe", SearchOption.TopDirectoryOnly); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in subFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var fn = Path.GetFileName(file);
                        if (!KnownMapperExecutables.Contains(fn)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Known Mapper Executable in AppData Subdirectory: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"The file '{fn}' matches a known manual-mapping/BYOVD tool found in an AppData " +
                                     "subdirectory. AppData subdirectories are a typical staging location for cheat " +
                                     "loaders and mapper tools to evade superficial directory scans.",
                            Detail = $"Path: {file}"
                        });
                    }

                    await Task.Yield();
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 2: Known vulnerable driver files (BYOVD)
    // -------------------------------------------------------------------------

    private Task CheckKnownVulnerableDriverFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var topLevelDirs = new[]
            {
                System32Drivers,
                UserTempDir,
                WindowsTempDir,
                LocalAppDataDir,
                DownloadsDir,
            };

            foreach (var dir in topLevelDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try
                {
                    files = Directory.GetFiles(dir, "*.sys", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }
                catch (IOException)
                {
                    continue;
                }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file);
                    if (!KnownVulnerableDriverFiles.Contains(fn)) continue;

                    bool isInDriversDir = dir.Equals(System32Drivers, StringComparison.OrdinalIgnoreCase);
                    var risk = RiskLevel.High;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known Vulnerable BYOVD Driver File: {fn}",
                        Risk = risk,
                        Location = file,
                        FileName = fn,
                        Reason = $"Driver file '{fn}' matches a known vulnerable driver used in BYOVD " +
                                 "(Bring Your Own Vulnerable Driver) attacks. These drivers contain exploitable " +
                                 "kernel-level vulnerabilities that allow usermode code to gain ring-0 access " +
                                 "and map unsigned drivers into kernel memory without triggering DSE checks.",
                        Detail = $"Path: {file} | " +
                                 (isInDriversDir
                                     ? "Found in System32\\drivers — driver may have been loaded as a service."
                                     : "Found outside System32\\drivers — likely a staged/dropped payload.")
                    });
                }

                await Task.Yield();
            }

            // Deep scan RoamingAppData for any .sys files
            if (!ct.IsCancellationRequested && Directory.Exists(RoamingAppDataDir))
            {
                string[] appDataSysFiles;
                try
                {
                    appDataSysFiles = Directory.GetFiles(RoamingAppDataDir, "*.sys",
                        SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { appDataSysFiles = Array.Empty<string>(); }
                catch (IOException) { appDataSysFiles = Array.Empty<string>(); }

                foreach (var file in appDataSysFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file);
                    if (!KnownVulnerableDriverFiles.Contains(fn)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Vulnerable BYOVD Driver in AppData: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Known vulnerable driver '{fn}' was found in AppData — a non-standard location " +
                                 "for driver files. This strongly indicates the file is a staged BYOVD payload " +
                                 "waiting to be registered and loaded by a mapper tool.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 3: Mapper config file artifacts
    // -------------------------------------------------------------------------

    private Task CheckMapperConfigArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                UserTempDir,
                WindowsTempDir,
                DesktopDir,
                DownloadsDir,
                LocalAppDataDir,
                RoamingAppDataDir,
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] allFiles;
                try { allFiles = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in allFiles)
                {
                    if (ct.IsCancellationRequested) return;

                    var fn = Path.GetFileName(file);
                    if (!MapperConfigFileNames.Contains(fn)) continue;

                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    var matchedKeywords = MapperConfigKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchedKeywords.Count == 0) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Mapper Configuration File: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Configuration file '{fn}' associated with manual-mapping driver tools was found " +
                                 "and its content contains keywords typical of BYOVD/mapper configurations, " +
                                 "including driver loading parameters, kernel offsets, and bypass settings.",
                        Detail = $"Path: {file} | Matched keywords: {string.Join(", ", matchedKeywords)}"
                    });
                }

                await Task.Yield();
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 4: Mapper driver-load scripts
    // -------------------------------------------------------------------------

    private Task CheckMapperLoadScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var scriptExtensions = new[] { "*.ps1", "*.bat", "*.vbs", "*.py" };
            var searchDirs = new[]
            {
                UserTempDir,
                WindowsTempDir,
                DesktopDir,
                DownloadsDir,
                LocalAppDataDir,
                RoamingAppDataDir,
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                foreach (var ext in scriptExtensions)
                {
                    string[] files;
                    try
                    {
                        files = Directory.GetFiles(dir, ext, SearchOption.AllDirectories);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in files)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        string content;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read,
                                FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (UnauthorizedAccessException) { continue; }
                        catch (IOException) { continue; }

                        var matchedKeywords = LoadScriptKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matchedKeywords.Count < 4) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Mapper Driver Load Script Found: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Script file '{Path.GetFileName(file)}' contains " +
                                     $"{matchedKeywords.Count} keywords strongly associated with driver " +
                                     "manual-mapping and BYOVD loading operations. These scripts automate " +
                                     "unsigned kernel driver loading and DSE bypass configuration.",
                            Detail = $"Path: {file} | Matched keywords ({matchedKeywords.Count}): " +
                                     string.Join(", ", matchedKeywords.Take(10))
                        });
                    }

                    await Task.Yield();
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 5: BYOVD registry artifacts
    // -------------------------------------------------------------------------

    private Task CheckByovdRegistryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            // 5a — HKLM\SYSTEM\CurrentControlSet\Services — look for BYOVD service entries
            try
            {
                using var servicesKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services", writable: false);
                if (servicesKey != null)
                {
                    foreach (var svcName in servicesKey.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        if (!ByovdServiceNames.Contains(svcName)) continue;

                        string? imagePath = null;
                        int? startType = null;
                        try
                        {
                            using var svcKey = servicesKey.OpenSubKey(svcName, writable: false);
                            if (svcKey != null)
                            {
                                imagePath = svcKey.GetValue("ImagePath") as string;
                                startType = svcKey.GetValue("Start") as int?;
                                ctx.IncrementRegistryKeys();
                            }
                        }
                        catch (IOException) { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"BYOVD Vulnerable Driver Service Registered: {svcName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = imagePath != null ? Path.GetFileName(imagePath) : null,
                            Reason = $"Windows service '{svcName}' matches a known vulnerable driver used in BYOVD " +
                                     "attacks. A registered service entry indicates the vulnerable driver was " +
                                     "installed, which is a prerequisite step in the BYOVD kernel-map chain.",
                            Detail = $"Service: {svcName} | ImagePath: {imagePath ?? "N/A"} | " +
                                     $"StartType: {startType?.ToString() ?? "N/A"}"
                        });
                    }
                }
            }
            catch (IOException) { }

            // 5b — HKCU\Software — mapper tool installation remnants
            try
            {
                using var hkcuSw = Registry.CurrentUser.OpenSubKey(@"Software", writable: false);
                if (hkcuSw != null)
                {
                    foreach (var keyName in hkcuSw.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        bool isMapperRelated =
                            keyName.Contains("mapper", StringComparison.OrdinalIgnoreCase) ||
                            keyName.Contains("kdmapper", StringComparison.OrdinalIgnoreCase) ||
                            keyName.Contains("byovd", StringComparison.OrdinalIgnoreCase) ||
                            keyName.Contains("physmem", StringComparison.OrdinalIgnoreCase) ||
                            keyName.Contains("ring0", StringComparison.OrdinalIgnoreCase) ||
                            keyName.Contains("driver_map", StringComparison.OrdinalIgnoreCase) ||
                            keyName.Contains("kernel_map", StringComparison.OrdinalIgnoreCase) ||
                            keyName.Contains("dse_bypass", StringComparison.OrdinalIgnoreCase) ||
                            keyName.Contains("sign_bypass", StringComparison.OrdinalIgnoreCase);

                        if (!isMapperRelated) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Mapper Tool Registry Remnant: HKCU\\Software\\{keyName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\Software\{keyName}",
                            Reason = $"Registry key '{keyName}' under HKCU\\Software contains keywords associated " +
                                     "with manual-mapping or BYOVD driver tools. This is a configuration remnant " +
                                     "left by a mapper tool that was installed or run on this system.",
                            Detail = $"Key: HKCU\\Software\\{keyName}"
                        });
                    }
                }
            }
            catch (IOException) { }

            // 5c — UserAssist — ROT13-encoded mapper executable execution evidence
            try
            {
                using var uaRoot = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                    writable: false);
                if (uaRoot != null)
                {
                    foreach (var guidName in uaRoot.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        using var countKey = uaRoot.OpenSubKey($@"{guidName}\Count", writable: false);
                        if (countKey == null) continue;

                        foreach (var valName in countKey.GetValueNames())
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementRegistryKeys();

                            var decoded = Rot13Decode(valName);
                            var fn = Path.GetFileName(decoded);

                            if (!MapperUserAssistNames.Contains(fn)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Mapper Executable in UserAssist: {fn}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\" +
                                           $@"{guidName}\Count",
                                FileName = fn,
                                Reason = $"UserAssist entry decodes to '{fn}' (ROT13), matching a known mapper tool. " +
                                         "UserAssist records GUI program execution with run count and timestamps, " +
                                         "providing forensic evidence even after the executable was deleted.",
                                Detail = $"Encoded value: {valName} | Decoded: {decoded}"
                            });
                        }
                    }
                }
            }
            catch (IOException) { }

            // 5d — MUICache — mapper execution evidence
            var muiCachePaths = new[]
            {
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                @"Software\Microsoft\Windows\ShellNoRoam\MUICache",
            };

            foreach (var muiPath in muiCachePaths)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var muiKey = Registry.CurrentUser.OpenSubKey(muiPath, writable: false);
                    if (muiKey == null) continue;

                    foreach (var valName in muiKey.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        var fn = Path.GetFileName(valName);
                        if (!KnownMapperExecutables.Contains(fn)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Mapper Executable in MUICache: {fn}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{muiPath}",
                            FileName = fn,
                            Reason = $"MUICache entry references the mapper executable '{fn}'. The MUICache " +
                                     "stores the full path of every GUI application that ran, providing forensic " +
                                     "evidence of mapper tool execution even after file deletion.",
                            Detail = $"MUICache entry: {valName}"
                        });
                    }
                }
                catch (IOException) { }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 6: Mapper download artifacts (archives in Downloads and Desktop)
    // -------------------------------------------------------------------------

    private Task CheckMapperDownloadArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[] { DownloadsDir, DesktopDir };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try { files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file);

                    // Exact name match
                    if (KnownMapperArchives.Contains(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Mapper Tool Archive in Downloads/Desktop: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Archive '{fn}' matches a known mapper or BYOVD toolkit distribution " +
                                     "package. These archives are distributed on forums and repositories that " +
                                     "provide BYOVD exploit kits and vulnerable driver collections.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    // Heuristic keyword match on archive filenames
                    var ext = Path.GetExtension(fn).ToLowerInvariant();
                    if (ext != ".zip" && ext != ".rar" && ext != ".7z") continue;

                    bool hasMapperKeyword =
                        fn.Contains("byovd", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("kdmapper", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("physmem_mapper", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("driver_mapper", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("vulnerable_driver", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("kernel_mapper", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("ring0_mapper", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("dse_bypass", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("sign_bypass", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("mhyprot_mapper", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("gdrv_mapper", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("rtcore_mapper", StringComparison.OrdinalIgnoreCase);

                    if (!hasMapperKeyword) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious Mapper-Related Archive: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"Archive '{fn}' contains keywords associated with BYOVD and driver-mapping " +
                                 "toolkit distributions. The filename pattern is characteristic of kernel " +
                                 "exploitation framework packages.",
                        Detail = $"Path: {file}"
                    });
                }

                await Task.Yield();
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 7: Mapper prefetch artifacts
    // -------------------------------------------------------------------------

    private Task CheckMapperPrefetchArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            if (!Directory.Exists(PrefetchDir)) return;

            string[] pfFiles;
            try
            {
                pfFiles = Directory.GetFiles(PrefetchDir, "*.pf", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            var now = DateTime.UtcNow;

            foreach (var pf in pfFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var pfStem = Path.GetFileNameWithoutExtension(pf).ToUpperInvariant();
                // Strip trailing -XXXXXXXX hash suffix (exactly 9 chars: dash + 8 hex digits)
                var dashIdx = pfStem.LastIndexOf('-');
                var exeStem = (dashIdx >= 0 && dashIdx == pfStem.Length - 9)
                    ? pfStem[..dashIdx]
                    : pfStem;

                var matchedKeyword = MapperPrefetchKeywords.FirstOrDefault(k =>
                    exeStem.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (matchedKeyword == null) continue;

                DateTime lastWrite;
                try { lastWrite = File.GetLastWriteTimeUtc(pf); }
                catch { lastWrite = DateTime.MinValue; }

                bool isRecent = lastWrite > now.AddDays(-30);

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Mapper/BYOVD Tool in Windows Prefetch: {Path.GetFileName(pf)}",
                    Risk = isRecent ? RiskLevel.High : RiskLevel.Medium,
                    Location = pf,
                    FileName = Path.GetFileName(pf),
                    Reason = $"Prefetch file '{Path.GetFileName(pf)}' (executable stem: '{exeStem}') matches " +
                             $"mapper/BYOVD keyword '{matchedKeyword}'. Windows Prefetch confirms this executable " +
                             "ran on this system. Prefetch entries survive after the executable is deleted.",
                    Detail = $"Executable stem: {exeStem} | Keyword: {matchedKeyword} | " +
                             $"Last write: {lastWrite:yyyy-MM-dd} | " +
                             (isRecent ? "RECENT (within 30 days)" : "Historical entry")
                });

                await Task.Yield();
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 8: Mapper event log artifacts
    // -------------------------------------------------------------------------

    private Task CheckMapperEventLogArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            // 8a — Binary scan System.evtx for BYOVD service-install (7045) evidence
            var systemEvtx = Path.Combine(WinEvtLogsDir, "System.evtx");
            if (File.Exists(systemEvtx))
            {
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(systemEvtx, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite);
                    int readLen = (int)Math.Min(524288L, fs.Length);
                    var buf = new byte[readLen];
                    int bytesRead = 0;
                    while (bytesRead < readLen)
                    {
                        int n = await fs.ReadAsync(buf, bytesRead, readLen - bytesRead, ct);
                        if (n == 0) break;
                        bytesRead += n;
                    }

                    var content = System.Text.Encoding.Latin1.GetString(buf, 0, bytesRead);

                    // Check if event log binary contains 7045 (service install event indicator string)
                    if (content.Contains("7045", StringComparison.Ordinal))
                    {
                        // Look for BYOVD driver names near service install events
                        foreach (var driverName in ByovdServiceNames)
                        {
                            if (ct.IsCancellationRequested) return;
                            if (!content.Contains(driverName, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"BYOVD Driver Name in System Event Log: {driverName}",
                                Risk = RiskLevel.High,
                                Location = systemEvtx,
                                FileName = "System.evtx",
                                Reason = $"The Windows System event log binary contains references to the known " +
                                         $"vulnerable driver name '{driverName}' alongside EventID 7045 " +
                                         "(new service installed). This indicates a BYOVD driver was registered " +
                                         "as a service, which is a prerequisite for kernel exploitation.",
                                Detail = $"Driver name found in log: {driverName} | Log: {systemEvtx}"
                            });
                            break; // One finding per log file scan to avoid noise
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }

            // 8b — Secondary Prefetch sweep for well-known mapper names
            if (Directory.Exists(PrefetchDir))
            {
                var highConfidenceMapperStems = new[]
                {
                    "kdmapper", "physmem", "gdrv", "byovd", "drvmap", "kernelmapper",
                    "mhyprot", "rtcore", "iqvw64", "dsebypass", "dsefixer",
                };

                string[] pfFiles;
                try
                {
                    pfFiles = Directory.GetFiles(PrefetchDir, "*.pf", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { pfFiles = Array.Empty<string>(); }
                catch (IOException) { pfFiles = Array.Empty<string>(); }

                foreach (var pf in pfFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var pfName = Path.GetFileName(pf).ToLowerInvariant();
                    var matched = highConfidenceMapperStems.FirstOrDefault(n =>
                        pfName.Contains(n, StringComparison.OrdinalIgnoreCase));

                    if (matched == null) continue;

                    DateTime lastWrite;
                    try { lastWrite = File.GetLastWriteTimeUtc(pf); }
                    catch { lastWrite = DateTime.MinValue; }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"High-Confidence Mapper Prefetch (EventLog Context): {Path.GetFileName(pf)}",
                        Risk = RiskLevel.High,
                        Location = pf,
                        FileName = Path.GetFileName(pf),
                        Reason = $"Prefetch file '{Path.GetFileName(pf)}' contains high-confidence mapper keyword " +
                                 $"'{matched}'. Discovered during event log artifact analysis, corroborating " +
                                 "evidence of mapper tool execution on this system.",
                        Detail = $"Matched: {matched} | Last write: {lastWrite:yyyy-MM-dd}"
                    });
                }
            }

            // 8c — Temp directory sweep for .sys and .dmp mapper artifacts
            foreach (var tempDir in new[] { UserTempDir, WindowsTempDir })
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tempDir)) continue;

                foreach (var pattern in new[] { "*.sys", "*.dmp" })
                {
                    string[] files;
                    try
                    {
                        files = Directory.GetFiles(tempDir, pattern, SearchOption.TopDirectoryOnly);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in files)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var fn = Path.GetFileName(file);
                        bool isKnownVuln = KnownVulnerableDriverFiles.Contains(fn);
                        bool hasSuspiciousName =
                            fn.Contains("mapper", StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains("byovd", StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains("kdmap", StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains("physmem", StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains("gdrv", StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains("mhyprot", StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains("rtcore", StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains("bsod", StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains("crash", StringComparison.OrdinalIgnoreCase);

                        if (!isKnownVuln && !hasSuspiciousName) continue;

                        long fileSize = 0;
                        DateTime modified = DateTime.MinValue;
                        try { var fi = new FileInfo(file); fileSize = fi.Length; modified = fi.LastWriteTime; }
                        catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = isKnownVuln
                                ? $"Known Vulnerable Driver in Temp (EventLog Check): {fn}"
                                : $"Mapper Crash/Temp Artifact: {fn}",
                            Risk = isKnownVuln ? RiskLevel.High : RiskLevel.Medium,
                            Location = file,
                            FileName = fn,
                            Reason = isKnownVuln
                                ? $"Known BYOVD driver '{fn}' found in Temp. Mapper tools drop vulnerable " +
                                  "drivers to Temp before service registration."
                                : $"File '{fn}' in Temp matches mapper/crash patterns. Mappers leave " +
                                  "driver and dump artifacts in Temp when they crash or fail.",
                            Detail = $"Path: {file} | Size: {fileSize} bytes | Modified: {modified:yyyy-MM-dd}"
                        });
                    }

                    await Task.Yield();
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 9: Known mapper DLL files
    // -------------------------------------------------------------------------

    private Task CheckKnownMapperDlls(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = new[]
            {
                System32Dir,
                UserTempDir,
                WindowsTempDir,
                DesktopDir,
                DownloadsDir,
                LocalAppDataDir,
                RoamingAppDataDir,
            };

            foreach (var dir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dir)) continue;

                string[] files;
                try
                {
                    files = Directory.GetFiles(dir, "*.dll", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file);
                    if (!KnownMapperDlls.Contains(fn)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Known Mapper DLL Found: {fn}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason = $"DLL file '{fn}' matches a known manual-mapping or code-injection library. " +
                                 "These DLLs implement core mapping logic for usermode-to-kernel injection, " +
                                 "process injection techniques (hollowing, ghosting, doppelgänging), or DSE " +
                                 "bypass routines used to load unsigned kernel drivers.",
                        Detail = $"Path: {file} | Directory: {dir}"
                    });
                }

                // Check AppData subdirs one level deep
                if (dir == LocalAppDataDir || dir == RoamingAppDataDir)
                {
                    string[] subDirs;
                    try { subDirs = Directory.GetDirectories(dir); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var sub in subDirs)
                    {
                        if (ct.IsCancellationRequested) return;

                        string[] subFiles;
                        try
                        {
                            subFiles = Directory.GetFiles(sub, "*.dll", SearchOption.TopDirectoryOnly);
                        }
                        catch (UnauthorizedAccessException) { continue; }
                        catch (IOException) { continue; }

                        foreach (var file in subFiles)
                        {
                            if (ct.IsCancellationRequested) return;
                            ctx.IncrementFiles();

                            var fn = Path.GetFileName(file);
                            if (!KnownMapperDlls.Contains(fn)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Known Mapper DLL in AppData Subdirectory: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Mapper DLL '{fn}' found in an AppData subdirectory. This is a common " +
                                         "staging location for injection libraries used by usermode mapper tools " +
                                         "prior to loading the vulnerable driver.",
                                Detail = $"Path: {file}"
                            });
                        }
                    }
                }

                await Task.Yield();
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Check 10: Mapper temporary directory artifacts
    // -------------------------------------------------------------------------

    private Task CheckMapperTemporaryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var tempDirs = new[]
            {
                UserTempDir,
                WindowsTempDir,
                Path.Combine(LocalAppDataDir, "Temp"),
            };

            foreach (var tempDir in tempDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(tempDir)) continue;

                // Check for .sys files (dropped driver payloads)
                string[] sysFiles;
                try
                {
                    sysFiles = Directory.GetFiles(tempDir, "*.sys", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { sysFiles = Array.Empty<string>(); }
                catch (IOException) { sysFiles = Array.Empty<string>(); }

                foreach (var file in sysFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file);
                    bool isKnownVuln = KnownVulnerableDriverFiles.Contains(fn);
                    bool hasSuspiciousName =
                        fn.Contains("drv", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("driver", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("mapper", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("kernel", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("ring0", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("physmem", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("byovd", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("gdrv", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("mhyprot", StringComparison.OrdinalIgnoreCase);

                    if (!isKnownVuln && !hasSuspiciousName) continue;

                    long fileSize = 0;
                    DateTime modified = DateTime.MinValue;
                    try
                    {
                        var fi = new FileInfo(file);
                        fileSize = fi.Length;
                        modified = fi.LastWriteTime;
                    }
                    catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = isKnownVuln
                            ? $"Known Vulnerable Driver Dropped to Temp: {fn}"
                            : $"Suspicious Driver File in Temp Directory: {fn}",
                        Risk = isKnownVuln ? RiskLevel.High : RiskLevel.Medium,
                        Location = file,
                        FileName = fn,
                        Reason = isKnownVuln
                            ? $"Known BYOVD vulnerable driver '{fn}' found in the Temp directory. Mapper tools " +
                              "extract the vulnerable driver to Temp before registering it as a Windows service."
                            : $"Driver file '{fn}' in Temp has a name suggesting mapper/bypass activity. " +
                              "Driver files do not normally reside in Temp; their presence strongly indicates " +
                              "a staged BYOVD payload from a manual-mapping tool.",
                        Detail = $"Path: {file} | Temp dir: {tempDir} | " +
                                 $"Size: {fileSize} bytes | Modified: {modified:yyyy-MM-dd HH:mm:ss}"
                    });
                }

                // Check for .dmp files (mapper crash artifacts)
                string[] dmpFiles;
                try
                {
                    dmpFiles = Directory.GetFiles(tempDir, "*.dmp", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { dmpFiles = Array.Empty<string>(); }
                catch (IOException) { dmpFiles = Array.Empty<string>(); }

                foreach (var file in dmpFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file);
                    bool hasMapperKeyword =
                        fn.Contains("mapper", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("kdmap", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("byovd", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("physmem", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("gdrv", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("mhyprot", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("bsod", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("driver_crash", StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains("kernel_crash", StringComparison.OrdinalIgnoreCase);

                    if (!hasMapperKeyword) continue;

                    long fileSize = 0;
                    DateTime modified = DateTime.MinValue;
                    try
                    {
                        var fi = new FileInfo(file);
                        fileSize = fi.Length;
                        modified = fi.LastWriteTime;
                    }
                    catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Mapper Crash Dump in Temp Directory: {fn}",
                        Risk = RiskLevel.Medium,
                        Location = file,
                        FileName = fn,
                        Reason = $"Dump file '{fn}' in Temp contains keywords associated with mapper or BYOVD " +
                                 "tools. Mappers that cause kernel instability (failed driver loads, BSODs) " +
                                 "leave crash dump files in Temp as forensic artifacts of exploitation attempts.",
                        Detail = $"Path: {file} | Temp dir: {tempDir} | " +
                                 $"Size: {fileSize} bytes | Modified: {modified:yyyy-MM-dd HH:mm:ss}"
                    });
                }

                // Check for any files named with mapper keywords regardless of extension
                string[] allTempFiles;
                try
                {
                    allTempFiles = Directory.GetFiles(tempDir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { allTempFiles = Array.Empty<string>(); }
                catch (IOException) { allTempFiles = Array.Empty<string>(); }

                foreach (var file in allTempFiles)
                {
                    if (ct.IsCancellationRequested) return;

                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(fn).ToLowerInvariant();
                    // Already handled .sys and .dmp above
                    if (ext == ".sys" || ext == ".dmp") continue;

                    bool isMapperNamed =
                        fn.StartsWith("kdmapper", StringComparison.OrdinalIgnoreCase) ||
                        fn.StartsWith("byovd", StringComparison.OrdinalIgnoreCase) ||
                        fn.StartsWith("physmem_mapper", StringComparison.OrdinalIgnoreCase) ||
                        fn.StartsWith("gdrv_mapper", StringComparison.OrdinalIgnoreCase) ||
                        fn.StartsWith("mhyprot_mapper", StringComparison.OrdinalIgnoreCase) ||
                        fn.StartsWith("rtcore_mapper", StringComparison.OrdinalIgnoreCase);

                    if (!isMapperNamed) continue;

                    ctx.IncrementFiles();

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Mapper-Named Temporary File: {fn}",
                        Risk = RiskLevel.Medium,
                        Location = file,
                        FileName = fn,
                        Reason = $"File '{fn}' in Temp begins with a well-known mapper tool name. Mapper tools " +
                                 "often write configuration, log, or intermediate files to Temp during operation, " +
                                 "and these files persist as forensic artifacts after the tool exits.",
                        Detail = $"Path: {file} | Temp dir: {tempDir}"
                    });
                }

                await Task.Yield();
            }
        }, ct);

    // -------------------------------------------------------------------------
    // ROT13 decoder for UserAssist registry values
    // -------------------------------------------------------------------------

    private static string Rot13Decode(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (char c in s)
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
