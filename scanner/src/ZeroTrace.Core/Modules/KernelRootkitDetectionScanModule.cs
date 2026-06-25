using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class KernelRootkitDetectionScanModule : IScanModule
{
    public string Name => "Kernel Rootkit Detection";
    public double Weight => 4.5;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Known rootkit / BYOVD driver file names
    // -------------------------------------------------------------------------
    private static readonly HashSet<string> KnownRootkitDriverNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Generic rootkit drivers
        "r0driver.sys", "rootkit.sys", "hider.sys", "hide.sys", "prochider.sys",
        "dkom.sys", "kmodule.sys", "kernelmod.sys", "kdm.sys",
        "dse_fix.sys", "patchguard_bypass.sys", "kpatch.sys", "ghostdriver.sys",
        "phantom.sys", "stealth.sys", "hideme.sys", "nulldrv.sys", "hookdrv.sys",
        "syscall_hook.sys", "svchost_drv.sys", "kernel_hook.sys", "ntoskrnl_patch.sys",
        // SSDT / inline hook drivers
        "ssdt_hook.sys", "ssdt_bypass.sys", "ntdll_hook.sys", "inline_hook.sys",
        "iat_hook.sys", "idt_hook.sys", "sdt_hook.sys",
        // Network filtering rootkits
        "ndis_hook.sys", "tcpip_hook.sys", "wfp_bypass.sys", "netfilter_rk.sys",
        "packetfilter.sys", "ndisfilter.sys",
        // BYOVD (Bring Your Own Vulnerable Driver) - commonly abused legitimate drivers
        "capcom.sys", "rtcore64.sys", "gdrv.sys", "kdmapper_drv.sys",
        "dbutil_2_3.sys", "iqvw64e.sys", "mhyprot2.sys", "mhyprot.sys",
        "nvoclock.sys", "speedfan.sys", "asmmap64.sys", "msio64.sys",
        "physmem.sys", "winio.sys", "winring0.sys", "winring0x64.sys",
        "lenovodiagnosticsdriver.sys", "etdsupp.sys", "libnicm.sys",
        "nicm.sys", "nscm.sys", "ntiolib_x64.sys", "piddrv.sys",
        "piddrv64.sys", "rwdrv.sys", "semav6msr64.sys", "sfdrvx32.sys",
        "superbmc.sys", "directio64.sys", "inpoutx64.sys",
        // Process / object hiding
        "process_hide.sys", "objhide.sys", "proccloak.sys", "filehide.sys",
        "reghide.sys", "porkhide.sys", "nthide.sys",
        // Driver loaders / mappers
        "tdrv.sys", "mapper.sys", "drvmap.sys", "kmap.sys",
        // Generic suspicious names
        "exploit.sys", "bypass.sys", "spoofer_drv.sys", "hwid_spoof.sys",
        "anti_cheat_bypass.sys", "acbypass.sys", "eac_bypass.sys", "be_bypass.sys",
        "vac_bypass.sys",
    };

    // -------------------------------------------------------------------------
    // DKOM tool executables
    // -------------------------------------------------------------------------
    private static readonly HashSet<string> DkomToolNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "dkom_tool.exe", "eprocess_unlink.exe", "process_hide.exe",
        "pideprocess.exe", "hide_process.exe", "dkom_demo.exe",
        "unlinkprocess.exe", "eprocesshide.exe", "objhide.exe",
        "processmasker.exe", "proccloak.exe",
    };

    // -------------------------------------------------------------------------
    // Driver-loading / kernel-mapping tool executables
    // -------------------------------------------------------------------------
    private static readonly HashSet<string> DriverLoaderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "kdmapper.exe", "kdmapper_loader.exe", "dsefix.exe", "tdriver.exe",
        "loaddrv.exe", "drvinst.exe", "gdiplus_loader.exe", "drivermapper.exe",
        "driverutil.exe", "kmap.exe", "manualmap.exe", "kernelmap.exe",
        "scdtool.exe", "scloader.exe", "kloader.exe", "drvloader.exe",
        "exploitdriver.exe", "byovd_loader.exe", "vulndrv.exe",
        "dsebypass.exe", "patchguard_bypass.exe", "pg_bypass.exe",
        "kdm.exe", "kdmload.exe",
    };

    // -------------------------------------------------------------------------
    // SSDT / inline hook tool executables
    // -------------------------------------------------------------------------
    private static readonly HashSet<string> SsdtHookToolNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "ssdt_hook.exe", "syscall_hijack.exe", "ntdll_patch.exe",
        "ssdt_restore.exe", "ssdt_viewer.exe", "ssdthooker.exe",
        "syscall_monitor.exe", "hooktool.exe", "inlinehook.exe",
        "iat_patcher.exe", "idt_hook.exe", "ntapi_hook.exe",
    };

    // -------------------------------------------------------------------------
    // System file size sanity ranges (min bytes, max bytes)
    // Ranges are conservative: flag only obvious outliers.
    // -------------------------------------------------------------------------
    private static readonly Dictionary<string, (long Min, long Max)> SystemFileSizeRanges =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // ntoskrnl.exe: varies heavily by Windows build, but always several MB
            ["ntoskrnl.exe"] = (8_000_000L,  25_000_000L),
            ["ntkrnlpa.exe"] = (6_000_000L,  20_000_000L),
            ["hal.dll"]      = (800_000L,    4_000_000L),
            ["ndis.sys"]     = (1_500_000L,  6_000_000L),
            ["tcpip.sys"]    = (1_000_000L,  6_000_000L),
            ["ntdll.dll"]    = (1_800_000L,  8_000_000L),
            ["win32k.sys"]   = (2_000_000L,  12_000_000L),
            ["ksecdd.sys"]   = (100_000L,    800_000L),
            ["ci.dll"]       = (400_000L,    3_000_000L),
        };

    // -------------------------------------------------------------------------
    // Suspicious driver service image-path fragments (non-standard locations)
    // -------------------------------------------------------------------------
    private static readonly string[] SuspiciousServiceImagePathFragments =
    {
        @"\temp\", @"\tmp\", @"\appdata\", @"\users\public\",
        @"\downloads\", @"\desktop\", @"\documents\",
        @"\programdata\temp\", @"\recycle", @"\$recycle",
    };

    // -------------------------------------------------------------------------
    // Static helpers
    // -------------------------------------------------------------------------
    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string System32Dir =
        Path.Combine(WinDir, "System32");
    private static readonly string DriversDir =
        Path.Combine(WinDir, "System32", "drivers");
    private static readonly string SysWow64DriversDir =
        Path.Combine(WinDir, "SysWOW64", "drivers");
    private static readonly string TempDir =
        Path.GetTempPath();

    // -------------------------------------------------------------------------
    // Entry point
    // -------------------------------------------------------------------------
    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        await ScanDriverDirectoryAsync(ctx, DriversDir, ct);
        ctx.Report(0.15, "Driver dir scan", "System32\\drivers scanned");

        ct.ThrowIfCancellationRequested();
        await ScanDriverDirectoryAsync(ctx, SysWow64DriversDir, ct);
        ctx.Report(0.22, "SysWOW64 driver dir scan", "SysWOW64\\drivers scanned");

        ct.ThrowIfCancellationRequested();
        await ScanTempForDriverArtifactsAsync(ctx, ct);
        ctx.Report(0.35, "Temp driver artifacts", "Temp directory scanned for rootkit drivers");

        ct.ThrowIfCancellationRequested();
        await ScanForDkomToolsAsync(ctx, ct);
        ctx.Report(0.45, "DKOM tools", "DKOM tool artifacts scanned");

        ct.ThrowIfCancellationRequested();
        await ScanForDriverLoaderToolsAsync(ctx, ct);
        ctx.Report(0.55, "Driver loader tools", "Kernel-mapping loader tools scanned");

        ct.ThrowIfCancellationRequested();
        await ScanForSsdtHookToolsAsync(ctx, ct);
        ctx.Report(0.65, "SSDT hook tools", "SSDT/inline-hook tool artifacts scanned");

        ct.ThrowIfCancellationRequested();
        CheckSystemFileIntegrity(ctx);
        ctx.Report(0.75, "System file integrity", "Critical system file size anomalies checked");

        ct.ThrowIfCancellationRequested();
        CheckSuspiciousDriverServices(ctx, ct);
        ctx.Report(0.85, "Driver services", "Registry driver service entries scanned");

        ct.ThrowIfCancellationRequested();
        await ScanForInlineHookPayloadsAsync(ctx, ct);
        ctx.Report(0.95, "Hook payloads", "Hex/payload hook artifact files scanned");

        ct.ThrowIfCancellationRequested();
        ScanUnexpectedSystem32Drivers(ctx, ct);
        ctx.Report(1.0, "Kernel Rootkit Detection", "Scan complete");
    }

    // -------------------------------------------------------------------------
    // 1. Scan a drivers directory for known rootkit/BYOVD driver names
    // -------------------------------------------------------------------------
    private async Task ScanDriverDirectoryAsync(ScanContext ctx, string dir, CancellationToken ct)
    {
        if (!Directory.Exists(dir)) return;

        string[] files;
        try
        {
            files = Directory.GetFiles(dir, "*.sys");
        }
        catch (UnauthorizedAccessException) { return; }

        foreach (var path in files)
        {
            ct.ThrowIfCancellationRequested();
            var fileName = Path.GetFileName(path);

            if (KnownRootkitDriverNames.Contains(fileName))
            {
                string content = string.Empty;
                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                    ctx.IncrementFiles();
                }
                catch (IOException) { ctx.IncrementFiles(); }

                var isByovd = IsKnownByovdDriver(fileName);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = isByovd
                        ? $"BYOVD Vulnerable Driver Present: {fileName}"
                        : $"Known Rootkit Driver File: {fileName}",
                    Risk = isByovd ? RiskLevel.Critical : RiskLevel.Critical,
                    Location = path,
                    FileName = fileName,
                    Reason = isByovd
                        ? $"The driver '{fileName}' is a known vulnerable signed driver (BYOVD — Bring Your Own Vulnerable Driver). " +
                          "Rootkits and cheat loaders abuse this driver to disable Driver Signature Enforcement, bypass " +
                          "anti-cheat kernel protection, or map unsigned code into the kernel. Its presence outside of legitimate " +
                          "software installation directories is a critical indicator of kernel-level cheat infrastructure."
                        : $"The file '{fileName}' matches a known rootkit kernel driver name. This driver is associated with " +
                          "kernel-mode rootkits, process hiding, system call hooking, or DKOM attacks that allow cheats to operate " +
                          "invisibly to anti-cheat software and system monitoring tools.",
                    Detail = $"Directory: {dir} | File size: {GetFileSizeStr(path)} | BYOVD: {isByovd}"
                });
            }
            else
            {
                // Check indicator matcher for any name/keyword matches not in our hard list
                var ind = ctx.Matcher.MatchFileName(fileName)
                          ?? ctx.Matcher.MatchFileNameKeyword(fileName);
                if (ind is not null)
                {
                    try
                    {
                        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        _ = await sr.ReadToEndAsync();
                        ctx.IncrementFiles();
                    }
                    catch (IOException) { ctx.IncrementFiles(); }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Indicator-matched Driver: {fileName} ({ind.Category})",
                        Risk = ind.Risk,
                        Location = path,
                        FileName = fileName,
                        Reason = $"The driver file '{fileName}' matched indicator pattern '{ind.Pattern}' " +
                                 $"({ind.Category}): {ind.Description}",
                        Detail = $"Directory: {dir}"
                    });
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // 2. Scan temp directory for dropped rootkit drivers
    // -------------------------------------------------------------------------
    private async Task ScanTempForDriverArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(TempDir)) return;

        string[] sysFiles;
        try
        {
            sysFiles = Directory.GetFiles(TempDir, "*.sys", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }

        foreach (var path in sysFiles)
        {
            ct.ThrowIfCancellationRequested();
            var fileName = Path.GetFileName(path);

            string content = string.Empty;
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync();
                ctx.IncrementFiles();
            }
            catch (IOException) { ctx.IncrementFiles(); continue; }

            var isKnown = KnownRootkitDriverNames.Contains(fileName);
            var ind = ctx.Matcher.MatchFileName(fileName)
                      ?? ctx.Matcher.MatchFileNameKeyword(fileName)
                      ?? ctx.Matcher.MatchPathKeyword(path);

            if (isKnown || ind is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = isKnown
                        ? $"Rootkit Driver in Temp Directory: {fileName}"
                        : $"Suspicious Driver in Temp Directory: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = path,
                    FileName = fileName,
                    Reason = $"A kernel driver file '{fileName}' was found in the system temporary directory. " +
                             "Legitimate Windows drivers are never installed from the temp directory. This is a " +
                             "strong indicator that a rootkit or kernel-level cheat loader has staged or dropped " +
                             "a driver for manual kernel mapping (kdmapper, manual map, BYOVD load pattern). " +
                             (ind is not null ? $"Indicator '{ind.Pattern}': {ind.Description}" : "Name matches known rootkit driver list."),
                    Detail = $"Temp path: {path} | Size: {GetFileSizeStr(path)}"
                });
            }
            else
            {
                // Any .sys in temp is at minimum suspicious — flag as Medium
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Kernel Driver File in Temp Directory: {fileName}",
                    Risk = RiskLevel.Medium,
                    Location = path,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' is a kernel driver (.sys) located in the system temporary directory. " +
                             "Windows does not place legitimate drivers in temp directories. This may indicate a staged " +
                             "rootkit driver, a BYOVD payload being prepared for kernel loading, or malware dropper activity.",
                    Detail = $"Temp path: {path} | Size: {GetFileSizeStr(path)}"
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 3. Scan common user directories for DKOM tool executables
    // -------------------------------------------------------------------------
    private async Task ScanForDkomToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = GetUserSearchDirectories();
        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var path in files)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(path);
                if (!DkomToolNames.Contains(fileName)) continue;

                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    _ = await sr.ReadToEndAsync();
                    ctx.IncrementFiles();
                }
                catch (IOException) { ctx.IncrementFiles(); continue; }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"DKOM Tool Artifact: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = path,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' is a known Direct Kernel Object Manipulation (DKOM) tool. " +
                             "DKOM tools modify kernel data structures (specifically the EPROCESS linked list) to " +
                             "hide processes from user-mode enumeration, making cheat processes and rootkit drivers " +
                             "invisible to task managers, anti-cheat scanners, and WMI queries. This is a critical " +
                             "indicator of kernel-level rootkit activity.",
                    Detail = $"Found in: {dir} | DKOM tools manipulate kernel EPROCESS list entries"
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 4. Scan for kernel driver loader / mapper tools
    // -------------------------------------------------------------------------
    private async Task ScanForDriverLoaderToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = GetUserSearchDirectories();
        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var path in files)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(path);
                if (!DriverLoaderNames.Contains(fileName)) continue;

                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    _ = await sr.ReadToEndAsync();
                    ctx.IncrementFiles();
                }
                catch (IOException) { ctx.IncrementFiles(); continue; }

                var isKdmapper = fileName.StartsWith("kdmapper", StringComparison.OrdinalIgnoreCase);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = isKdmapper
                        ? $"kdmapper Kernel Driver Mapper: {fileName}"
                        : $"Kernel Driver Loader Tool: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = path,
                    FileName = fileName,
                    Reason = isKdmapper
                        ? $"The file '{fileName}' is kdmapper or a derivative, a tool specifically designed to " +
                          "manually map unsigned kernel drivers into memory by abusing a vulnerable signed driver " +
                          "(BYOVD). kdmapper is the most common tool used by cheat developers to load unsigned " +
                          "kernel cheats while bypassing Driver Signature Enforcement and anti-cheat kernel protection."
                        : $"The file '{fileName}' is a known kernel driver loading or mapping tool. These tools " +
                          "are used to load unsigned kernel drivers, bypass Driver Signature Enforcement (DSE), " +
                          "and install rootkit or cheat components at the kernel level without going through the " +
                          "normal Service Control Manager path.",
                    Detail = $"Found in: {dir}"
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 5. Scan for SSDT / inline hook tools
    // -------------------------------------------------------------------------
    private async Task ScanForSsdtHookToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = GetUserSearchDirectories();
        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var path in files)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(path);
                if (!SsdtHookToolNames.Contains(fileName)) continue;

                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    _ = await sr.ReadToEndAsync();
                    ctx.IncrementFiles();
                }
                catch (IOException) { ctx.IncrementFiles(); continue; }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"SSDT/Syscall Hook Tool: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = path,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' is a known System Service Descriptor Table (SSDT) hook tool " +
                             "or system call hijacking utility. SSDT hooks redirect Windows kernel system calls to " +
                             "attacker-controlled code, enabling cheats and rootkits to intercept and modify kernel " +
                             "operations such as process enumeration, file access, and network connections. This " +
                             "allows cheats to remain hidden from all user-mode and kernel-mode security tools.",
                    Detail = $"Found in: {dir} | SSDT hooks modify the kernel system call dispatch table"
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 6. System file integrity via size range checks
    // -------------------------------------------------------------------------
    private void CheckSystemFileIntegrity(ScanContext ctx)
    {
        foreach (var (fileName, (minSize, maxSize)) in SystemFileSizeRanges)
        {
            var path = Path.Combine(System32Dir, fileName);
            if (!File.Exists(path)) continue;

            long size;
            try
            {
                size = new FileInfo(path).Length;
                ctx.IncrementFiles();
            }
            catch (IOException) { ctx.IncrementFiles(); continue; }

            if (size < minSize || size > maxSize)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"System File Size Anomaly: {fileName}",
                    Risk = RiskLevel.High,
                    Location = path,
                    FileName = fileName,
                    Reason = $"The critical system file '{fileName}' has an unexpected size of {size:N0} bytes " +
                             $"(expected range: {minSize:N0}–{maxSize:N0} bytes). A size anomaly in a core kernel " +
                             "file can indicate rootkit patching, file replacement by a malicious actor, or " +
                             "corruption. Kernel rootkits sometimes replace or patch ntoskrnl.exe, hal.dll, " +
                             "ndis.sys, or tcpip.sys to intercept system calls or network traffic.",
                    Detail = $"Actual size: {size:N0} bytes | Expected range: {minSize:N0}–{maxSize:N0} bytes"
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 7. Registry: suspicious kernel driver service entries
    // -------------------------------------------------------------------------
    private void CheckSuspiciousDriverServices(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var services = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is null) return;

            var subKeyNames = services.GetSubKeyNames();
            int checkedCount = 0;

            foreach (var svcName in subKeyNames)
            {
                ct.ThrowIfCancellationRequested();
                if (++checkedCount > 2000) break; // bound the scan

                using var svcKey = services.OpenSubKey(svcName);
                if (svcKey is null) continue;
                ctx.IncrementRegistryKeys();

                var typeVal = svcKey.GetValue("Type");
                if (typeVal is null) continue;

                int serviceType;
                try { serviceType = Convert.ToInt32(typeVal); }
                catch { continue; }

                // Type = 1 = SERVICE_KERNEL_DRIVER
                if (serviceType != 1) continue;

                var imagePath = svcKey.GetValue("ImagePath")?.ToString();
                if (string.IsNullOrWhiteSpace(imagePath)) continue;

                var expanded = Environment.ExpandEnvironmentVariables(imagePath).ToLowerInvariant();

                // Check if ImagePath points to a non-standard location
                bool isNonStandard = SuspiciousServiceImagePathFragments.Any(frag =>
                    expanded.Contains(frag, StringComparison.OrdinalIgnoreCase));

                // Also check known rootkit driver names in the service image name
                var imageFileName = Path.GetFileName(expanded.Trim().Trim('"'));
                bool isKnownRootkitName = KnownRootkitDriverNames.Contains(imageFileName);

                if (isNonStandard || isKnownRootkitName)
                {
                    var startVal = svcKey.GetValue("Start");
                    int startType = startVal is not null ? Convert.ToInt32(startVal) : -1;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = isKnownRootkitName
                            ? $"Rootkit Driver Service Registration: {svcName}"
                            : $"Kernel Driver Service with Suspicious Image Path: {svcName}",
                        Risk = isKnownRootkitName ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        FileName = imageFileName,
                        Reason = isKnownRootkitName
                            ? $"The service '{svcName}' is registered as a kernel driver (Type=1) with " +
                              $"ImagePath '{imagePath}'. The driver filename matches a known rootkit or BYOVD " +
                              "driver name. This registration is used to load the rootkit driver at boot or on demand."
                            : $"The service '{svcName}' is registered as a kernel driver (Type=1) with an " +
                              $"ImagePath pointing to a non-standard location: '{imagePath}'. Legitimate Windows " +
                              "kernel drivers are installed in System32\\drivers, not in user-writable directories. " +
                              "This pattern is used by rootkits and cheat loaders that register a driver service " +
                              "pointing to a staged payload in temp or user directories.",
                        Detail = $"Type=1 (KERNEL_DRIVER) | Start={startType} | ImagePath={imagePath}"
                    });
                }

                // Additionally flag: matching name in known rootkit list (service name, not just file)
                if (KnownRootkitDriverNames.Contains(svcName + ".sys") ||
                    KnownRootkitDriverNames.Contains(svcName))
                {
                    if (!isKnownRootkitName) // avoid duplicate if already caught above
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Kernel Service Name Matches Known Rootkit: {svcName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = imageFileName,
                            Reason = $"The kernel driver service name '{svcName}' matches a known rootkit " +
                                     "or malicious driver name pattern. Even without the binary present, " +
                                     "this service registration indicates historical rootkit installation.",
                            Detail = $"ImagePath={imagePath} | Type={serviceType}"
                        });
                    }
                }
            }
        }
        catch { }
    }

    // -------------------------------------------------------------------------
    // 8. Scan for inline hook payload files (.hex, payload.bin, etc.)
    // -------------------------------------------------------------------------
    private async Task ScanForInlineHookPayloadsAsync(ScanContext ctx, CancellationToken ct)
    {
        var suspiciousPayloadNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "payload.bin", "loader.bin", "cheat.bin", "hook.bin", "ssdt.bin",
            "syscall.bin", "patch.bin", "ntdll.bin", "kernel.bin",
            "hook_payload.hex", "ssdt_hook.hex", "syscall_hook.hex",
            "ntoskrnl.hex", "patch.hex", "bypass.hex", "inject.hex",
        };

        var searchDirs = new[]
        {
            TempDir,
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            // Scan .bin files
            string[] binFiles;
            try
            {
                binFiles = Directory.GetFiles(dir, "*.bin", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var path in binFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(path);
                if (!suspiciousPayloadNames.Contains(fileName)) continue;

                string content = string.Empty;
                long fileSize = 0;
                try
                {
                    var fi = new FileInfo(path);
                    fileSize = fi.Length;
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync();
                    ctx.IncrementFiles();
                }
                catch (IOException) { ctx.IncrementFiles(); continue; }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspicious Hook Payload File: {fileName}",
                    Risk = RiskLevel.High,
                    Location = path,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' matches a known naming pattern for inline hook payloads, " +
                             "SSDT hook shellcode, or syscall patch buffers used by rootkits and kernel-level " +
                             "cheats. These binary blobs are loaded into kernel memory to redirect system calls " +
                             "and hide cheat activity from anti-cheat and system monitoring tools.",
                    Detail = $"Size: {fileSize:N0} bytes | Directory: {dir}"
                });
            }

            // Scan .hex files
            string[] hexFiles;
            try
            {
                hexFiles = Directory.GetFiles(dir, "*.hex", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }

            foreach (var path in hexFiles)
            {
                ct.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(path);
                if (!suspiciousPayloadNames.Contains(fileName)) continue;

                long fileSize = 0;
                try
                {
                    fileSize = new FileInfo(path).Length;
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    _ = await sr.ReadToEndAsync();
                    ctx.IncrementFiles();
                }
                catch (IOException) { ctx.IncrementFiles(); continue; }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Hex-encoded Hook Payload: {fileName}",
                    Risk = RiskLevel.High,
                    Location = path,
                    FileName = fileName,
                    Reason = $"The file '{fileName}' is a hex-encoded payload file matching a known syscall hook " +
                             "or SSDT patch payload naming pattern. Rootkit developers use hex-encoded payloads " +
                             "to store the actual patch bytes that will be written into kernel memory to redirect " +
                             "system calls, bypassing anti-cheat kernel integrity checks.",
                    Detail = $"Size: {fileSize:N0} bytes | Directory: {dir}"
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // 9. Check System32 for unexpected .sys files placed alongside real drivers
    // -------------------------------------------------------------------------
    private void ScanUnexpectedSystem32Drivers(ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(System32Dir)) return;

        // System32 itself (not drivers subdirectory) should not normally contain .sys files
        // placed by users — filter out Windows catalog entries
        string[] sysFiles;
        try
        {
            sysFiles = Directory.GetFiles(System32Dir, "*.sys", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException) { return; }

        // Known legitimate .sys files that sometimes appear in System32 (not in drivers subdir)
        var knownSystem32SysFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ntdll.sys", "win32k.sys", "win32kbase.sys", "win32kfull.sys",
            "cng.sys", "kd.sys", "kdcom.sys", "kdstub.sys",
        };

        foreach (var path in sysFiles)
        {
            ct.ThrowIfCancellationRequested();
            var fileName = Path.GetFileName(path);
            if (knownSystem32SysFiles.Contains(fileName)) continue;

            ctx.IncrementFiles();

            var isKnownRootkit = KnownRootkitDriverNames.Contains(fileName);
            var ind = ctx.Matcher.MatchFileName(fileName)
                      ?? ctx.Matcher.MatchFileNameKeyword(fileName);

            if (isKnownRootkit || ind is not null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspicious .sys File in System32 Root: {fileName}",
                    Risk = isKnownRootkit ? RiskLevel.Critical : ind?.Risk ?? RiskLevel.High,
                    Location = path,
                    FileName = fileName,
                    Reason = isKnownRootkit
                        ? $"The file '{fileName}' is a known rootkit driver and was found directly in System32 " +
                          "(not the drivers subdirectory). This placement may be an attempt to blend with system files."
                        : $"An unexpected kernel driver '{fileName}' matching indicator '{ind?.Pattern}' was found " +
                          "directly in System32. Rootkits sometimes copy drivers into System32 to evade directory-level " +
                          "filtering that only checks the drivers subdirectory.",
                    Detail = $"Size: {GetFileSizeStr(path)} | Expected location: {DriversDir}"
                });
            }
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------
    private static bool IsKnownByovdDriver(string fileName)
    {
        var byovdNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "capcom.sys", "rtcore64.sys", "gdrv.sys", "dbutil_2_3.sys",
            "iqvw64e.sys", "mhyprot2.sys", "mhyprot.sys", "nvoclock.sys",
            "speedfan.sys", "asmmap64.sys", "msio64.sys", "physmem.sys",
            "winio.sys", "winring0.sys", "winring0x64.sys",
            "lenovodiagnosticsdriver.sys", "etdsupp.sys", "libnicm.sys",
            "nicm.sys", "nscm.sys", "ntiolib_x64.sys", "piddrv.sys",
            "piddrv64.sys", "rwdrv.sys", "semav6msr64.sys", "directio64.sys",
            "inpoutx64.sys",
        };
        return byovdNames.Contains(fileName);
    }

    private static string[] GetUserSearchDirectories()
    {
        return new[]
        {
            TempDir,
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "Roaming"),
        };
    }

    private static string GetFileSizeStr(string path)
    {
        try { return $"{new FileInfo(path).Length:N0} bytes"; }
        catch { return "unknown"; }
    }
}
