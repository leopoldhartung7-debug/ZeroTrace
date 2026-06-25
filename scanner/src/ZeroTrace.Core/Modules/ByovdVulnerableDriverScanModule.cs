using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class ByovdVulnerableDriverScanModule : IScanModule
{
    public string Name => "BYOVD Vulnerable Driver Detection";
    public double Weight => 4.5;
    public int ParallelGroup => 4;

    private static readonly string WinDir =
        Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private static readonly string SystemDriversDir =
        Path.Combine(WinDir, "System32", "drivers");
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string TempDir =
        Path.GetTempPath();

    // Canonical lookup: driver file name (lower-case) -> CVE / vendor description
    private static readonly Dictionary<string, string> VulnerableDrivers =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // Gigabyte
            { "gdrv.sys",          "Gigabyte GDRV (CVE-2018-19320) - arbitrary kernel r/w" },
            { "gdrv2.sys",         "Gigabyte GDRV2 - arbitrary kernel r/w" },
            { "gdrvsio64.sys",     "Gigabyte GDrvSio64 - arbitrary kernel r/w" },
            // Intel
            { "iqvw64e.sys",       "Intel Network Adapter Diagnostics (CVE-2015-2291) - arbitrary kernel r/w via IOCTL" },
            { "iqvw64.sys",        "Intel Network Adapter Diagnostics (CVE-2015-2291) - arbitrary kernel r/w via IOCTL" },
            // MSI / MSI Afterburner
            { "rtcore64.sys",      "MSI RTCore64 / Afterburner (CVE-2019-16098) - arbitrary kernel r/w" },
            { "rtcore32.sys",      "MSI RTCore32 (CVE-2019-16098) - arbitrary kernel r/w" },
            // Dell
            { "dbutil_2_3.sys",    "Dell DBUtil (CVE-2021-21551) - arbitrary kernel r/w, LPE" },
            { "dbutil_2_5.sys",    "Dell DBUtil 2.5 (CVE-2021-21551) - arbitrary kernel r/w, LPE" },
            // ASUS / ASRock
            { "asrdrv103.sys",     "ASUS/ASRock AsrDrv103 (CVE-2020-15368) - arbitrary kernel r/w" },
            { "asrdrv104.sys",     "ASUS AsrDrv104 - arbitrary kernel r/w" },
            { "asupio64.sys",      "ASUS AsUpIO64 - arbitrary kernel r/w" },
            { "asio3.sys",         "ASUS AsIO3 - arbitrary kernel r/w" },
            // WinRing0
            { "winring0x64.sys",   "WinRing0x64 (CVE-2020-14979) - arbitrary kernel r/w" },
            { "winring0.sys",      "WinRing0 (CVE-2020-14979) - arbitrary kernel r/w" },
            { "winring0_1_2_0.sys","WinRing0 1.2.0 (CVE-2020-14979) - arbitrary kernel r/w" },
            // CPU-Z
            { "cpuz141_x64.sys",   "CPU-Z 1.41 driver (CVE-2017-15303) - arbitrary kernel r/w" },
            { "cpuz149_x64.sys",   "CPU-Z 1.49 driver - arbitrary kernel r/w" },
            { "cpuz154_x64.sys",   "CPU-Z 1.54 driver - arbitrary kernel r/w" },
            { "cpuz155_x64.sys",   "CPU-Z 1.55 driver - arbitrary kernel r/w" },
            { "cpuz136.sys",       "CPU-Z 1.36 driver - arbitrary kernel r/w" },
            { "cpuz143.sys",       "CPU-Z 1.43 driver - arbitrary kernel r/w" },
            { "cpuz145.sys",       "CPU-Z 1.45 driver - arbitrary kernel r/w" },
            { "cpuz148.sys",       "CPU-Z 1.48 driver - arbitrary kernel r/w" },
            // GPU-Z
            { "gpuzv2.38.sys",     "GPU-Z v2.38 driver - arbitrary kernel r/w" },
            { "gpuz.sys",          "GPU-Z driver - arbitrary kernel r/w" },
            // SpeedFan
            { "speedfan.sys",      "SpeedFan driver - arbitrary kernel r/w" },
            // Process Hacker
            { "kprocesshacker.sys", "Process Hacker KProcessHacker (CVE-2020-35488) - kernel object access" },
            { "kprocesshacker2.sys","Process Hacker KProcessHacker2 - kernel object access" },
            // HWiNFO64
            { "hwinfo64a.sys",     "HWiNFO64 driver - arbitrary kernel r/w" },
            // SiSoftware Sandra
            { "sandra.sys",        "SiSoftware Sandra driver - arbitrary kernel r/w" },
            // PassMark
            { "directio64.sys",    "PassMark DirectIO64 - arbitrary kernel r/w" },
            { "directio32.sys",    "PassMark DirectIO32 - arbitrary kernel r/w" },
            // Netfilter
            { "netfilter64.sys",   "Netfilter64 (used in Genshin rootkit campaigns) - arbitrary kernel r/w" },
            // Logitech
            { "lmiinfo.sys",       "Logitech LMIinfo driver - arbitrary kernel r/w" },
            // Razer
            { "rzpnk.sys",         "Razer rzpnk (CVE-2017-9769/9770) - arbitrary kernel r/w" },
            // EVGA
            { "eio64.sys",         "EVGA EIO64 driver - arbitrary kernel r/w" },
            // HwRwDrv
            { "hwrwdrv.sys",       "HwRwDrv - arbitrary kernel r/w" },
            { "hwrwdrv64.sys",     "HwRwDrv64 - arbitrary kernel r/w" },
            // MsIo / HP
            { "msio64.sys",        "MsIo64 / HP driver (CVE-2019-7255) - arbitrary kernel r/w" },
            { "msio32.sys",        "MsIo32 driver - arbitrary kernel r/w" },
            // PhyMem
            { "phymemdrv.sys",     "PhyMemDrv - direct physical memory r/w" },
            { "phymem64.sys",      "phymem64 - direct physical memory r/w" },
            // ATSZIO
            { "atszio64.sys",      "ATSZIO64 driver - arbitrary kernel r/w" },
            { "atszio.sys",        "ATSZIO driver - arbitrary kernel r/w" },
            // WinIo
            { "winio64.sys",       "WinIo64 - arbitrary kernel r/w" },
            { "winio32.sys",       "WinIo32 - arbitrary kernel r/w" },
            { "winio3.sys",        "WinIo3 - arbitrary kernel r/w" },
            // NalDrv
            { "naldrv.sys",        "NalDrv (Intel Network Adapter) - arbitrary kernel r/w" },
            // Viragt
            { "viragt64.sys",      "VirAGT64 driver - arbitrary kernel r/w" },
            { "viragt.sys",        "VirAGT driver - arbitrary kernel r/w" },
            // rwdrv
            { "rwdrv.sys",         "RWDrv (RWEverything) - direct physical memory r/w" },
            { "rw64.sys",          "RW64 (RWEverything) - direct physical memory r/w" },
            // sysdiag
            { "sysdiag64.sys",     "SysDiag64 - arbitrary kernel r/w" },
            // piddrv
            { "piddrv64.sys",      "PidDrv64 - arbitrary kernel r/w" },
            { "piddrv.sys",        "PidDrv - arbitrary kernel r/w" },
            // Nvflash
            { "nvflash64.sys",     "Nvidia NVFlash64 - arbitrary kernel r/w" },
            { "nvflashstrapper.sys","Nvidia NVFlash Strapper - arbitrary kernel r/w" },
            // Power Tool
            { "powertool64.sys",   "PowerTool64 - arbitrary kernel r/w, AC-bypass tool" },
            // Cheat Engine
            { "dbk64.sys",         "Cheat Engine DBK64 (CVE-2020-15782) - arbitrary kernel r/w" },
            { "dbk32.sys",         "Cheat Engine DBK32 - arbitrary kernel r/w" },
            // Core Temp
            { "alcpuio64.sys",     "Core Temp ALCPUio64 - arbitrary kernel r/w" },
            { "alcpu.sys",         "Core Temp ALCPU - arbitrary kernel r/w" },
            // IOBit
            { "iobit.sys",         "IOBit driver - arbitrary kernel r/w" },
            { "iobitunlocker.sys", "IOBit Unlocker driver - arbitrary kernel r/w" },
            // ENE
            { "enetechIo64.sys",   "ENE EneTechIo64 - arbitrary kernel r/w" },
            { "eneio64.sys",       "ENE EneIo64 - arbitrary kernel r/w" },
            { "ene.sys",           "ENE driver - arbitrary kernel r/w" },
            // Nvidia overclock
            { "nvoclock.sys",      "Nvidia NVOclock driver - arbitrary kernel r/w" },
            // Asmmap
            { "asmmap64.sys",      "Asmmap64 (ASMedia) - direct physical memory r/w" },
            { "asmmap.sys",        "Asmmap (ASMedia) - direct physical memory r/w" },
            // Genshin Impact / mhyprot (most common BYOVD vector)
            { "mhyprot2.sys",      "miHoYo mhyprot2 (Genshin Impact AC, CVE-2022-0185 / BYOVD) - most-exploited BYOVD driver" },
            { "mhyprot3.sys",      "miHoYo mhyprot3 (Genshin Impact AC) - most-exploited BYOVD driver" },
            // HookLib
            { "hooklib.sys",       "HookLib kernel hooking driver - arbitrary kernel hooks" },
            // Process Explorer
            { "procexp.sys",       "Sysinternals Process Explorer driver (abused for token theft / BYOVD)" },
            { "procexp152.sys",    "Sysinternals Process Explorer 15.2 driver (abused for token theft / BYOVD)" },
            // nkvirtmem
            { "nkvirtmem.sys",     "nkvirtmem - direct virtual memory r/w" },
            // nicm
            { "nicm.sys",          "Novell Client (nicm) - arbitrary kernel r/w" },
            // Dell BIOS
            { "dellbios.sys",      "Dell BIOS driver - arbitrary kernel r/w" },
            // bs_i2cIo
            { "bs_i2cio.sys",      "BSM bs_i2cIo - arbitrary kernel r/w" },
        };

    // KDMapper and BYOVD tooling executables — names and keywords
    private static readonly string[] MapperExecutableNames =
    {
        "kdmapper.exe",
        "kdmapper_x64.exe",
        "drvmap.exe",
        "drvmapper.exe",
        "drivermapper.exe",
        "drivermapperx64.exe",
        "puzzlemapper.exe",
        "tdlmapper.exe",
        "ezmap.exe",
        "ldr.exe",
    };

    // Substrings in exe filenames that suggest a mapper
    private static readonly string[] MapperNameKeywords =
    {
        "kdmapper",
        "drvmap",
        "drvmapper",
        "drivermapper",
        "kernelmapper",
        "byovd",
    };

    // Git clone folder names associated with BYOVD tooling
    private static readonly string[] ByovdFolderNames =
    {
        "kdmapper",
        "kdmapper-master",
        "BYOVD",
        "byovd-master",
        "VulnerableDrivers",
        "vulnerable-drivers",
        "driver-mapper",
        "drvmapper",
        "DriverMapper",
    };

    // PowerShell history / script keywords that indicate BYOVD activity
    private static readonly (string Keyword, string Description, RiskLevel Risk)[] PsHistoryPatterns =
    {
        ("NtLoadDriver",                "NtLoadDriver syscall (kernel driver loading without SCM)", RiskLevel.Critical),
        ("ZwLoadDriver",                "ZwLoadDriver syscall (kernel driver loading without SCM)", RiskLevel.Critical),
        ("kdmapper",                    "KDMapper kernel-driver mapper tool referenced in PS history", RiskLevel.Critical),
        ("byovd",                       "BYOVD technique keyword in PS history", RiskLevel.Critical),
        ("drvmap",                      "drvmap driver-mapper tool referenced in PS history", RiskLevel.Critical),
        ("sc create",                   "Service creation command (possible driver registration)", RiskLevel.High),
        ("sc.exe create",               "Service creation via sc.exe (possible driver registration)", RiskLevel.High),
        ("NtMapViewOfSection",          "NtMapViewOfSection in PS history (memory mapping for driver exploit)", RiskLevel.High),
        ("KeRemoveNotifyRoutine",       "KeRemoveNotifyRoutine string in PS history (AC callback removal)", RiskLevel.Critical),
        ("PsRemoveLoadImageNotifyRoutine", "PsRemoveLoadImageNotifyRoutine in PS history (load-image callback removal)", RiskLevel.Critical),
        ("PsSetCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutine removal string in PS history", RiskLevel.Critical),
        ("ObRegisterCallbacks",         "ObRegisterCallbacks string in PS history (callback manipulation)", RiskLevel.High),
        ("mhyprot",                     "mhyprot (Genshin BYOVD driver) referenced in PS history", RiskLevel.Critical),
        ("rtcore64",                    "RTCore64 vulnerable driver referenced in PS history", RiskLevel.Critical),
        ("gdrv",                        "GDRV (Gigabyte vulnerable driver) referenced in PS history", RiskLevel.Critical),
        ("dbutil",                      "DBUtil (Dell vulnerable driver) referenced in PS history", RiskLevel.Critical),
        ("iqvw64",                      "IQVW64 (Intel vulnerable driver) referenced in PS history", RiskLevel.Critical),
        ("winring0",                    "WinRing0 vulnerable driver referenced in PS history", RiskLevel.Critical),
        ("dbk64",                       "Cheat Engine DBK64 driver referenced in PS history", RiskLevel.Critical),
    };

    // Content strings in executables that indicate BYOVD / AC-bypass functionality
    private static readonly (string Needle, string Description)[] ExeContentSignatures =
    {
        ("NtLoadDriver",                     "NtLoadDriver API string (driver loading without SCM)"),
        ("ZwLoadDriver",                     "ZwLoadDriver API string (driver loading without SCM)"),
        ("NtMapViewOfSection",               "NtMapViewOfSection API string (memory-mapping kernel exploit)"),
        ("KeRemoveNotifyRoutine",            "KeRemoveNotifyRoutine string (kernel callback removal)"),
        ("PsRemoveLoadImageNotifyRoutine",   "PsRemoveLoadImageNotifyRoutine string (load-image callback removal)"),
        ("PsSetCreateProcessNotifyRoutine",  "PsSetCreateProcessNotifyRoutine string (process-notify callback manipulation)"),
        ("ObRegisterCallbacks",              "ObRegisterCallbacks string (object callback manipulation)"),
        ("kdmapper",                         "kdmapper string literal embedded in executable"),
        ("BYOVD",                            "BYOVD string literal embedded in executable"),
        ("mhyprot",                          "mhyprot (Genshin BYOVD driver) string in executable"),
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting BYOVD vulnerable driver scan...");

        var vulnNameLookup = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in VulnerableDrivers)
            vulnNameLookup[kvp.Key] = kvp.Value;

        var vulnNameSet = new HashSet<string>(vulnNameLookup.Keys, StringComparer.OrdinalIgnoreCase);

        await ScanFileSystemForDriversAsync(ctx, vulnNameLookup, ct).ConfigureAwait(false);
        ctx.Report(0.35, Name, "File system scan complete");

        await ScanRegistryServicesAsync(ctx, vulnNameLookup, ct).ConfigureAwait(false);
        ctx.Report(0.55, Name, "Registry services scan complete");

        await ScanByovdToolingAsync(ctx, vulnNameSet, ct).ConfigureAwait(false);
        ctx.Report(0.75, Name, "BYOVD tooling scan complete");

        await ScanPowerShellHistoryAsync(ctx, ct).ConfigureAwait(false);
        ctx.Report(0.90, Name, "PowerShell history scan complete");

        ctx.Report(1.0, Name, "BYOVD scan complete");
    }

    private async Task ScanFileSystemForDriversAsync(
        ScanContext ctx,
        Dictionary<string, string> lookup,
        CancellationToken ct)
    {
        var dirsToScan = new List<string>();

        // All logical drive roots
        await Task.Run(() =>
        {
            try
            {
                foreach (var drive in DriveInfo.GetDrives())
                {
                    if (drive.IsReady && drive.DriveType is DriveType.Fixed or DriveType.Removable)
                        dirsToScan.Add(drive.RootDirectory.FullName);
                }
            }
            catch { }
        }, ct).ConfigureAwait(false);

        // High-priority locations added explicitly so they are not missed if
        // the recursive drive walk is limited by depth
        var priorityDirs = new[]
        {
            TempDir,
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Documents"),
            AppData,
            LocalAppData,
            Path.Combine(LocalAppData, "Temp"),
            SystemDriversDir,
            Path.Combine(WinDir, "System32"),
            Path.Combine(WinDir, "SysWOW64"),
            Path.Combine(WinDir, "Temp"),
            @"C:\Temp",
            @"C:\Tools",
            @"C:\Drivers",
            @"C:\Cheat",
            @"C:\hack",
            @"C:\bypass",
        };

        foreach (var d in priorityDirs)
        {
            if (Directory.Exists(d) && !dirsToScan.Contains(d, StringComparer.OrdinalIgnoreCase))
                dirsToScan.Add(d);
        }

        int total = Math.Max(dirsToScan.Count, 1);
        int idx = 0;
        foreach (var root in dirsToScan)
        {
            ct.ThrowIfCancellationRequested();
            idx++;
            ctx.Report((double)idx / total * 0.33, root, $"Scanning {root} for vulnerable drivers");
            await ScanDirectoryForDrivers(ctx, root, lookup, 0, ct).ConfigureAwait(false);
        }
    }

    private async Task ScanDirectoryForDrivers(
        ScanContext ctx,
        string dir,
        Dictionary<string, string> lookup,
        int depth,
        CancellationToken ct)
    {
        if (depth > 8) return;
        ct.ThrowIfCancellationRequested();

        string[] files = Array.Empty<string>();
        try
        {
            files = Directory.GetFiles(dir, "*.sys");
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);
            if (!lookup.TryGetValue(fileName, out var description))
                continue;

            // Driver found — check if it sits outside the legit system drivers dir
            bool inSystemDir = file.StartsWith(SystemDriversDir, StringComparison.OrdinalIgnoreCase);
            var risk = inSystemDir ? RiskLevel.High : RiskLevel.Critical;
            var locationNote = inSystemDir
                ? "Found inside the Windows system drivers directory — may be legitimate tool installation but is a known vulnerable driver."
                : "Found OUTSIDE the Windows system drivers directory — strongly suspicious, likely BYOVD staging.";

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Known Vulnerable Driver: {fileName}",
                Risk     = risk,
                Location = file,
                FileName = fileName,
                Reason   = $"The file '{fileName}' is a known CVE-exploited driver used in BYOVD attacks. " +
                           $"{locationNote} Description: {description}",
                Detail   = $"Path: {file} | Known vulnerability: {description}"
            });
        }

        string[] subDirs = Array.Empty<string>();
        try
        {
            subDirs = Directory.GetDirectories(dir);
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            ct.ThrowIfCancellationRequested();
            await ScanDirectoryForDrivers(ctx, sub, lookup, depth + 1, ct).ConfigureAwait(false);
        }
    }

    private async Task ScanRegistryServicesAsync(
        ScanContext ctx,
        Dictionary<string, string> lookup,
        CancellationToken ct)
    {
        await Task.Run(() =>
        {
            const string servicesPath = @"SYSTEM\CurrentControlSet\Services";
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var services = baseKey.OpenSubKey(servicesPath);
                if (services is null) return;

                ctx.IncrementRegistryKeys();
                var serviceNames = services.GetSubKeyNames();

                foreach (var svcName in serviceNames)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var svcKey = services.OpenSubKey(svcName);
                        if (svcKey is null) continue;
                        ctx.IncrementRegistryKeys();

                        var imagePath = svcKey.GetValue("ImagePath")?.ToString();
                        if (string.IsNullOrWhiteSpace(imagePath)) continue;

                        // Expand environment variables and normalise NT-style prefix
                        var expanded = Environment.ExpandEnvironmentVariables(imagePath).Trim();
                        if (expanded.StartsWith(@"\??\", StringComparison.Ordinal))
                            expanded = expanded[4..];
                        if (expanded.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
                            expanded = Path.Combine(WinDir, expanded[@"\SystemRoot\".Length..]);

                        var driverFileName = Path.GetFileName(expanded);
                        if (!lookup.TryGetValue(driverFileName, out var description))
                            continue;

                        // Flag if the path is outside %WINDIR%\System32\drivers
                        bool inSystemDir = expanded.StartsWith(SystemDriversDir, StringComparison.OrdinalIgnoreCase);
                        if (inSystemDir) continue; // inside system dir — lower priority, skip for registry-only check

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"BYOVD Service Registration: {svcName} -> {driverFileName}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{servicesPath}\{svcName}\ImagePath",
                            FileName = driverFileName,
                            Reason   = $"Registry service '{svcName}' has an ImagePath pointing to the known " +
                                       $"vulnerable driver '{driverFileName}' at a location outside the standard " +
                                       $"Windows drivers directory. This is a classic BYOVD attack registration. " +
                                       $"Vulnerability: {description}",
                            Detail   = $"Service: {svcName} | ImagePath: {imagePath} | Expanded: {expanded}"
                        });
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                    catch { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }, ct).ConfigureAwait(false);
    }

    private async Task ScanByovdToolingAsync(
        ScanContext ctx,
        HashSet<string> vulnDriverNames,
        CancellationToken ct)
    {
        var searchRoots = new List<string>
        {
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Documents"),
            AppData,
            LocalAppData,
            Path.Combine(LocalAppData, "Temp"),
            TempDir,
        };

        // Also check all drive roots shallowly for well-known BYOVD tooling staging dirs
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady && drive.DriveType is DriveType.Fixed)
                {
                    var root = drive.RootDirectory.FullName;
                    searchRoots.Add(root);
                }
            }
        }
        catch { }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var searchRoot in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(searchRoot)) continue;

            await Task.Run(() =>
            {
                ScanDirectoryForByovdTooling(ctx, searchRoot, vulnDriverNames, 0, seen, ct);
            }, ct).ConfigureAwait(false);
        }
    }

    private void ScanDirectoryForByovdTooling(
        ScanContext ctx,
        string dir,
        HashSet<string> vulnDriverNames,
        int depth,
        HashSet<string> seen,
        CancellationToken ct)
    {
        if (depth > 6) return;
        ct.ThrowIfCancellationRequested();

        if (!seen.Add(dir)) return;

        // Check if this directory name matches known BYOVD tooling repository names
        var dirName = Path.GetFileName(dir);
        foreach (var folderName in ByovdFolderNames)
        {
            if (dirName.Equals(folderName, StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"BYOVD Tooling Directory: {dirName}",
                    Risk     = RiskLevel.Critical,
                    Location = dir,
                    FileName = dirName,
                    Reason   = $"Directory '{dirName}' matches a known BYOVD tooling repository or mapper " +
                               "folder name. This is characteristic of KDMapper, driver-mapper, or similar " +
                               "kernel-driver mapping tools used in BYOVD attacks.",
                    Detail   = $"Full path: {dir}"
                });
                break;
            }
        }

        // Check files in this directory
        string[] files = Array.Empty<string>();
        try { files = Directory.GetFiles(dir); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }
        catch { return; }

        bool dirHasMapperExe = false;
        bool dirHasVulnDriver = false;
        string? mapperExePath = null;
        string? vulnDriverPath = null;

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var fileName = Path.GetFileName(file);
            var ext = Path.GetExtension(file);

            // Check for mapper executables
            if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase))
            {
                bool isMapper = false;
                foreach (var mapperName in MapperExecutableNames)
                {
                    if (fileName.Equals(mapperName, StringComparison.OrdinalIgnoreCase))
                    {
                        isMapper = true;
                        break;
                    }
                }

                if (!isMapper)
                {
                    var fileNameLower = fileName.ToLowerInvariant();
                    foreach (var keyword in MapperNameKeywords)
                    {
                        if (fileNameLower.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            isMapper = true;
                            break;
                        }
                    }
                }

                if (isMapper)
                {
                    dirHasMapperExe = true;
                    mapperExePath = file;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"BYOVD Mapper Executable: {fileName}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"The file '{fileName}' is a known or suspected BYOVD kernel-driver " +
                                   "mapper executable (KDMapper variant, drvmap, or similar). These tools " +
                                   "exploit vulnerable signed drivers to load unsigned kernel code and bypass " +
                                   "Driver Signature Enforcement (DSE) / anti-cheat kernel protection.",
                        Detail   = $"Path: {file}"
                    });
                }
            }

            // Check for vulnerable .sys files co-located with other files
            if (ext.Equals(".sys", StringComparison.OrdinalIgnoreCase))
            {
                if (vulnDriverNames.Contains(fileName))
                {
                    dirHasVulnDriver = true;
                    vulnDriverPath = file;
                }
            }
        }

        // If a directory contains BOTH a vulnerable driver AND a mapper exe,
        // that is an extremely strong BYOVD staging indicator
        if (dirHasMapperExe && dirHasVulnDriver && mapperExePath is not null && vulnDriverPath is not null)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "BYOVD Staging Directory: Mapper + Vulnerable Driver Co-Located",
                Risk     = RiskLevel.Critical,
                Location = dir,
                FileName = Path.GetFileName(mapperExePath),
                Reason   = "A directory contains both a BYOVD mapper executable and a known vulnerable " +
                           "driver in the same folder. This is the exact staging pattern used in BYOVD " +
                           "kernel-driver exploitation attacks to load unsigned kernel code and disable " +
                           "anti-cheat callbacks.",
                Detail   = $"Mapper: {mapperExePath} | Vulnerable driver: {vulnDriverPath}"
            });
        }

        // Recurse into subdirectories
        string[] subDirs = Array.Empty<string>();
        try { subDirs = Directory.GetDirectories(dir); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            ct.ThrowIfCancellationRequested();
            ScanDirectoryForByovdTooling(ctx, sub, vulnDriverNames, depth + 1, seen, ct);
        }
    }

    private async Task ScanPowerShellHistoryAsync(ScanContext ctx, CancellationToken ct)
    {
        var historyFiles = new List<string>();

        // Current user's PSReadLine history
        var primaryHistory = Path.Combine(
            AppData,
            @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
        if (File.Exists(primaryHistory))
            historyFiles.Add(primaryHistory);

        // All user profiles: scan %SYSTEMDRIVE%\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\
        await Task.Run(() =>
        {
            try
            {
                var usersDir = Path.Combine(
                    Environment.GetEnvironmentVariable("SYSTEMDRIVE") ?? "C:", "Users");
                if (Directory.Exists(usersDir))
                {
                    string[] profileDirs = Array.Empty<string>();
                    try { profileDirs = Directory.GetDirectories(usersDir); }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }

                    foreach (var profileDir in profileDirs)
                    {
                        ct.ThrowIfCancellationRequested();
                        var candidate = Path.Combine(
                            profileDir,
                            @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
                        if (File.Exists(candidate) &&
                            !historyFiles.Contains(candidate, StringComparer.OrdinalIgnoreCase))
                        {
                            historyFiles.Add(candidate);
                        }
                    }
                }
            }
            catch { }
        }, ct).ConfigureAwait(false);

        foreach (var histFile in historyFiles)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(histFile)) continue;

            ctx.IncrementFiles();
            ctx.Report(0.82, histFile, $"Scanning PS history: {Path.GetFileName(histFile)}");

            await ScanPsHistoryFileAsync(ctx, histFile, ct).ConfigureAwait(false);
        }
    }

    private async Task ScanPsHistoryFileAsync(
        ScanContext ctx,
        string histFile,
        CancellationToken ct)
    {
        string content;
        try
        {
            using var fs = new FileStream(histFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        var lines = content.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var vulnDriverNames = new HashSet<string>(VulnerableDrivers.Keys, StringComparer.OrdinalIgnoreCase);

        foreach (var rawLine in lines)
        {
            ct.ThrowIfCancellationRequested();
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line)) continue;

            // Check against known BYOVD patterns
            foreach (var (keyword, description, risk) in PsHistoryPatterns)
            {
                if (!line.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    continue;

                // For "sc create" style entries, also check if a vulnerable driver name appears
                if (keyword.Equals("sc create", StringComparison.OrdinalIgnoreCase) ||
                    keyword.Equals("sc.exe create", StringComparison.OrdinalIgnoreCase))
                {
                    bool refersToVulnDriver = false;
                    foreach (var drvName in vulnDriverNames)
                    {
                        if (line.Contains(drvName, StringComparison.OrdinalIgnoreCase))
                        {
                            refersToVulnDriver = true;
                            break;
                        }
                    }

                    if (!refersToVulnDriver)
                    {
                        // Generic sc create without a vulnerable driver name — lower priority
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "PS History: Service Creation Command",
                            Risk     = RiskLevel.Medium,
                            Location = histFile,
                            FileName = Path.GetFileName(histFile),
                            Reason   = $"PowerShell history contains a service-creation command that could " +
                                       "indicate manual driver registration. Pattern: 'sc create'. " +
                                       $"Command: '{line[..Math.Min(200, line.Length)]}'",
                            Detail   = $"File: {histFile} | Line: {line}"
                        });
                        break;
                    }

                    // Service creation referencing a vulnerable driver name — critical
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"PS History: BYOVD Service Registration — {description}",
                        Risk     = RiskLevel.Critical,
                        Location = histFile,
                        FileName = Path.GetFileName(histFile),
                        Reason   = $"PowerShell history contains a service-creation command that references " +
                                   $"a known vulnerable driver. {description}. " +
                                   $"Command: '{line[..Math.Min(200, line.Length)]}'",
                        Detail   = $"File: {histFile} | Line: {line}"
                    });
                    break;
                }

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"PS History: BYOVD Indicator — {description}",
                    Risk     = risk,
                    Location = histFile,
                    FileName = Path.GetFileName(histFile),
                    Reason   = $"PowerShell history contains a BYOVD-related keyword or technique. " +
                               $"Indicator: '{keyword}'. {description}. " +
                               $"Command: '{line[..Math.Min(200, line.Length)]}'",
                    Detail   = $"File: {histFile} | Keyword: {keyword} | Line: {line}"
                });
                break; // one finding per line
            }

            // Also check every line for any vulnerable driver name reference not already caught
            foreach (var drvName in vulnDriverNames)
            {
                if (!line.Contains(drvName, StringComparison.OrdinalIgnoreCase))
                    continue;

                // Avoid duplicate if already reported above
                bool alreadyMatched = false;
                foreach (var (keyword, _, _) in PsHistoryPatterns)
                {
                    if (line.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        alreadyMatched = true;
                        break;
                    }
                }
                if (alreadyMatched) continue;

                var drvDesc = VulnerableDrivers.TryGetValue(drvName, out var d) ? d : drvName;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"PS History: Vulnerable Driver Reference — {drvName}",
                    Risk     = RiskLevel.Critical,
                    Location = histFile,
                    FileName = Path.GetFileName(histFile),
                    Reason   = $"PowerShell history contains a direct reference to the known vulnerable " +
                               $"driver '{drvName}'. This driver is commonly used in BYOVD attacks. " +
                               $"Vulnerability: {drvDesc}. " +
                               $"Command: '{line[..Math.Min(200, line.Length)]}'",
                    Detail   = $"File: {histFile} | Driver: {drvName} | Line: {line}"
                });
                break; // one finding per line
            }
        }
    }

    private async Task ScanExecutableContentAsync(
        ScanContext ctx,
        string path,
        CancellationToken ct)
    {
        ctx.IncrementFiles();
        ct.ThrowIfCancellationRequested();

        string content;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs, detectEncodingFromByteOrderMarks: false,
                leaveOpen: false);
            content = await sr.ReadToEndAsync().ConfigureAwait(false);
        }
        catch (IOException) { return; }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        int hits = 0;
        var matchedSignatures = new List<string>();

        foreach (var (needle, description) in ExeContentSignatures)
        {
            if (!content.Contains(needle, StringComparison.OrdinalIgnoreCase))
                continue;

            hits++;
            matchedSignatures.Add($"'{needle}' ({description})");

            if (hits >= 3) break; // once we have 3+ hits it's clearly BYOVD-related
        }

        if (hits == 0) return;

        var fileName = Path.GetFileName(path);
        var risk = hits >= 2 ? RiskLevel.Critical : RiskLevel.High;

        ctx.AddFinding(new Finding
        {
            Module   = Name,
            Title    = $"BYOVD Content Signature in Executable: {fileName}",
            Risk     = risk,
            Location = path,
            FileName = fileName,
            Reason   = $"The executable '{fileName}' contains {hits} BYOVD-related string signature(s) " +
                       "associated with kernel-driver loading, anti-cheat callback removal, or driver " +
                       "exploitation. Legitimate user-mode tools do not embed these kernel-mode API strings.",
            Detail   = $"Matched signatures: {string.Join(", ", matchedSignatures)} | Path: {path}"
        });
    }

    private async Task CheckDirectoryForMapperCombo(
        ScanContext ctx,
        string dir,
        HashSet<string> vulnDriverNames,
        CancellationToken ct)
    {
        if (!Directory.Exists(dir)) return;

        string[] files = Array.Empty<string>();
        try { files = Directory.GetFiles(dir); }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }
        catch { return; }

        var mapperExes = new List<string>();
        var vulnSysFiles = new List<string>();

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var fileName = Path.GetFileName(file);
            var ext = Path.GetExtension(file);

            if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase))
            {
                var lower = fileName.ToLowerInvariant();
                foreach (var keyword in MapperNameKeywords)
                {
                    if (lower.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        mapperExes.Add(file);
                        break;
                    }
                }

                foreach (var mapperName in MapperExecutableNames)
                {
                    if (fileName.Equals(mapperName, StringComparison.OrdinalIgnoreCase))
                    {
                        if (!mapperExes.Contains(file, StringComparer.OrdinalIgnoreCase))
                            mapperExes.Add(file);
                        break;
                    }
                }
            }

            if (ext.Equals(".sys", StringComparison.OrdinalIgnoreCase) &&
                vulnDriverNames.Contains(fileName))
            {
                vulnSysFiles.Add(file);
            }
        }

        if (mapperExes.Count > 0 && vulnSysFiles.Count > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "BYOVD Staging Combo: Mapper + Vulnerable Driver",
                Risk     = RiskLevel.Critical,
                Location = dir,
                FileName = Path.GetFileName(mapperExes[0]),
                Reason   = "A directory contains both a BYOVD kernel-driver mapper tool and a known " +
                           "vulnerable driver in the same location. This is the definitive BYOVD staging " +
                           "pattern used to load unsigned kernel code into Windows by exploiting the " +
                           "vulnerable signed driver to disable Driver Signature Enforcement.",
                Detail   = $"Mapper(s): {string.Join(", ", mapperExes)} | " +
                           $"Vulnerable driver(s): {string.Join(", ", vulnSysFiles)}"
            });
        }
        else if (mapperExes.Count > 0)
        {
            // Scan exe content for BYOVD signatures
            foreach (var exe in mapperExes)
            {
                await ScanExecutableContentAsync(ctx, exe, ct).ConfigureAwait(false);
            }
        }
    }
}
