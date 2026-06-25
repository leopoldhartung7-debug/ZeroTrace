using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class HwidSpoofingDeepScanModule : IScanModule
{
    public string Name => "HWID-Spoofing-Deep";
    public double Weight => 0.75;
    public int ParallelGroup => 4;

    private static readonly string[] KnownSpooferExeNames =
    {
        "spoofer.exe", "hwidspoofer.exe", "hwid-spoofer.exe", "hwid_spoofer.exe",
        "serialspoofer.exe", "diskspoofgui.exe", "macspoofer.exe", "smbiosspoofer.exe",
        "raidspoofer.exe", "pcspoofer.exe", "driverspoofer.exe", "cleaner.exe",
        "eacspoofer.exe", "vacspoofer.exe", "be-spoofer.exe", "battleye-spoofer.exe",
        "easy-spoofer.exe", "kernal-spoofer.exe", "kernelspoofer.exe", "kspoofer.exe",
        "phantom-spoofer.exe", "crow-spoofer.exe", "absolute-spoofer.exe",
        "valorant-spoofer.exe", "fivem-spoofer.exe", "unban.exe", "unban-tool.exe",
    };

    private static readonly string[] KnownSpooferDllNames =
    {
        "spoofer.dll", "hwidspoof.dll", "spoof.dll", "serialchanger.dll", "diskspoof.dll",
    };

    private static readonly string[] KnownSpooferDriverNames =
    {
        "spoofer.sys", "hwid.sys", "hwids.sys", "disk_spoofer.sys", "smbios_spoofer.sys",
        "macchange.sys", "cleaner.sys", "krnl.sys", "krnl64.sys", "krnspoofdrv.sys",
    };

    private static readonly string[] SpooferServiceKeywords =
    {
        "spoofer", "hwid", "hwids", "disk_spoofer", "smbios_spoofer",
        "macchange", "krnl", "krnspoofdrv",
    };

    private static readonly string[] SpooferHkcuSubKeys =
    {
        "Spoofer", "HwidSpoofer", "PCSpoofer", "PhantomSpoofer",
        "CrowSpoofer", "AbsoluteSpoofer", "KSpoofer",
    };

    private static readonly string[] SpoofConfigContentKeywords =
    {
        "serialNumber", "diskId", "macAddress", "smbios", "productId", "machineId",
    };

    private static readonly string[] SpooferBatPatterns =
    {
        "wmic diskdrive set serialnumber",
        "reg add",
        "netsh interface set interface",
    };

    private static readonly string[] SpooferBatRegPatterns =
    {
        "HARDWARE", "BIOS",
    };

    private static readonly string[] SpooferUninstallKeywords =
    {
        "spoofer", "hwid", "unban", "cleaner",
    };

    private static readonly string[] SpooferPrefetchPatterns =
    {
        "SPOOFER", "HWID", "KSPOOFER", "UNBAN", "DISKSPOOFGUI", "SERIALSPOOFER",
    };

    private static readonly string[] SuspiciousBiosManufacturers =
    {
        "to be filled by o.e.m.", "to be filled", "not specified", "default string",
    };

    private static readonly string[] SuspiciousSerialPatterns =
    {
        "0000000000", "000000000000", "0000000000000000",
        "to be filled", "not specified", "default string", "n/a", "none",
        "serial", "chassis serial", "board serial",
    };

    private static readonly string[] SpooferMacPrefixes =
    {
        "000000", "FFFFFF",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "HWID-Spoofing-Deep", "Scanning spoofer executables and DLLs...");
        await ScanSpooferFilesOnDiskAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.2, "HWID-Spoofing-Deep", "Scanning driver artifacts...");
        await ScanSpooferDriversAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.35, "HWID-Spoofing-Deep", "Checking registry artifacts...");
        CheckRegistryArtifacts(ctx, ct);

        ctx.Report(0.5, "HWID-Spoofing-Deep", "Checking BIOS/SMBIOS serial values...");
        CheckBiosSerialAnomalies(ctx, ct);

        ctx.Report(0.6, "HWID-Spoofing-Deep", "Checking MAC address overrides...");
        CheckMacAddressOverrides(ctx, ct);

        ctx.Report(0.7, "HWID-Spoofing-Deep", "Scanning spoofer config files...");
        await ScanSpooferConfigFilesAsync(ctx, ct).ConfigureAwait(false);

        ctx.Report(0.82, "HWID-Spoofing-Deep", "Checking installed program artifacts...");
        CheckInstalledProgramArtifacts(ctx, ct);

        ctx.Report(0.91, "HWID-Spoofing-Deep", "Scanning prefetch artifacts...");
        ScanPrefetchArtifacts(ctx, ct);

        ctx.Report(1.0, "HWID-Spoofing-Deep", "HWID spoofing deep scan complete.");
    }

    private static readonly string[] UserSearchRoots = BuildUserSearchRoots();

    private static string[] BuildUserSearchRoots()
    {
        var roots = new List<string>();
        roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
        roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
        roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        roots.Add(Path.GetTempPath());

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        roots.Add(Path.Combine(profile, "Downloads"));

        roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        roots.Add(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));

        return roots.Where(r => !string.IsNullOrEmpty(r)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static async Task ScanSpooferFilesOnDiskAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var root in UserSearchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
            }
            catch
            {
                continue;
            }

            foreach (var filePath in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(filePath);

                foreach (var known in KnownSpooferExeNames)
                {
                    if (fileName.Equals(known, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "HWID-Spoofing-Deep",
                            Title = $"Known HWID spoofer executable: {fileName}",
                            Risk = RiskLevel.High,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"File '{fileName}' matches a known HWID spoofer executable name. " +
                                     "HWID spoofers manipulate hardware serial numbers to evade hardware bans.",
                            Detail = $"Path: {filePath}",
                        });
                        break;
                    }
                }

                foreach (var known in KnownSpooferDllNames)
                {
                    if (fileName.Equals(known, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "HWID-Spoofing-Deep",
                            Title = $"Known HWID spoofer DLL: {fileName}",
                            Risk = RiskLevel.High,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"File '{fileName}' matches a known HWID spoofer DLL name. " +
                                     "Spoofer DLLs are used to intercept and manipulate hardware ID queries.",
                            Detail = $"Path: {filePath}",
                        });
                        break;
                    }
                }

                var ext = Path.GetExtension(fileName);
                if (ext.Equals(".bat", StringComparison.OrdinalIgnoreCase) ||
                    ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        using var sr = new StreamReader(filePath);
                        string content = await sr.ReadToEndAsync().ConfigureAwait(false);
                        bool hasWmic = content.Contains("wmic diskdrive set serialnumber", StringComparison.OrdinalIgnoreCase);
                        bool hasNetsh = content.Contains("netsh interface set interface", StringComparison.OrdinalIgnoreCase);
                        bool hasRegBios = content.Contains("reg add", StringComparison.OrdinalIgnoreCase)
                                          && (content.Contains("HARDWARE", StringComparison.OrdinalIgnoreCase)
                                              || content.Contains("BIOS", StringComparison.OrdinalIgnoreCase));

                        if (hasWmic || hasNetsh || hasRegBios)
                        {
                            var triggers = new List<string>();
                            if (hasWmic) triggers.Add("wmic diskdrive set serialnumber");
                            if (hasNetsh) triggers.Add("netsh interface set interface");
                            if (hasRegBios) triggers.Add("reg add HARDWARE/BIOS");

                            ctx.AddFinding(new Finding
                            {
                                Module = "HWID-Spoofing-Deep",
                                Title = $"Spoofer batch script: {fileName}",
                                Risk = RiskLevel.High,
                                Location = filePath,
                                FileName = fileName,
                                Reason = $"Batch script '{fileName}' contains commands used by HWID spoofers " +
                                         "to manipulate disk serial numbers, MAC addresses, or BIOS registry entries.",
                                Detail = $"Matched patterns: {string.Join(", ", triggers)}",
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch { }
                }
            }
        }
    }

    private static async Task ScanSpooferDriversAsync(ScanContext ctx, CancellationToken ct)
    {
        var driversDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), "drivers"),
        };

        var recentCutoff = DateTime.Now.AddDays(-30);

        foreach (var dir in driversDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> sysFiles;
            try
            {
                sysFiles = Directory.EnumerateFiles(dir, "*.sys");
            }
            catch
            {
                continue;
            }

            foreach (var filePath in sysFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(filePath);

                foreach (var known in KnownSpooferDriverNames)
                {
                    if (fileName.Equals(known, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "HWID-Spoofing-Deep",
                            Title = $"Known spoofer driver in System32: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"Spoofer driver '{fileName}' found in the Windows driver directory. " +
                                     "Kernel-mode spoofer drivers can manipulate hardware serial numbers at " +
                                     "the OS level, making the spoofing invisible to anti-cheat software.",
                            Detail = $"Path: {filePath}",
                        });
                        goto nextFile;
                    }
                }

                var nameWithoutExt = Path.GetFileNameWithoutExtension(fileName);
                if (nameWithoutExt.Length >= 1 && nameWithoutExt.Length <= 8)
                {
                    DateTime creationTime;
                    try { creationTime = File.GetCreationTime(filePath); }
                    catch { goto nextFile; }

                    if (creationTime >= recentCutoff)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "HWID-Spoofing-Deep",
                            Title = $"Recently added short-name driver: {fileName}",
                            Risk = RiskLevel.Medium,
                            Location = filePath,
                            FileName = fileName,
                            Reason = $"Driver '{fileName}' has a very short name (1-8 characters) and was " +
                                     "added to the Windows driver directory within the last 30 days. " +
                                     "HWID spoofer drivers frequently use obfuscated short names to avoid detection.",
                            Detail = $"Created: {creationTime:yyyy-MM-dd HH:mm:ss} | Path: {filePath}",
                        });
                    }
                }

                nextFile:;
            }
        }

        CheckSpooferServiceRegistry(ctx, ct);
    }

    private static void CheckSpooferServiceRegistry(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services", writable: false);
            if (servicesKey is null) return;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                try
                {
                    using var svc = servicesKey.OpenSubKey(svcName, writable: false);
                    if (svc is null) continue;

                    var imgPath = (svc.GetValue("ImagePath") as string ?? string.Empty);
                    var imgFileName = Path.GetFileName(imgPath);

                    foreach (var known in KnownSpooferDriverNames)
                    {
                        if (imgFileName.Equals(known, StringComparison.OrdinalIgnoreCase)
                            || svcName.Equals(Path.GetFileNameWithoutExtension(known), StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "HWID-Spoofing-Deep",
                                Title = $"Spoofer driver service entry: {svcName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = imgFileName,
                                Reason = $"Registry service entry '{svcName}' references a known HWID spoofer driver. " +
                                         "This indicates an installed or recently-used kernel-mode spoofer.",
                                Detail = $"ImagePath: {imgPath}",
                            });
                            break;
                        }
                    }

                    foreach (var keyword in SpooferServiceKeywords)
                    {
                        if (svcName.Contains(keyword, StringComparison.OrdinalIgnoreCase)
                            || imgPath.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "HWID-Spoofing-Deep",
                                Title = $"Suspicious spoofer-named service: {svcName}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = imgFileName,
                                Reason = $"Registry service '{svcName}' name or ImagePath contains the keyword " +
                                         $"'{keyword}', which is associated with HWID spoofing tools.",
                                Detail = $"ImagePath: {imgPath}",
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

    private static void CheckRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        foreach (var subKey in SpooferHkcuSubKeys)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(
                    $@"Software\{subKey}", writable: false);
                if (key is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "HWID-Spoofing-Deep",
                    Title = $"HWID spoofer registry key: {subKey}",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\Software\{subKey}",
                    Reason = $"Registry key 'HKCU\\Software\\{subKey}' found. This is a known artifact " +
                             "left by HWID spoofer software after installation or use.",
                    Detail = $"Key: HKCU\\Software\\{subKey}",
                });
            }
            catch { }
        }

        if (ct.IsCancellationRequested) return;

        CheckStorageDevicePolicies(ctx, ct);
        CheckDiskEnumArtifacts(ctx, ct);
    }

    private static void CheckStorageDevicePolicies(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        ctx.IncrementRegistryKeys();

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies", writable: false);
            if (key is null) return;

            var writeProtect = key.GetValue("WriteProtect");
            if (writeProtect is int wp && wp == 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = "HWID-Spoofing-Deep",
                    Title = "StorageDevicePolicies WriteProtect enabled",
                    Risk = RiskLevel.Medium,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies",
                    Reason = "StorageDevicePolicies WriteProtect is set to 1. This registry key is sometimes " +
                             "modified by HWID spoofer tools as part of disk serial number manipulation routines.",
                    Detail = $"WriteProtect: {wp}",
                });
            }
        }
        catch { }
    }

    private static void CheckDiskEnumArtifacts(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        try
        {
            using var storageKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Enum\STORAGE", writable: false);
            if (storageKey is null) return;

            foreach (var subName in storageKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                try
                {
                    using var sub = storageKey.OpenSubKey(subName, writable: false);
                    if (sub is null) continue;

                    foreach (var deviceName in sub.GetSubKeyNames())
                    {
                        ctx.IncrementRegistryKeys();
                        try
                        {
                            using var deviceKey = sub.OpenSubKey(deviceName, writable: false);
                            if (deviceKey is null) continue;

                            var friendlyName = (deviceKey.GetValue("FriendlyName") as string ?? string.Empty);
                            var deviceDesc = (deviceKey.GetValue("DeviceDesc") as string ?? string.Empty);

                            foreach (var suspect in new[] { "spoofed", "fake", "generic" })
                            {
                                if (friendlyName.Contains(suspect, StringComparison.OrdinalIgnoreCase)
                                    || deviceDesc.Contains(suspect, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "HWID-Spoofing-Deep",
                                        Title = $"Suspicious disk entry in STORAGE enum: {friendlyName}",
                                        Risk = RiskLevel.High,
                                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Enum\STORAGE\{subName}\{deviceName}",
                                        Reason = $"Disk device entry '{friendlyName}' contains suspicious keyword '{suspect}' " +
                                                 "in its FriendlyName or DeviceDesc. This may indicate a spoofed disk device identity.",
                                        Detail = $"FriendlyName: {friendlyName} | DeviceDesc: {deviceDesc}",
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
        catch { }
    }

    private static void CheckBiosSerialAnomalies(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        ctx.IncrementRegistryKeys();

        try
        {
            using var biosKey = Registry.LocalMachine.OpenSubKey(
                @"HARDWARE\DESCRIPTION\System\BIOS", writable: false);
            if (biosKey is null) return;

            var manufacturer = (biosKey.GetValue("SystemManufacturer") as string ?? string.Empty).Trim();
            var serial = (biosKey.GetValue("SystemSerialNumber") as string ?? string.Empty).Trim();
            var biosVendor = (biosKey.GetValue("BIOSVendor") as string ?? string.Empty).Trim();

            foreach (var suspect in SuspiciousBiosManufacturers)
            {
                if (manufacturer.Contains(suspect, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "HWID-Spoofing-Deep",
                        Title = "Suspicious BIOS manufacturer string",
                        Risk = RiskLevel.Medium,
                        Location = @"HKLM\HARDWARE\DESCRIPTION\System\BIOS",
                        Reason = $"BIOS SystemManufacturer is '{manufacturer}', which is a placeholder value " +
                                 "commonly seen after SMBIOS spoofing tools modify the hardware identity table.",
                        Detail = $"SystemManufacturer: {manufacturer} | BIOSVendor: {biosVendor}",
                    });
                    break;
                }
            }

            if (!string.IsNullOrWhiteSpace(serial))
            {
                var serialNorm = serial.Trim().ToLowerInvariant();
                bool allZeros = serialNorm.Replace("0", string.Empty).Length == 0 && serialNorm.Length > 0;

                foreach (var suspect in SuspiciousSerialPatterns)
                {
                    if (serialNorm.Contains(suspect, StringComparison.OrdinalIgnoreCase) || allZeros)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "HWID-Spoofing-Deep",
                            Title = "Suspicious BIOS serial number",
                            Risk = RiskLevel.Medium,
                            Location = @"HKLM\HARDWARE\DESCRIPTION\System\BIOS",
                            Reason = $"BIOS SystemSerialNumber is '{serial}', which is a placeholder or all-zeros value. " +
                                     "HWID spoofer tools commonly replace genuine serial numbers with zeroed or " +
                                     "placeholder values to prevent hardware ban detection.",
                            Detail = $"SystemSerialNumber: {serial}",
                        });
                        break;
                    }
                }
            }
        }
        catch { }

        if (ct.IsCancellationRequested) return;

        try
        {
            using var idConfigKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\IDConfigDB", writable: false);
            if (idConfigKey is null) return;
            ctx.IncrementRegistryKeys();

            foreach (var valueName in idConfigKey.GetValueNames())
            {
                ctx.IncrementRegistryKeys();
                if (valueName.Contains("SMBIOS", StringComparison.OrdinalIgnoreCase)
                    || valueName.Contains("override", StringComparison.OrdinalIgnoreCase))
                {
                    var val = idConfigKey.GetValue(valueName)?.ToString() ?? string.Empty;
                    ctx.AddFinding(new Finding
                    {
                        Module = "HWID-Spoofing-Deep",
                        Title = $"IDConfigDB SMBIOS override value: {valueName}",
                        Risk = RiskLevel.Medium,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB",
                        Reason = $"IDConfigDB value '{valueName}' may indicate a SMBIOS override applied by a spoofer tool. " +
                                 "Some spoofers write SMBIOS overrides here to persist hardware ID changes across reboots.",
                        Detail = $"Value: {valueName} = {val}",
                    });
                }
            }
        }
        catch { }
    }

    private static void CheckMacAddressOverrides(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        const string nicClassGuid = @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}";

        try
        {
            using var nicClassKey = Registry.LocalMachine.OpenSubKey(nicClassGuid, writable: false);
            if (nicClassKey is null) return;

            foreach (var subKeyName in nicClassKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                try
                {
                    using var adapterKey = nicClassKey.OpenSubKey(subKeyName, writable: false);
                    if (adapterKey is null) continue;

                    var networkAddress = adapterKey.GetValue("NetworkAddress") as string;
                    if (string.IsNullOrWhiteSpace(networkAddress)) continue;

                    var mac = networkAddress.Replace(":", string.Empty)
                                           .Replace("-", string.Empty)
                                           .ToUpperInvariant()
                                           .Trim();

                    if (mac.Length < 12) continue;

                    var description = adapterKey.GetValue("DriverDesc") as string ?? subKeyName;

                    bool isSuspiciousPrefix = SpooferMacPrefixes.Any(p =>
                        mac.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                    bool localBitSet = false;
                    if (int.TryParse(mac.Substring(0, 2),
                        System.Globalization.NumberStyles.HexNumber, null, out int firstByte))
                    {
                        localBitSet = (firstByte & 0x02) != 0;
                    }

                    if (isSuspiciousPrefix || localBitSet)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "HWID-Spoofing-Deep",
                            Title = $"Manually overridden MAC address: {description}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{nicClassGuid}\{subKeyName}",
                            Reason = $"Network adapter '{description}' has a manually-configured MAC address " +
                                     $"(NetworkAddress = {networkAddress}). " +
                                     (localBitSet ? "The locally-administered bit is set, indicating the MAC was manually assigned. " : "") +
                                     (isSuspiciousPrefix ? "The MAC prefix matches known spoofer patterns. " : "") +
                                     "MAC spoofing is used to evade hardware bans tied to network adapter addresses.",
                            Detail = $"NetworkAddress: {networkAddress} | Adapter: {description}",
                        });
                    }
                    else
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "HWID-Spoofing-Deep",
                            Title = $"Manually configured MAC address on adapter: {description}",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKLM\{nicClassGuid}\{subKeyName}",
                            Reason = $"Network adapter '{description}' has a NetworkAddress value set in the registry " +
                                     $"(MAC: {networkAddress}). Any manually-set MAC address is a potential spoofer indicator.",
                            Detail = $"NetworkAddress: {networkAddress} | Adapter: {description}",
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static async Task ScanSpooferConfigFilesAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Path.GetTempPath(),
        };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> allFiles;
            try
            {
                allFiles = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
            }
            catch
            {
                continue;
            }

            foreach (var filePath in allFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(filePath);
                var ext = Path.GetExtension(fileName).ToLowerInvariant();

                if (ext is ".spoof" or ".hwid" or ".unban")
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = "HWID-Spoofing-Deep",
                        Title = $"Spoofer config file extension: {fileName}",
                        Risk = RiskLevel.High,
                        Location = filePath,
                        FileName = fileName,
                        Reason = $"File with extension '{ext}' found. This file extension is exclusively " +
                                 "associated with HWID spoofer tools for storing spoofing configuration data.",
                        Detail = $"Path: {filePath}",
                    });
                    continue;
                }

                if (ext == ".json" && fileName.Equals("config.json", StringComparison.OrdinalIgnoreCase))
                {
                    var parentDir = Path.GetDirectoryName(filePath) ?? string.Empty;
                    var parentName = Path.GetFileName(parentDir).ToLowerInvariant();

                    bool isSuspiciousDir = parentName.Contains("spoofer", StringComparison.OrdinalIgnoreCase)
                                          || parentName.Contains("hwid", StringComparison.OrdinalIgnoreCase)
                                          || parentName.Contains("unban", StringComparison.OrdinalIgnoreCase)
                                          || parentName.Contains("cleaner", StringComparison.OrdinalIgnoreCase);

                    if (isSuspiciousDir)
                    {
                        try
                        {
                            using var sr = new StreamReader(filePath);
                            string content = await sr.ReadToEndAsync().ConfigureAwait(false);

                            foreach (var keyword in SpoofConfigContentKeywords)
                            {
                                if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "HWID-Spoofing-Deep",
                                        Title = $"Spoofer config.json in suspicious directory: {parentName}",
                                        Risk = RiskLevel.Medium,
                                        Location = filePath,
                                        FileName = fileName,
                                        Reason = $"config.json file in directory '{parentName}' contains the keyword '{keyword}', " +
                                                 "which is characteristic of HWID spoofer configuration files that store " +
                                                 "hardware ID replacement values.",
                                        Detail = $"Keyword match: {keyword} | Directory: {parentDir}",
                                    });
                                    break;
                                }
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                        catch { }
                    }
                }
            }
        }
    }

    private static void CheckInstalledProgramArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var uninstallKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (var uninstallPath in uninstallKeys)
        {
            if (ct.IsCancellationRequested) return;

            try
            {
                using var root = Registry.LocalMachine.OpenSubKey(uninstallPath, writable: false);
                if (root is null) continue;

                foreach (var subName in root.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    try
                    {
                        using var entry = root.OpenSubKey(subName, writable: false);
                        if (entry is null) continue;

                        var displayName = (entry.GetValue("DisplayName") as string ?? string.Empty);
                        var publisher = (entry.GetValue("Publisher") as string ?? string.Empty);

                        if (string.IsNullOrEmpty(displayName)) continue;

                        foreach (var keyword in SpooferUninstallKeywords)
                        {
                            if (displayName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                bool noPublisher = string.IsNullOrWhiteSpace(publisher);
                                bool suspectPublisher = publisher.Contains("cheat", StringComparison.OrdinalIgnoreCase)
                                                       || publisher.Contains("hack", StringComparison.OrdinalIgnoreCase)
                                                       || publisher.Contains("unban", StringComparison.OrdinalIgnoreCase);

                                if (noPublisher || suspectPublisher)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "HWID-Spoofing-Deep",
                                        Title = $"Spoofer in installed programs: {displayName}",
                                        Risk = RiskLevel.High,
                                        Location = $@"HKLM\{uninstallPath}\{subName}",
                                        Reason = $"Installed program '{displayName}' matches a spoofer keyword '{keyword}' " +
                                                 (noPublisher ? "and has no publisher listed" : $"and has a suspicious publisher '{publisher}'") +
                                                 ". This indicates an installed HWID spoofer tool.",
                                        Detail = $"DisplayName: {displayName} | Publisher: {publisher}",
                                    });
                                }
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

    private static void ScanPrefetchArtifacts(ScanContext ctx, CancellationToken ct)
    {
        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir)) return;

        IEnumerable<string> pfFiles;
        try
        {
            pfFiles = Directory.EnumerateFiles(prefetchDir, "*.pf");
        }
        catch
        {
            return;
        }

        foreach (var pfPath in pfFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var pfName = Path.GetFileNameWithoutExtension(pfPath).ToUpperInvariant();

            foreach (var pattern in SpooferPrefetchPatterns)
            {
                if (pfName.StartsWith(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    DateTime lastRun;
                    try { lastRun = File.GetLastWriteTime(pfPath); }
                    catch { lastRun = DateTime.MinValue; }

                    ctx.AddFinding(new Finding
                    {
                        Module = "HWID-Spoofing-Deep",
                        Title = $"Spoofer prefetch artifact: {pfName}",
                        Risk = RiskLevel.High,
                        Location = pfPath,
                        FileName = Path.GetFileName(pfPath),
                        Reason = $"Prefetch file '{pfName}.pf' indicates that a HWID spoofer-related executable " +
                                 $"matching pattern '{pattern}' was previously run on this system. " +
                                 "Prefetch artifacts persist even after the original file is deleted.",
                        Detail = lastRun != DateTime.MinValue
                            ? $"Last executed (approx.): {lastRun:yyyy-MM-dd HH:mm:ss}"
                            : null,
                    });
                    break;
                }
            }
        }
    }
}
