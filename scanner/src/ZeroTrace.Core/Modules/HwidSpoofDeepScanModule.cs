using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class HwidSpoofDeepScanModule : IScanModule
{
    public string Name => "HWID Spoofer Deep Detection";
    public double Weight => 4.4;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Environment paths
    // -------------------------------------------------------------------------
    private static readonly string SystemRoot =
        Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows";

    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

    private static readonly string Downloads =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

    private static readonly string Documents =
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

    private static readonly string AppDataRoaming =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    private static readonly string AppDataLocal =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static readonly string TempDir = Path.GetTempPath();

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static readonly string SystemDriversDir =
        Path.Combine(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "System32", "drivers");

    // -------------------------------------------------------------------------
    // Known HWID spoofer executables
    // -------------------------------------------------------------------------
    private static readonly string[] SpooferExeNames =
    [
        "hwid_spoofer.exe",
        "HWID_Changer.exe",
        "HWIDChanger.exe",
        "hwid-spoofer.exe",
        "hwid-changer.exe",
        "PhantomSpoofer.exe",
        "phantom_spoofer.exe",
        "CrowSpoofer.exe",
        "crow_spoofer.exe",
        "KSpoofer.exe",
        "k-spoofer.exe",
        "k_spoofer.exe",
        "AbsoluteSpoofer.exe",
        "absolute_spoofer.exe",
        "TsSpoofer.exe",
        "ts_spoofer.exe",
        "SkypeSpoofer.exe",
        "skype_spoofer.exe",
        "EvoSpoofer.exe",
        "evo_spoofer.exe",
        "UnlinkSpoofer.exe",
        "unlink_spoofer.exe",
        "GhostSpoofer.exe",
        "ghost_spoofer.exe",
        "ProSpoofer.exe",
        "pro_spoofer.exe",
        "EliteSpoofer.exe",
        "elite_spoofer.exe",
        "FutureSpoofery.exe",
        "future_spoofer.exe",
        "ShadowSpoofer.exe",
        "shadow_spoofer.exe",
        "NightSpoofer.exe",
        "night_spoofer.exe",
        "BlueSpoofer.exe",
        "blue_spoofer.exe",
        "StealthSpoofer.exe",
        "stealth_spoofer.exe",
        "HideSpoofer.exe",
        "hide_spoofer.exe",
        "MasterSpoofer.exe",
        "master_spoofer.exe",
        "SpooferX.exe",
        "spoofer_x.exe",
        "SpooferPro.exe",
        "spoofer_pro.exe",
        "BanBypass.exe",
        "ban_bypass.exe",
        "BanEvader.exe",
        "ban_evader.exe",
        "SpoofAndPlay.exe",
        "spoof_and_play.exe",
        "RezeexSpoofer.exe",
        "rezeex_spoofer.exe",
        "RealSpoofer.exe",
        "real_spoofer.exe",
        "IcebergSpoofer.exe",
        "iceberg_spoofer.exe",
        "FrigidSpoofer.exe",
        "frigid_spoofer.exe",
        "ZenSpoofer.exe",
        "zen_spoofer.exe",
        "NexusSpoofer.exe",
        "nexus_spoofer.exe",
        "VoidSpoofer.exe",
        "void_spoofer.exe",
        "ChronosSpoofer.exe",
        "chronos_spoofer.exe",
        "QuantumSpoofer.exe",
        "quantum_spoofer.exe",
        "HWIDGen.exe",
        "hwid_gen.exe",
        "hwid_reset.exe",
        "HWIDReset.exe",
        "SerialChanger.exe",
        "serial_changer.exe",
        "DiskSerialChanger.exe",
        "disk_serial_changer.exe",
        "MacChanger.exe",
        "mac_changer.exe",
        "VolumeIDChanger.exe",
        "volumeid_changer.exe",
        "AmideWin64.exe",
        "smbios_editor.exe",
        "bios_spoofer.exe",
        "BiosSpoofer.exe",
        "SMBIOSSpoofer.exe",
        "smbios_spoofer.exe",
    ];

    // -------------------------------------------------------------------------
    // Known HWID spoofer driver files — suspicious outside System32\drivers
    // -------------------------------------------------------------------------
    private static readonly string[] SpooferDriverNames =
    [
        "spoofer.sys",
        "hwid_spoofer.sys",
        "hwids.sys",
        "spoof_driver.sys",
        "phantom.sys",
        "crow.sys",
        "absolute.sys",
        "ts_spoofer.sys",
        "kspoofer.sys",
        "ghostspoofer.sys",
        "stealthspoofer.sys",
        "shadowspoofer.sys",
        "masterspy.sys",
        "hidespy.sys",
        "elitespoof.sys",
        "voidspoof.sys",
        "zenspoof.sys",
        "nexusspoof.sys",
        "chronosspoof.sys",
        "quantumspoof.sys",
        "rezeex.sys",
        "realspoofer.sys",
        "icebergspoof.sys",
        "frigidspoof.sys",
        "diskspoof.sys",
        "macspoof.sys",
        "serialspoof.sys",
        "smbiosspoof.sys",
        "uuidspoof.sys",
        "nicspoof.sys",
        "pcispoof.sys",
        "dmaspoof.sys",
    ];

    // -------------------------------------------------------------------------
    // GitHub clone directory names for HWID spoofer repos
    // -------------------------------------------------------------------------
    private static readonly string[] SpooferRepoDirNames =
    [
        "HWID-Spoofer",
        "hwid-spoofer",
        "HWIDSpoofer",
        "hwid_spoofer",
        "Phantom-Spoofer",
        "phantom-spoofer",
        "PhantomSpoofer",
        "Crow-Spoofer",
        "crow-spoofer",
        "CrowSpoofer",
        "K-Spoofer",
        "k-spoofer",
        "KSpoofer",
        "Absolute-Spoofer",
        "absolute-spoofer",
        "AbsoluteSpoofer",
        "spoofer-source",
        "hwid-bypass",
        "HWID-Bypass",
        "ban-bypass",
        "BanBypass",
        "hwid-changer",
        "HWID-Changer",
        "spoofer-pro",
        "SpooferPro",
        "EvoSpoofer",
        "evo-spoofer",
        "GhostSpoofer",
        "ghost-spoofer",
        "UnlinkSpoofer",
        "unlink-spoofer",
    ];

    // -------------------------------------------------------------------------
    // Placeholder / clearly fake serial number values
    // -------------------------------------------------------------------------
    private static readonly string[] FakeSerialPatterns =
    [
        "0000000000000000",
        "00000000000000000",
        "000000000000",
        "00000000",
        "SPOOFED",
        "DEFAULT",
        "NONE",
        "N/A",
        "NOT SPECIFIED",
        "TO BE FILLED",
        "TO BE DETERMINED",
        "SERIAL NUMBER",
        "DEFAULT STRING",
        "CHASSIS SERIAL",
        "BOARD SERIAL",
        "SYSTEM SERIAL",
        "FFFFFFFFFFFFFFFF",
        "DEADBEEF",
        "BAADBEEF",
        "12345678",
        "87654321",
        "XXXXXXXXXXXX",
        "AAAAAAAAAAAA",
        "SPOOF",
        "CHANGED",
        "MODIFIED",
        "RANDOMIZED",
        "FAKE",
    ];

    // =========================================================================
    // Entry point
    // =========================================================================
    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanSpooferExecutablesAsync(ctx, ct);
        await ScanSpooferDriversAsync(ctx, ct);
        await CheckRegistrySpoofingArtifactsAsync(ctx, ct);
        await CheckMachineGuidAnomaliesAsync(ctx, ct);
        await CheckBiosSerialAnomaliesAsync(ctx, ct);
        await CheckNicMacOverridesAsync(ctx, ct);
        await CheckDiskSerialAnomaliesAsync(ctx, ct);
        await CheckVolumeSerialAnomaliesAsync(ctx, ct);
        await CheckSmacAndTechnitiumArtifactsAsync(ctx, ct);
        await CheckSpooferRepoDirsAsync(ctx, ct);
        await ScanEfiBiosSpoofToolsAsync(ctx, ct);
        await CheckWmiSpoofingHooksAsync(ctx, ct);
    }

    // =========================================================================
    // 1. Known spoofer executable file scan
    // =========================================================================
    private async Task ScanSpooferExecutablesAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] scanDirs =
        [
            Desktop,
            Downloads,
            Documents,
            TempDir,
            AppDataRoaming,
            AppDataLocal,
            Path.Combine(AppDataLocal, "Temp"),
            Path.Combine(UserProfile, "Games"),
            Path.Combine(UserProfile, "Cheats"),
        ];

        foreach (string dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                string fileName = Path.GetFileName(filePath);
                ctx.IncrementFiles();

                try
                {
                    foreach (string spooferExe in SpooferExeNames)
                    {
                        if (fileName.Equals(spooferExe, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Known HWID Spoofer Executable Detected",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File name \"{fileName}\" matches a known HWID spoofer tool. This software is designed to manipulate hardware identifiers to evade hardware bans.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }

                    // Heuristic: any file whose name contains both "spoof" and ("hwid" or "serial" or "mac" or "disk")
                    string lowerName = fileName.ToLowerInvariant();
                    if (lowerName.Contains("spoof") &&
                        (lowerName.Contains("hwid") ||
                         lowerName.Contains("serial") ||
                         lowerName.Contains("disk") ||
                         lowerName.Contains("mac") ||
                         lowerName.Contains("bios") ||
                         lowerName.Contains("smbios") ||
                         lowerName.Contains("uuid") ||
                         lowerName.Contains("volume")))
                    {
                        string ext = Path.GetExtension(fileName);
                        if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                            ext.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                            ext.Equals(".sys", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Heuristic HWID Spoofer Artifact Detected",
                                Risk     = RiskLevel.High,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"File name \"{fileName}\" contains HWID spoofing-related keywords. The combination suggests this is a hardware identifier manipulation tool.",
                                Detail   = $"Full path: {filePath}",
                            });
                        }
                    }
                }
                catch (IOException) { }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 2. Spoofer kernel driver detection
    // =========================================================================
    private async Task ScanSpooferDriversAsync(ScanContext ctx, CancellationToken ct)
    {
        // Search user-accessible directories for spoofer drivers
        string[] userSearchDirs =
        [
            Desktop,
            Downloads,
            Documents,
            TempDir,
            AppDataRoaming,
            AppDataLocal,
        ];

        foreach (string dir in userSearchDirs)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.sys", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                string fileName = Path.GetFileName(filePath);
                ctx.IncrementFiles();

                try
                {
                    foreach (string driverName in SpooferDriverNames)
                    {
                        if (fileName.Equals(driverName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "HWID Spoofer Kernel Driver Outside System32 Detected",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"Known HWID spoofer kernel driver \"{fileName}\" found outside System32\\drivers. Spoofer drivers are kernel-mode components that intercept hardware ID queries to substitute fake values.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
            }
        }

        // Also check System32\drivers for spoofer drivers loaded there
        if (Directory.Exists(SystemDriversDir))
        {
            IEnumerable<string> driverFiles;
            try
            {
                driverFiles = Directory.EnumerateFiles(SystemDriversDir, "*.sys", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                await Task.CompletedTask;
                return;
            }

            foreach (string filePath in driverFiles)
            {
                ct.ThrowIfCancellationRequested();

                string fileName = Path.GetFileName(filePath);
                ctx.IncrementFiles();

                try
                {
                    foreach (string driverName in SpooferDriverNames)
                    {
                        if (fileName.Equals(driverName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "HWID Spoofer Kernel Driver Installed in System32",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"Known HWID spoofer kernel driver \"{fileName}\" found in System32\\drivers. This driver has been installed into the system — likely registered as a service.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 3. Registry spoofing artifacts — service keys, software keys
    // =========================================================================
    private async Task CheckRegistrySpoofingArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Known spoofer software registry keys
            string[] spooferSoftwareKeys =
            [
                @"SOFTWARE\HWID Spoofer",
                @"SOFTWARE\HWIDSpoofer",
                @"SOFTWARE\PhantomSpoofer",
                @"SOFTWARE\CrowSpoofer",
                @"SOFTWARE\KSpoofer",
                @"SOFTWARE\AbsoluteSpoofer",
                @"SOFTWARE\TsSpoofer",
                @"SOFTWARE\GhostSpoofer",
                @"SOFTWARE\EliteSpoofer",
                @"SOFTWARE\ShadowSpoofer",
                @"SOFTWARE\NightSpoofer",
                @"SOFTWARE\BlueSpoofer",
                @"SOFTWARE\StealthSpoofer",
                @"SOFTWARE\MasterSpoofer",
                @"SOFTWARE\SpooferX",
                @"SOFTWARE\SpooferPro",
                @"SOFTWARE\BanBypass",
                @"SOFTWARE\BanEvader",
                @"SOFTWARE\Serial Spoofer",
                @"SOFTWARE\HWID Changer",
                @"SOFTWARE\RezeexSpoofer",
                @"SOFTWARE\RealSpoofer",
                @"SOFTWARE\IcebergSpoofer",
                @"SOFTWARE\FrigidSpoofer",
                @"SOFTWARE\DMA Spoofer",
                @"SOFTWARE\EvoSpoofer",
                @"SOFTWARE\UnlinkSpoofer",
                @"SOFTWARE\NexusSpoofer",
                @"SOFTWARE\VoidSpoofer",
            ];

            foreach (string keyPath in spooferSoftwareKeys)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? lmKey = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                    if (lmKey is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "HWID Spoofer Software Registry Key Found (HKLM)",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = $"Registry key \"{keyPath}\" found in HKLM. This is a known HWID spoofer tool installation key.",
                            Detail   = $"Key path: HKLM\\{keyPath}",
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }

                ctx.IncrementRegistryKeys();
                try
                {
                    using RegistryKey? cuKey = Registry.CurrentUser.OpenSubKey(keyPath, writable: false);
                    if (cuKey is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "HWID Spoofer Software Registry Key Found (HKCU)",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKCU\{keyPath}",
                            Reason   = $"Registry key \"{keyPath}\" found in HKCU. This is a known HWID spoofer tool installation key.",
                            Detail   = $"Key path: HKCU\\{keyPath}",
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }
            }

            // Check for spoofer-named services
            string servicesBasePath = @"SYSTEM\CurrentControlSet\Services";
            ctx.IncrementRegistryKeys();
            try
            {
                using RegistryKey? servicesKey = Registry.LocalMachine.OpenSubKey(servicesBasePath, writable: false);
                if (servicesKey is not null)
                {
                    foreach (string svcName in servicesKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();

                        string lowerSvc = svcName.ToLowerInvariant();
                        if (lowerSvc.Contains("spoofer") ||
                            lowerSvc.Contains("hwid") && lowerSvc.Contains("spoof") ||
                            lowerSvc.Contains("serialspoof") ||
                            lowerSvc.Contains("macspoof") ||
                            lowerSvc.Contains("diskspoof") ||
                            lowerSvc.Contains("smbiosspoof"))
                        {
                            ctx.IncrementRegistryKeys();
                            try
                            {
                                using RegistryKey? svcKey = servicesKey.OpenSubKey(svcName, writable: false);
                                object? startVal = svcKey?.GetValue("Start");
                                string startInfo = startVal is int si ? $"Start={si}" : "Start=unknown";

                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"HWID Spoofer Service Key Detected: {svcName}",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKLM\{servicesBasePath}\{svcName}",
                                    Reason   = $"Service \"{svcName}\" has a name matching HWID spoofer driver/service naming conventions. This is a kernel-mode spoofer component registered as a Windows service.",
                                    Detail   = startInfo,
                                });
                            }
                            catch (UnauthorizedAccessException) { }
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }
        }, ct);
    }

    // =========================================================================
    // 4. MachineGuid anomalies
    // =========================================================================
    private async Task CheckMachineGuidAnomaliesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            string cryptoPath = @"SOFTWARE\Microsoft\Cryptography";
            ctx.IncrementRegistryKeys();

            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(cryptoPath, writable: false);
                if (key is null) return;

                object? guidVal = key.GetValue("MachineGuid");
                if (guidVal is string guidStr)
                {
                    // Flag all-zero or suspiciously short GUIDs
                    if (string.IsNullOrWhiteSpace(guidStr))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "MachineGuid Is Empty",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{cryptoPath}",
                            Reason   = "The MachineGuid value in HKLM\\SOFTWARE\\Microsoft\\Cryptography is empty. HWID spoofers sometimes blank this value as part of hardware ban evasion.",
                            Detail   = "MachineGuid = (empty)",
                        });
                    }
                    else
                    {
                        // Check if all hex characters are the same (all-zeros, all-f, etc.)
                        string stripped = guidStr.Replace("-", "").Replace("{", "").Replace("}", "");
                        if (stripped.Length > 0 && stripped.Distinct().Count() <= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "MachineGuid Contains Placeholder Pattern",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{cryptoPath}",
                                Reason   = "The MachineGuid consists of repeating or near-uniform characters, indicating it may have been spoofed to a placeholder value.",
                                Detail   = $"MachineGuid = {guidStr}",
                            });
                        }
                    }
                }
                else if (guidVal is null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "MachineGuid Missing",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{cryptoPath}",
                        Reason   = "The MachineGuid value is missing from HKLM\\SOFTWARE\\Microsoft\\Cryptography. Spoofers may delete this value to force regeneration or leave it absent.",
                        Detail   = "MachineGuid value not found",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }

            // IDConfigDB hardware profiles — spoofers may modify these
            string idConfigPath = @"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001";
            ctx.IncrementRegistryKeys();
            try
            {
                using RegistryKey? idKey = Registry.LocalMachine.OpenSubKey(idConfigPath, writable: false);
                if (idKey is not null)
                {
                    // Check for FriendlyName that suggests spoofing
                    object? hwProfileId = idKey.GetValue("HwProfileGuid");
                    if (hwProfileId is string hwGuid)
                    {
                        string stripped2 = hwGuid.Replace("-", "").Replace("{", "").Replace("}", "");
                        if (stripped2.Length > 0 && stripped2.Distinct().Count() <= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Hardware Profile GUID Contains Placeholder Pattern",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{idConfigPath}",
                                Reason   = "The HwProfileGuid in the hardware profiles key contains a repeating/placeholder pattern. This may indicate HWID spoofing at the hardware profile level.",
                                Detail   = $"HwProfileGuid = {hwGuid}",
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }
        }, ct);
    }

    // =========================================================================
    // 5. BIOS/SMBIOS serial number anomalies
    // =========================================================================
    private async Task CheckBiosSerialAnomaliesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            var biosChecks = new[]
            {
                (Path: @"HARDWARE\DESCRIPTION\System\BIOS", ValueNames: new[] { "SystemSerialNumber", "BIOSReleaseDate", "BIOSVendor", "BIOSVersion", "SystemManufacturer", "SystemProductName" }),
                (Path: @"SYSTEM\CurrentControlSet\Control\SystemInformation",  ValueNames: new[] { "ComputerHardwareId", "BIOSReleaseDate", "BIOSVersion", "SystemManufacturer" }),
            };

            foreach (var check in biosChecks)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(check.Path, writable: false);
                    if (key is null) continue;

                    foreach (string valueName in check.ValueNames)
                    {
                        ct.ThrowIfCancellationRequested();

                        object? val = key.GetValue(valueName);
                        if (val is not string strVal) continue;

                        foreach (string fakePattern in FakeSerialPatterns)
                        {
                            if (strVal.Equals(fakePattern, StringComparison.OrdinalIgnoreCase) ||
                                strVal.Trim().Equals(fakePattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"BIOS/SMBIOS {valueName} Contains Placeholder Value",
                                    Risk     = RiskLevel.High,
                                    Location = $@"HKLM\{check.Path}",
                                    Reason   = $"Registry value {valueName} under {check.Path} contains a known placeholder or spoofed value \"{strVal}\". HWID spoofers replace legitimate BIOS strings with these markers.",
                                    Detail   = $"{valueName} = \"{strVal}\"",
                                });
                                break;
                            }
                        }

                        // Flag empty serial number values
                        if (valueName.Contains("Serial", StringComparison.OrdinalIgnoreCase) &&
                            string.IsNullOrWhiteSpace(strVal))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"BIOS/SMBIOS {valueName} Is Empty",
                                Risk     = RiskLevel.Medium,
                                Location = $@"HKLM\{check.Path}",
                                Reason   = $"Registry value {valueName} is empty. Legitimate hardware always populates this field; an empty value suggests spoofing.",
                                Detail   = $"{valueName} = (empty)",
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }
            }
        }, ct);
    }

    // =========================================================================
    // 6. NIC MAC address override detection
    // =========================================================================
    private async Task CheckNicMacOverridesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // The NIC class key contains subkeys for each adapter
            string nicClassPath = @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}";
            ctx.IncrementRegistryKeys();

            try
            {
                using RegistryKey? nicClass = Registry.LocalMachine.OpenSubKey(nicClassPath, writable: false);
                if (nicClass is null) return;

                foreach (string subkeyName in nicClass.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    // Skip properties subkeys
                    if (subkeyName.Equals("Properties", StringComparison.OrdinalIgnoreCase))
                        continue;

                    try
                    {
                        using RegistryKey? nicKey = nicClass.OpenSubKey(subkeyName, writable: false);
                        if (nicKey is null) continue;

                        // NetworkAddress presence means a MAC override is in place
                        object? networkAddress = nicKey.GetValue("NetworkAddress");
                        if (networkAddress is string mac && !string.IsNullOrWhiteSpace(mac))
                        {
                            object? driverDesc = nicKey.GetValue("DriverDesc");
                            string adapterDesc = driverDesc is string s ? s : "Unknown adapter";

                            // Check if the MAC is all-zeros or all-same characters
                            string macStripped = mac.Replace(":", "").Replace("-", "");
                            bool isSuspiciousMac = macStripped.Length > 0 &&
                                                   (macStripped.Distinct().Count() <= 2 ||
                                                    macStripped.Equals("000000000000", StringComparison.OrdinalIgnoreCase));

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "NIC MAC Address Override Detected",
                                Risk     = isSuspiciousMac ? RiskLevel.Critical : RiskLevel.High,
                                Location = $@"HKLM\{nicClassPath}\{subkeyName}",
                                Reason   = $"Adapter \"{adapterDesc}\" has a NetworkAddress override value set in the registry. This forces Windows to use a custom MAC address instead of the hardware-burned address — a common HWID spoofer technique for ban evasion.",
                                Detail   = $"NetworkAddress = {mac} | Adapter: {adapterDesc}",
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }
        }, ct);
    }

    // =========================================================================
    // 7. Disk serial number anomalies via SCSI registry
    // =========================================================================
    private async Task CheckDiskSerialAnomaliesAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // The SCSI bus registry often contains cached disk identifiers
            // that spoofers may zero out
            string[] scsiPaths =
            [
                @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
                @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
                @"HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
            ];

            foreach (string scsiPath in scsiPaths)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? scsiKey = Registry.LocalMachine.OpenSubKey(scsiPath, writable: false);
                    if (scsiKey is null) continue;

                    object? identifierVal = scsiKey.GetValue("Identifier");
                    if (identifierVal is string identifier)
                    {
                        foreach (string fakePattern in FakeSerialPatterns)
                        {
                            if (identifier.Trim().Contains(fakePattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "Disk Drive Identifier Contains Placeholder Value",
                                    Risk     = RiskLevel.High,
                                    Location = $@"HKLM\{scsiPath}",
                                    Reason   = $"The SCSI disk Identifier value contains \"{fakePattern}\", which is a known fake/placeholder serial pattern used by HWID spoofers to zero out disk identifiers.",
                                    Detail   = $"Identifier = \"{identifier}\"",
                                });
                                break;
                            }
                        }

                        // All-numeric-zero pattern check
                        string identifierStripped = identifier.Replace(" ", "").Replace("-", "");
                        if (identifierStripped.Length >= 8 &&
                            identifierStripped.All(c => c == '0'))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Disk Drive Identifier Is All Zeros",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{scsiPath}",
                                Reason   = "The SCSI disk Identifier is filled with zeros, indicating the disk serial number was erased or spoofed by an HWID spoofer tool.",
                                Detail   = $"Identifier = \"{identifier}\"",
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }
            }
        }, ct);
    }

    // =========================================================================
    // 8. Volume serial number spoofing (VolumeID tool artifact)
    // =========================================================================
    private async Task CheckVolumeSerialAnomaliesAsync(ScanContext ctx, CancellationToken ct)
    {
        // VolumeID tool (by Sysinternals-fork) writes Volume.dat as an artifact
        string[] volumeDatPaths =
        [
            Path.Combine(SystemRoot, "Volume.dat"),
            Path.Combine(SystemRoot, "System32", "Volume.dat"),
            Path.Combine(TempDir, "Volume.dat"),
        ];

        foreach (string volumeDatPath in volumeDatPaths)
        {
            ct.ThrowIfCancellationRequested();

            if (!File.Exists(volumeDatPath))
                continue;

            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "VolumeID Tool Artifact Detected",
                Risk     = RiskLevel.High,
                Location = volumeDatPath,
                FileName = "Volume.dat",
                Reason   = "Volume.dat is a known artifact left by VolumeID — a tool that modifies the FAT/NTFS volume serial number. Modifying volume serial numbers is a common HWID ban evasion technique.",
                Detail   = $"VolumeID artifact path: {volumeDatPath}",
            });
        }

        // Also search for VolumeID executable
        string[] volumeIdExeNames = ["volumeid.exe", "VolumeID.exe", "VolumeID64.exe", "volumeid64.exe"];

        string[] searchDirs =
        [
            Desktop,
            Downloads,
            TempDir,
            SystemRoot,
            Path.Combine(SystemRoot, "System32"),
        ];

        foreach (string dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                string fileName = Path.GetFileName(filePath);
                ctx.IncrementFiles();

                try
                {
                    foreach (string volIdExe in volumeIdExeNames)
                    {
                        if (fileName.Equals(volIdExe, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "VolumeID Tool Detected",
                                Risk     = RiskLevel.High,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"VolumeID executable \"{fileName}\" detected. This tool is used to change NTFS/FAT volume serial numbers, a known component of HWID spoofing for ban evasion.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 9. SMAC / Technitium MAC Changer artifacts
    // =========================================================================
    private async Task CheckSmacAndTechnitiumArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // SMAC MAC Address Changer leaves registry keys
            string[] smacKeys =
            [
                @"SOFTWARE\KLC Consulting\SMAC",
                @"SOFTWARE\SMAC",
                @"SOFTWARE\SMAC MAC Address Changer",
            ];

            foreach (string smacKey in smacKeys)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(smacKey, writable: false);
                    if (key is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "SMAC MAC Address Changer Installed",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{smacKey}",
                            Reason   = "SMAC MAC Address Changer installation key found in HKLM. SMAC is a tool specifically designed to change the MAC address of network adapters — a common HWID spoofing technique.",
                            Detail   = $"Key: HKLM\\{smacKey}",
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }

                ctx.IncrementRegistryKeys();
                try
                {
                    using RegistryKey? cuKey = Registry.CurrentUser.OpenSubKey(smacKey, writable: false);
                    if (cuKey is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "SMAC MAC Address Changer (HKCU) Detected",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{smacKey}",
                            Reason   = "SMAC MAC Address Changer key found in HKCU. This tool is used to substitute hardware MAC addresses for ban evasion.",
                            Detail   = $"Key: HKCU\\{smacKey}",
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }
            }

            // Technitium MAC Address Changer registry
            string[] technitiumKeys =
            [
                @"SOFTWARE\Technitium\MAC Address Changer",
                @"SOFTWARE\Technitium",
            ];

            foreach (string techKey in technitiumKeys)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(techKey, writable: false);
                    if (key is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Technitium MAC Address Changer Installed",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{techKey}",
                            Reason   = "Technitium MAC Address Changer installation key found. This is a well-known free tool for changing MAC addresses, used by spoofers for ban evasion.",
                            Detail   = $"Key: HKLM\\{techKey}",
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (System.Security.SecurityException) { }
            }
        }, ct);

        // Also check for SMAC / Technitium executable files
        string[] macChangerExes =
        [
            "SMAC.exe",
            "smac.exe",
            "TechnitiumMacChanger.exe",
            "tmac.exe",
            "TMAC.exe",
            "MACAddressChanger.exe",
            "mac_changer.exe",
            "MacChanger.exe",
        ];

        string[] searchDirs =
        [
            Desktop,
            Downloads,
            Documents,
            TempDir,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SMAC"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "SMAC"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Technitium"),
        ];

        foreach (string dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                string fileName = Path.GetFileName(filePath);
                ctx.IncrementFiles();

                try
                {
                    foreach (string exeName in macChangerExes)
                    {
                        if (fileName.Equals(exeName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "MAC Address Changer Tool Detected",
                                Risk     = RiskLevel.High,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"\"{fileName}\" is a known MAC address changer tool. Changing the MAC address is a standard technique in HWID spoofing to evade hardware bans.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
            }
        }
    }

    // =========================================================================
    // 10. GitHub clone directory detection for spoofer repos
    // =========================================================================
    private async Task CheckSpooferRepoDirsAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] repoRoots =
        [
            Desktop,
            Downloads,
            Documents,
            UserProfile,
            AppDataRoaming,
            AppDataLocal,
            Path.Combine(UserProfile, "source"),
            Path.Combine(UserProfile, "repos"),
            Path.Combine(UserProfile, "projects"),
            Path.Combine(UserProfile, "git"),
            Path.Combine(UserProfile, "GitHub"),
            Path.Combine(UserProfile, "GitLab"),
        ];

        foreach (string root in repoRoots)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(root))
                continue;

            IEnumerable<string> subdirs;
            try
            {
                subdirs = Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string subdir in subdirs)
            {
                ct.ThrowIfCancellationRequested();

                string dirName = Path.GetFileName(subdir);

                foreach (string repoName in SpooferRepoDirNames)
                {
                    if (dirName.Equals(repoName, StringComparison.OrdinalIgnoreCase))
                    {
                        bool hasGit = Directory.Exists(Path.Combine(subdir, ".git"));
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "HWID Spoofer GitHub Repository Clone Detected",
                            Risk     = RiskLevel.Critical,
                            Location = subdir,
                            FileName = dirName,
                            Reason   = $"Directory \"{dirName}\" matches a known HWID spoofer repository name. This indicates the user cloned spoofer source code or a prebuilt spoofer from a public repository.",
                            Detail   = hasGit
                                ? $"Git repo confirmed (.git folder present). Path: {subdir}"
                                : $"Path: {subdir}",
                        });
                        break;
                    }
                }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 11. EFI/BIOS SMBIOS spoofer tool detection
    // =========================================================================
    private async Task ScanEfiBiosSpoofToolsAsync(ScanContext ctx, CancellationToken ct)
    {
        string[] biosSpooferExes =
        [
            "AmideWin64.exe",
            "AmideWin32.exe",
            "Amide.exe",
            "smbios_editor.exe",
            "SMBIOSEditor.exe",
            "bios_spoofer.exe",
            "BiosSpoofer.exe",
            "SMBIOS_Spoofer.exe",
            "SMBIOSSpoofer.exe",
            "BIOSSpoofer.exe",
            "EFISpoofer.exe",
            "efi_spoofer.exe",
            "uefi_spoofer.exe",
            "UEFISpoofer.exe",
            "bios_editor.exe",
            "BIOSEditor.exe",
            "dmidecode.exe",
            "smbios_changer.exe",
            "uuid_changer.exe",
            "UUIDChanger.exe",
        ];

        string[] searchDirs =
        [
            Desktop,
            Downloads,
            Documents,
            TempDir,
            AppDataRoaming,
            AppDataLocal,
        ];

        foreach (string dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();

            if (!Directory.Exists(dir))
                continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (string filePath in files)
            {
                ct.ThrowIfCancellationRequested();

                string fileName = Path.GetFileName(filePath);
                ctx.IncrementFiles();

                try
                {
                    foreach (string biosExe in biosSpooferExes)
                    {
                        if (fileName.Equals(biosExe, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "EFI/BIOS SMBIOS Spoofer Tool Detected",
                                Risk     = RiskLevel.Critical,
                                Location = filePath,
                                FileName = fileName,
                                Reason   = $"\"{fileName}\" is a known EFI/BIOS SMBIOS editor or spoofer tool. These tools modify BIOS SMBIOS tables (serial numbers, UUIDs, manufacturer strings) to change hardware fingerprints that anti-cheat systems read at the firmware level.",
                                Detail   = $"Full path: {filePath}",
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
            }
        }

        await Task.CompletedTask;
    }

    // =========================================================================
    // 12. WMI/SMBIOS spoofing hook detection via registry
    // =========================================================================
    private async Task CheckWmiSpoofingHooksAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // WMI provider registration — spoofers register fake providers that
            // intercept Win32_DiskDrive, Win32_NetworkAdapter, etc. queries
            string wmiProvidersPath = @"SOFTWARE\Microsoft\Wbem\CIMOM";
            ctx.IncrementRegistryKeys();

            try
            {
                using RegistryKey? wmiKey = Registry.LocalMachine.OpenSubKey(wmiProvidersPath, writable: false);
                if (wmiKey is not null)
                {
                    foreach (string valueName in wmiKey.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();

                        object? val = wmiKey.GetValue(valueName);
                        if (val is string strVal)
                        {
                            // Flag any WMI CIMOM value referencing user-writable paths
                            if (IsInSuspiciousUserPath(strVal))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = "WMI CIMOM Value References User-Writable Path",
                                    Risk     = RiskLevel.High,
                                    Location = $@"HKLM\{wmiProvidersPath}",
                                    Reason   = $"WMI CIMOM registry value \"{valueName}\" references a path in a user-writable directory ({strVal}). Spoofers may register fake WMI providers here to intercept hardware query results.",
                                    Detail   = $"ValueName: {valueName} | Value: {strVal}",
                                });
                            }
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }

            // Check for suspicious WMI permanent subscriptions used by spoofers
            string wmiSubscriptionsPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\WbemPerf";
            ctx.IncrementRegistryKeys();
            try
            {
                using RegistryKey? wbemPerfKey = Registry.LocalMachine.OpenSubKey(wmiSubscriptionsPath, writable: false);
                if (wbemPerfKey is not null)
                {
                    string[] subNames = wbemPerfKey.GetSubKeyNames();
                    foreach (string sub in subNames)
                    {
                        ct.ThrowIfCancellationRequested();

                        string lower = sub.ToLowerInvariant();
                        if (lower.Contains("spoof") ||
                            lower.Contains("hwid") ||
                            lower.Contains("serial") ||
                            lower.Contains("changer"))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = "Suspicious WMI Performance Key Detected",
                                Risk     = RiskLevel.High,
                                Location = $@"HKLM\{wmiSubscriptionsPath}\{sub}",
                                Reason   = $"WMI performance subkey \"{sub}\" contains HWID spoofer-related keywords. This may be a WMI hook registration used to intercept hardware ID queries.",
                                Detail   = $"Subkey: {sub}",
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }

            // Check services that claim to be WMI providers but live in temp
            string servicesPath = @"SYSTEM\CurrentControlSet\Services";
            ctx.IncrementRegistryKeys();
            try
            {
                using RegistryKey? services = Registry.LocalMachine.OpenSubKey(servicesPath, writable: false);
                if (services is not null)
                {
                    foreach (string svcName in services.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();

                        try
                        {
                            using RegistryKey? svcKey = services.OpenSubKey(svcName, writable: false);
                            if (svcKey is null) continue;

                            object? imagePathVal = svcKey.GetValue("ImagePath");
                            if (imagePathVal is not string imagePath) continue;

                            if (IsInSuspiciousUserPath(imagePath) &&
                                (imagePath.Contains(".sys", StringComparison.OrdinalIgnoreCase)))
                            {
                                ctx.IncrementRegistryKeys();

                                // Check if this service name looks like a spoofer
                                string lowerSvc = svcName.ToLowerInvariant();
                                if (lowerSvc.Contains("spoof") ||
                                    lowerSvc.Contains("hwid") ||
                                    lowerSvc.Contains("phantom") ||
                                    lowerSvc.Contains("crow") ||
                                    lowerSvc.Contains("ghost") ||
                                    lowerSvc.Contains("stealth") ||
                                    lowerSvc.Contains("shadow"))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module   = Name,
                                        Title    = $"HWID Spoofer Driver Service with Suspicious ImagePath: {svcName}",
                                        Risk     = RiskLevel.Critical,
                                        Location = $@"HKLM\{servicesPath}\{svcName}",
                                        Reason   = $"Service \"{svcName}\" loads a .sys driver from a user-writable path ({imagePath}). This combination is characteristic of a kernel-mode HWID spoofer registering itself as a Windows service.",
                                        Detail   = $"ImagePath = {imagePath}",
                                    });
                                }
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (System.Security.SecurityException) { }
        }, ct);
    }

    // =========================================================================
    // Helpers
    // =========================================================================
    private static bool IsInSuspiciousUserPath(string path)
    {
        if (string.IsNullOrEmpty(path)) return false;

        string[] suspiciousSegments =
        [
            @"\Temp\",
            @"\Downloads\",
            @"\AppData\",
            @"\Desktop\",
            @"/Temp/",
            @"/Downloads/",
        ];

        foreach (string seg in suspiciousSegments)
        {
            if (path.Contains(seg, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }
}
