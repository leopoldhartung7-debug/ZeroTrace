using System.Runtime.Versioning;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class HWIDSpoofingForensicScanModule : IScanModule
{
    public string Name => "HWID Spoofer Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] KnownHWIDSpooferNames =
    [
        "hwid_spoofer", "hwid spoofer", "hwid-spoofer", "hwidspoofer",
        "hwid_changer", "hwid changer", "hwidchanger", "hwid-changer",
        "hwid_reset", "hwid reset", "hwidreset", "hwid-reset",
        "serialchanger", "serial_changer", "serial changer",
        "diskspoofer", "disk_spoofer", "disk spoofer",
        "macspoofer", "mac_spoofer", "mac spoofer", "mac_changer",
        "gpuspoofer", "gpu_spoofer", "gpu spoofer",
        "cpuspoofer", "cpu_spoofer", "cpu spoofer",
        "smbiosspoofer", "smbios_spoofer", "smbios spoofer",
        "volumespoofer", "volume_spoofer",
        "nvmeserial", "nvme_serial", "nvme spoofer",
        "efi_spoofer", "uefi_spoofer", "bios_spoofer",
        "spoofer", "unban", "unban_tool", "unbantool",
        "ban_bypass", "banbypass", "ban bypass",
        "fivem_spoofer", "fivem spoofer", "fivem_unban",
        "ragemp_spoofer", "altv_spoofer",
        "eac_spoofer", "be_spoofer", "vac_spoofer",
        "battleye_spoofer", "easyanticheat_spoofer",
        "tracker_spoofer", "tracking_bypass",
        "ghostsuite", "ghost suite", "ghost_suite",
        "shroud", "shroud_spoofer", "redline_spoofer",
        "unknown_cheats_spoofer", "uc_spoofer",
        "timbuktu", "lavicheats", "unlock_tool",
    ];

    private static readonly string[] HWIDSpoofingRegistryPaths =
    [
        @"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles",
        @"SYSTEM\CurrentControlSet\Services\disk",
        @"SYSTEM\MountedDevices",
        @"SOFTWARE\Microsoft\Cryptography",
        @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        @"SYSTEM\CurrentControlSet\Enum\SCSI",
        @"SYSTEM\CurrentControlSet\Enum\STORAGE",
        @"SYSTEM\CurrentControlSet\Enum\IDE",
        @"SYSTEM\CurrentControlSet\Enum\NVMe",
    ];

    private static readonly string[] SpoofingIndicatorValues =
    [
        "spoofed", "faked", "changed", "modified", "patched",
        "0000000000000000", "1234567890", "AABBCCDDEE", "DEADBEEF",
        "00000000-0000-0000-0000-000000000000",
    ];

    private static readonly string[] KnownSpoofedMachineGuids =
    [
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    ];

    private static readonly string[] HWIDSpoofDriverNames =
    [
        "hwid_drv", "hwiddrv", "spoofer_drv", "spoof_drv",
        "disk_spoof", "disk_change", "smbios_drv",
        "volumeid_changer", "serialchanger", "nvme_patch",
        "efi_patch", "bios_patch", "tpm_bypass",
        "macspoofer", "mac_drv", "guid_changer",
        "traceid_spoof", "telemetry_bypass",
    ];

    private static readonly string[] GenuineWindowsKeys =
    [
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability",
    ];

    private static readonly string[] BiosManipulationPaths =
    [
        @"C:\Windows\System32\drivers\acpi.sys",
        @"C:\Windows\System32\drivers\wdcsam64.sys",
    ];

    private static readonly string[] TelemetryBypassPaths =
    [
        @"SYSTEM\CurrentControlSet\Services\DiagTrack",
        @"SYSTEM\CurrentControlSet\Services\dmwappushservice",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack",
        @"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
    ];

    private static readonly string[] CheatKeywords =
    [
        "spoofer", "hwid", "unban", "ban bypass", "serial", "changer",
        "fivem", "ragemp", "altv", "battleye", "easyanticheat", "vac",
        "hardware", "identifier", "machine", "fingerprint",
    ];

    private static readonly string[] SuspiciousDeviceSerials =
    [
        "0000000000", "1111111111", "AAAAAAAA", "FAKEHWID",
        "SPOOFED", "CHANGED", "MODIFIED",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckHWIDSpooferToolArtifacts(ctx, ct),
            CheckHWIDSpooferRegistryArtifacts(ctx, ct),
            CheckMachineGUIDIntegrity(ctx, ct),
            CheckHWIDSpooferDriverArtifacts(ctx, ct),
            CheckHWIDSpooferPrefetchArtifacts(ctx, ct),
            CheckSMBIOSSpoofingArtifacts(ctx, ct),
            CheckDiskSerialSpoofingArtifacts(ctx, ct),
            CheckMACAddressSpoofingArtifacts(ctx, ct),
            CheckTPMSpoofingArtifacts(ctx, ct),
            CheckVolumeIDChangerArtifacts(ctx, ct),
            CheckTelemetryBypassArtifacts(ctx, ct),
            CheckHWIDSpooferDownloadArtifacts(ctx, ct),
            CheckUnbanToolArtifacts(ctx, ct),
            CheckNetworkAdapterMACSpoof(ctx, ct),
            CheckEFIUEFISpoofingArtifacts(ctx, ct),
            CheckHWIDSpooferMUICache(ctx, ct),
            CheckHWIDResetServiceArtifacts(ctx, ct),
            CheckHWIDSpoofingLogs(ctx, ct)
        );
    }

    private Task CheckHWIDSpooferToolArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var searchPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
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

                    foreach (var spooferName in KnownHWIDSpooferNames)
                    {
                        if (name.Contains(spooferName.Replace(" ", "").Replace("-", "").Replace("_", ""), StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "HWID Spoofer: Tool File Artifact",
                                Risk = RiskLevel.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Known HWID spoofer tool '{spooferName}' found — used to evade hardware bans",
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

    private Task CheckHWIDSpooferRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hkcu = Registry.CurrentUser;
        using var hklm = Registry.LocalMachine;

        var spooferRegPaths = new[]
        {
            @"SOFTWARE\HWIDSpoofer",
            @"SOFTWARE\HWID",
            @"SOFTWARE\Spoofer",
            @"SOFTWARE\GhostSuite",
            @"SOFTWARE\UnbanTool",
            @"SOFTWARE\HardwareSpoofer",
            @"SOFTWARE\SerialChanger",
            @"SOFTWARE\DiskSpoofer",
        };

        foreach (var regPath in spooferRegPaths)
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
                        Module = Name, Title = "HWID Spoofer Registry: Tool Registry Artifact",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKCU\{regPath}",
                        FileName = regPath.Split('\\').Last(),
                        Reason = $"HWID spoofer registry key '{regPath}' found — spoofer was installed or run",
                        Detail = $"Keys: {string.Join(", ", key.GetValueNames().Take(5))}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckMachineGUIDIntegrity(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var machineGuidPath = @"SOFTWARE\Microsoft\Cryptography";

        try
        {
            using var key = hklm.OpenSubKey(machineGuidPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            var machineGuid = key.GetValue("MachineGuid")?.ToString() ?? string.Empty;

            if (string.IsNullOrEmpty(machineGuid))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "MachineGuid: Missing — Possible Spoof",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{machineGuidPath}",
                    FileName = "MachineGuid",
                    Reason = "Windows MachineGuid is missing — may have been deleted by HWID spoofer",
                    Detail = "MachineGuid should always be present on genuine Windows installations"
                });
            }
            else
            {
                foreach (var spoofedGuid in KnownSpoofedMachineGuids)
                {
                    if (machineGuid.Equals(spoofedGuid, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "MachineGuid: Known Spoofed Value",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{machineGuidPath}",
                            FileName = "MachineGuid",
                            Reason = $"MachineGuid has known spoofed value '{machineGuid}' — HWID spoofer set a fake GUID",
                            Detail = $"MachineGuid: {machineGuid}"
                        });
                        break;
                    }
                }

                foreach (var indicator in SpoofingIndicatorValues)
                {
                    if (machineGuid.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "MachineGuid: Spoofing Indicator Pattern",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{machineGuidPath}",
                            FileName = "MachineGuid",
                            Reason = $"MachineGuid contains spoofing indicator pattern '{indicator}'",
                            Detail = $"MachineGuid: {machineGuid}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }

        var installationIdPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        try
        {
            using var key = hklm.OpenSubKey(installationIdPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            var installDate = key.GetValue("InstallDate")?.ToString() ?? string.Empty;
            var digitalProductId = key.GetValue("DigitalProductId");
            var buildGuid = key.GetValue("BuildGUID")?.ToString() ?? string.Empty;

            if (string.IsNullOrEmpty(installDate))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "Windows Installation: Missing Install Date",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{installationIdPath}",
                    FileName = "InstallDate",
                    Reason = "Windows installation date is missing — may have been wiped by HWID spoofer",
                    Detail = "Genuine Windows always has an InstallDate"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckHWIDSpooferDriverArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var servicesPath = @"SYSTEM\CurrentControlSet\Services";

        try
        {
            using var servicesKey = hklm.OpenSubKey(servicesPath);
            if (servicesKey == null) return;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                foreach (var driverName in HWIDSpoofDriverNames)
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
                                Module = Name, Title = "HWID Spoofer Driver: Spoofer Service Installed",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{servicesPath}\{svcName}",
                                FileName = svcName,
                                Reason = $"Known HWID spoofer driver service '{svcName}' in registry — kernel-level hardware ID spoofing",
                                Detail = $"ImagePath: {imagePath}"
                            });
                        }
                        catch { }
                        break;
                    }
                }
            }
        }
        catch { }

        var driverPaths = new[]
        {
            @"C:\Windows\System32\drivers",
            @"C:\Windows\SysWOW64\drivers",
        };

        foreach (var driverDir in driverPaths)
        {
            if (!Directory.Exists(driverDir)) continue;
            try
            {
                foreach (var sysFile in Directory.EnumerateFiles(driverDir, "*.sys"))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var sysName = Path.GetFileNameWithoutExtension(sysFile).ToLowerInvariant();
                    foreach (var driverName in HWIDSpoofDriverNames)
                    {
                        if (sysName.Equals(driverName, StringComparison.OrdinalIgnoreCase) ||
                            sysName.Contains(driverName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "HWID Spoofer Driver: Driver File in System Drivers",
                                Risk = RiskLevel.Critical, Location = sysFile,
                                FileName = Path.GetFileName(sysFile),
                                Reason = $"HWID spoofer driver file '{sysName}.sys' in System32/drivers — active hardware ID spoofing",
                                Detail = $"Path: {sysFile}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckHWIDSpooferPrefetchArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                foreach (var spooferName in KnownHWIDSpooferNames)
                {
                    var sanitized = spooferName.Replace(" ", "").Replace("-", "").Replace("_", "");
                    if (pfName.Contains(sanitized, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Prefetch: HWID Spoofer Execution Confirmed",
                            Risk = RiskLevel.Critical, Location = pf,
                            FileName = Path.GetFileName(pf),
                            Reason = $"HWID spoofer '{spooferName}' prefetch entry — confirms spoofer was executed on this system",
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

    private Task CheckSMBIOSSpoofingArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var smbiosPaths = new[]
        {
            @"SYSTEM\CurrentControlSet\Services\mssmbios\Data",
            @"HARDWARE\DESCRIPTION\System\BIOS",
        };

        foreach (var smbiosPath in smbiosPaths)
        {
            try
            {
                using var key = hklm.OpenSubKey(smbiosPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();

                var manufacturer = key.GetValue("SystemManufacturer")?.ToString() ?? string.Empty;
                var productName = key.GetValue("SystemProductName")?.ToString() ?? string.Empty;
                var biosVersion = key.GetValue("BIOSVersion")?.ToString() ?? string.Empty;
                var serialNumber = key.GetValue("SystemSerialNumber")?.ToString() ?? string.Empty;

                foreach (var indicator in SpoofingIndicatorValues)
                {
                    if (serialNumber.Contains(indicator, StringComparison.OrdinalIgnoreCase) ||
                        manufacturer.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "SMBIOS: Spoofing Indicator in System Info",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{smbiosPath}",
                            FileName = "SMBIOS",
                            Reason = $"SMBIOS data contains spoofing indicator '{indicator}' — hardware BIOS data was spoofed",
                            Detail = $"Manufacturer: {manufacturer}, Product: {productName}, Serial: {serialNumber}"
                        });
                        break;
                    }
                }

                if (string.IsNullOrEmpty(serialNumber) || serialNumber == "To Be Filled By O.E.M." ||
                    serialNumber == "0123456789")
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "SMBIOS: Missing or Placeholder Serial Number",
                        Risk = RiskLevel.Medium,
                        Location = $@"HKLM\{smbiosPath}",
                        FileName = "SystemSerialNumber",
                        Reason = $"System serial number is missing/placeholder ('{serialNumber}') — possible SMBIOS spoof",
                        Detail = $"Serial: '{serialNumber}'"
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckDiskSerialSpoofingArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var diskEnumPaths = new[]
        {
            @"SYSTEM\CurrentControlSet\Enum\SCSI",
            @"SYSTEM\CurrentControlSet\Enum\IDE",
            @"SYSTEM\CurrentControlSet\Enum\NVMe",
            @"SYSTEM\CurrentControlSet\Enum\STORAGE",
        };

        foreach (var diskPath in diskEnumPaths)
        {
            try
            {
                using var key = hklm.OpenSubKey(diskPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var controllerName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var controllerKey = key.OpenSubKey(controllerName);
                        if (controllerKey == null) continue;
                        foreach (var instanceId in controllerKey.GetSubKeyNames())
                        {
                            foreach (var suspectedSerial in SuspiciousDeviceSerials)
                            {
                                if (instanceId.Contains(suspectedSerial, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name, Title = "Disk Serial: Suspicious Serial Number in Enum",
                                        Risk = RiskLevel.High,
                                        Location = $@"HKLM\{diskPath}\{controllerName}\{instanceId}",
                                        FileName = controllerName,
                                        Reason = $"Disk device with suspicious serial pattern '{suspectedSerial}' — possible disk serial spoof",
                                        Detail = $"Instance: {instanceId}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckMACAddressSpoofingArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var networkAdaptersPath = @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}";

        try
        {
            using var adaptersKey = hklm.OpenSubKey(networkAdaptersPath);
            if (adaptersKey == null) return;
            ctx.IncrementRegistryKeys();

            foreach (var adapterNum in adaptersKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var adapterKey = adaptersKey.OpenSubKey(adapterNum);
                    if (adapterKey == null) continue;

                    var networkAddress = adapterKey.GetValue("NetworkAddress")?.ToString() ?? string.Empty;
                    var permanentAddress = adapterKey.GetValue("PermanentAddress")?.ToString() ?? string.Empty;
                    var adapterDesc = adapterKey.GetValue("DriverDesc")?.ToString() ?? string.Empty;

                    if (!string.IsNullOrEmpty(networkAddress) &&
                        !networkAddress.Equals(permanentAddress, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "MAC Address Spoof: NetworkAddress Differs from Permanent",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{networkAdaptersPath}\{adapterNum}",
                            FileName = adapterDesc,
                            Reason = "NetworkAddress (spoofed) differs from PermanentAddress (real) — MAC address is being spoofed",
                            Detail = $"Adapter: {adapterDesc}, NetworkAddress: {networkAddress}, Permanent: {permanentAddress}"
                        });
                    }

                    foreach (var indicator in SpoofingIndicatorValues)
                    {
                        if (!string.IsNullOrEmpty(networkAddress) &&
                            networkAddress.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "MAC Address: Known Spoofed Pattern",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{networkAdaptersPath}\{adapterNum}",
                                FileName = adapterDesc,
                                Reason = $"MAC address contains spoofing pattern '{indicator}' — fake MAC address set",
                                Detail = $"Adapter: {adapterDesc}, MAC: {networkAddress}"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }, ct);

    private Task CheckTPMSpoofingArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var tpmRegPath = @"SYSTEM\CurrentControlSet\Services\TPM";
        var tpmStatusPath = @"SOFTWARE\Microsoft\TPM";

        try
        {
            using var key = hklm.OpenSubKey(tpmRegPath);
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                var startType = key.GetValue("Start")?.ToString();
                if (startType == "4")
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "TPM Service: Disabled",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{tpmRegPath}",
                        FileName = "TPM",
                        Reason = "TPM service is disabled — may be part of HWID/TPM spoofing to bypass hardware fingerprinting",
                        Detail = $"Start type: {startType} (4 = Disabled)"
                    });
                }
            }
        }
        catch { }

        try
        {
            using var key = hklm.OpenSubKey(tpmStatusPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            var tpmPresent = key.GetValue("IsPresent")?.ToString();
            var tpmEnabled = key.GetValue("IsEnabled")?.ToString();
            var tpmReady = key.GetValue("IsReady")?.ToString();

            if (tpmPresent == "0" && tpmEnabled == "1")
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "TPM Status: Inconsistent State (Spoof Indicator)",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{tpmStatusPath}",
                    FileName = "TPM",
                    Reason = "TPM reports as present=0 but enabled=1 — inconsistent state may indicate TPM spoofing",
                    Detail = $"IsPresent: {tpmPresent}, IsEnabled: {tpmEnabled}, IsReady: {tpmReady}"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckVolumeIDChangerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var mountedDevicesPath = @"SYSTEM\MountedDevices";
        var volumeGuidPath = @"SYSTEM\CurrentControlSet\Enum\STORAGE\Volume";

        try
        {
            using var key = hklm.OpenSubKey(mountedDevicesPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            var valueNames = key.GetValueNames();
            var guidPattern = valueNames.Where(v => v.StartsWith(@"\??\Volume{", StringComparison.OrdinalIgnoreCase)).ToList();

            foreach (var guidVal in guidPattern)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var indicator in SpoofingIndicatorValues)
                {
                    if (guidVal.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Volume GUID: Spoofing Indicator Pattern",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{mountedDevicesPath}",
                            FileName = guidVal,
                            Reason = $"Volume GUID contains spoofing indicator '{indicator}' — volume ID may have been changed",
                            Detail = $"Value: {guidVal}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckTelemetryBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;

        foreach (var telemetryPath in TelemetryBypassPaths)
        {
            try
            {
                using var key = hklm.OpenSubKey(telemetryPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();

                if (telemetryPath.Contains("DiagTrack"))
                {
                    var start = key.GetValue("Start")?.ToString();
                    if (start == "4")
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "DiagTrack: Windows Telemetry Service Disabled",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKLM\{telemetryPath}",
                            FileName = "DiagTrack",
                            Reason = "Windows telemetry/diagnostic tracking service disabled — prevents AC telemetry reporting",
                            Detail = $"Start type: {start}"
                        });
                    }
                }

                if (telemetryPath.Contains("DataCollection"))
                {
                    var allowTelemetry = key.GetValue("AllowTelemetry")?.ToString();
                    if (allowTelemetry == "0")
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Data Collection Policy: Telemetry Blocked via Policy",
                            Risk = RiskLevel.Medium,
                            Location = $@"HKLM\{telemetryPath}",
                            FileName = "AllowTelemetry",
                            Reason = "Windows telemetry blocked via Group Policy — may prevent AC from reporting hardware fingerprints",
                            Detail = $"AllowTelemetry: {allowTelemetry}"
                        });
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckHWIDSpooferDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchPaths = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
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
                    var name = Path.GetFileName(file).ToLowerInvariant();
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    if (ext is ".zip" or ".rar" or ".7z" or ".exe")
                    {
                        foreach (var spooferName in KnownHWIDSpooferNames)
                        {
                            var sanitized = spooferName.Replace(" ", "").Replace("-", "").Replace("_", "");
                            if (name.Contains(sanitized, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Download: HWID Spoofer Package",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"HWID spoofer package '{spooferName}' in downloads/desktop",
                                    Detail = $"Path: {file}"
                                });
                                break;
                            }
                        }
                    }

                    if (ext is ".txt" or ".json" or ".xml" or ".cfg" or ".ini" or ".key")
                    {
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            var content = await sr.ReadToEndAsync(ct);
                            bool hasHwidKw = CheatKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                            bool hasSpooferKw = new[] { "hwid", "spoof", "serial", "unban", "machine id", "hardware id" }
                                .Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (hasHwidKw && hasSpooferKw)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "File: HWID Spoofer Configuration/License",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = "File contains HWID spoofer configuration or license data",
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

    private Task CheckUnbanToolArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (var uninstallPath in uninstallPaths)
        {
            try
            {
                using var key = hklm.OpenSubKey(uninstallPath);
                if (key == null) continue;
                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var appKey = key.OpenSubKey(subKeyName);
                        if (appKey == null) continue;
                        ctx.IncrementRegistryKeys();
                        var displayName = appKey.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        foreach (var spooferName in KnownHWIDSpooferNames)
                        {
                            var sanitized = spooferName.Replace(" ", "").Replace("-", "");
                            if (displayName.Contains(sanitized, StringComparison.OrdinalIgnoreCase) ||
                                displayName.Contains(spooferName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Uninstall Registry: HWID Spoofer Was Installed",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                    FileName = displayName,
                                    Reason = $"HWID spoofer '{displayName}' found in Add/Remove Programs — was installed on this system",
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
    }, ct);

    private Task CheckNetworkAdapterMACSpoof(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var adapterPath = @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}";

        try
        {
            using var adapterRoot = hklm.OpenSubKey(adapterPath);
            if (adapterRoot == null) return;
            ctx.IncrementRegistryKeys();

            foreach (var adapterNum in adapterRoot.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var adapterKey = adapterRoot.OpenSubKey(adapterNum);
                    if (adapterKey == null) continue;
                    var networkAddress = adapterKey.GetValue("NetworkAddress")?.ToString() ?? string.Empty;
                    var driverDesc = adapterKey.GetValue("DriverDesc")?.ToString() ?? string.Empty;

                    if (!string.IsNullOrEmpty(networkAddress) && networkAddress.Length == 12)
                    {
                        var prefix = networkAddress[..6].ToUpperInvariant();
                        var knownSpoofPrefixes = new[] { "000000", "AABBCC", "DEADBE", "CAFE00", "123456" };
                        foreach (var spoof in knownSpoofPrefixes)
                        {
                            if (prefix.StartsWith(spoof, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "MAC Address: Suspicious OUI Prefix",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKLM\{adapterPath}\{adapterNum}",
                                    FileName = driverDesc,
                                    Reason = $"Network adapter MAC prefix '{prefix}' is a known spoofing OUI pattern",
                                    Detail = $"Adapter: {driverDesc}, MAC: {networkAddress}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }, ct);

    private Task CheckEFIUEFISpoofingArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var efisPath = @"SYSTEM\CurrentControlSet\Control\EFI";
        var uefiBootPath = @"SYSTEM\CurrentControlSet\Control\SecureBoot\State";

        try
        {
            using var secureBootKey = hklm.OpenSubKey(uefiBootPath);
            if (secureBootKey != null)
            {
                ctx.IncrementRegistryKeys();
                var uefiSecureBootEnabled = secureBootKey.GetValue("UEFISecureBootEnabled")?.ToString();
                if (uefiSecureBootEnabled == "0")
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "UEFI Secure Boot: Disabled",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{uefiBootPath}",
                        FileName = "UEFISecureBootEnabled",
                        Reason = "UEFI Secure Boot is disabled — required for some HWID spoofer and driver bypass techniques",
                        Detail = $"UEFISecureBootEnabled: {uefiSecureBootEnabled}"
                    });
                }
            }
        }
        catch { }

        var testSigningPath = @"SYSTEM\CurrentControlSet\Control\CI\Policy";
        try
        {
            using var tsKey = hklm.OpenSubKey(testSigningPath);
            if (tsKey == null) return;
            ctx.IncrementRegistryKeys();
            var policyOptions = tsKey.GetValue("PolyicyOptions")?.ToString() ??
                                tsKey.GetValue("PolicyOptions")?.ToString() ?? string.Empty;
            if (!string.IsNullOrEmpty(policyOptions))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "CI Policy: Custom Code Integrity Policy Set",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{testSigningPath}",
                    FileName = "PolicyOptions",
                    Reason = "Custom CI policy active — may enable unsigned/spoofed drivers for HWID manipulation",
                    Detail = $"Options: {policyOptions}"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckHWIDSpooferMUICache(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                foreach (var spooferName in KnownHWIDSpooferNames)
                {
                    var sanitized = spooferName.Replace(" ", "").Replace("-", "").Replace("_", "");
                    if (valueName.Contains(sanitized, StringComparison.OrdinalIgnoreCase) ||
                        valueName.Contains(spooferName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "MUICache: HWID Spoofer Execution History",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\{muiCachePath}",
                            FileName = Path.GetFileName(valueName.Split('.')[0]),
                            Reason = $"HWID spoofer '{spooferName}' in MUICache — confirms spoofer was executed",
                            Detail = $"Key: {valueName}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckHWIDResetServiceArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hklm = Registry.LocalMachine;
        var servicesPath = @"SYSTEM\CurrentControlSet\Services";
        var spooferServiceKeywords = new[]
        {
            "hwidspoof", "hwid_spoof", "serialspoof", "macspoof",
            "guidchanger", "guid_change", "smbiosspoof", "smbios_spoof",
            "diskspoof", "disk_spoof", "volumeid", "volumechange",
            "tpmbypass", "tpm_bypass", "secureboot_bypass",
            "unban", "hwidchanger", "hwid_changer",
        };

        try
        {
            using var servicesKey = hklm.OpenSubKey(servicesPath);
            if (servicesKey == null) return;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                var svcLower = svcName.ToLowerInvariant();
                foreach (var kw in spooferServiceKeywords)
                {
                    if (svcLower.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "HWID Spoofer Service: Persistent Spoof Service",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\{servicesPath}\{svcName}",
                            FileName = svcName,
                            Reason = $"HWID spoofer service '{svcName}' registered — persistent hardware ID spoofing service",
                            Detail = $"Service: {svcName}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckHWIDSpoofingLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var logSearchPaths = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.Combine(userProfile, "Documents"),
            Path.GetTempPath(),
        };

        var hwidLogKeywords = new[]
        {
            "hwid spoofed", "serial changed", "mac changed", "mac spoofed",
            "smbios spoofed", "guid changed", "disk serial", "volume id changed",
            "spoofing complete", "spoof success", "hardware id changed",
            "ban evaded", "unban success",
        };

        foreach (var root in logSearchPaths)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.log", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.EnumerateFiles(root, "*.txt", SearchOption.TopDirectoryOnly)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        foreach (var kw in hwidLogKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "HWID Spoofer Log: Spoofing Operation Logged",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"HWID spoofer log keyword '{kw}' — confirms hardware ID spoofing was performed",
                                    Detail = content.Length > 500 ? content[..500] : content
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
}
