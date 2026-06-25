using Microsoft.Win32;
using System.Text.RegularExpressions;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

// Detects HWID spoofer artifacts exclusively through registry inspection.
// Complements HwidSpooferScanModule (which focuses on files and processes) and
// HwidSpoofDeepScanModule by concentrating on registry residue left by spoofer
// tools: modified disk serials, spoofed MAC addresses, tampered SMBIOS/BIOS
// data, GPU driver modifications, USB serial nullification, volume shadow
// service disablement, and computer-name randomisation.
public sealed class HwidSpooferRegistryScanModule : IScanModule
{
    public string Name => "HWID Spoofer Registry Artifact Detection";
    public double Weight => 4.4;
    public int ParallelGroup => 4;

    // Well-known NIC class GUID for network adapters
    private const string NicClassGuid = @"{4d36e972-e325-11ce-bfc1-08002be10318}";
    // Well-known display adapter class GUID
    private const string GpuClassGuid = @"{4d36e968-e325-11ce-bfc1-08002be10318}";

    // BIOS vendor/version strings that indicate QEMU, VirtualBox, VMware injection or
    // placeholder values left by spoofer tools when they blank out the real strings.
    private static readonly string[] SuspiciousBiosStrings =
    {
        "qemu", "virtualbox", "vmware", "bochs", "xen", "hyper-v",
        "aaaa", "bbbb", "cccc", "1111", "2222", "3333", "0000",
        "unknown", "to be filled", "to be determined", "not specified",
        "default string", "o.e.m.", "base board", "system product",
        "system manufacturer", "chassis manufacturer", "chassis serial",
        "board manufacturer", "board product", "board serial",
        "serial number", "none", "n/a", "empty", "placeholder",
    };

    // CPU name strings substituted by CPU-ID spoofers.
    private static readonly string[] FakeCpuNames =
    {
        "generic cpu", "cpu 0", "processor 0", "unknown processor",
        "virtual cpu", "qemu virtual cpu", "common kvm processor",
        "genuine intel 0000", "authenticamd 0000",
    };

    // Regex: eight contiguous hex characters — pattern spoofers use for generated
    // computer names (e.g. "A3F19C02").
    private static readonly Regex HexComputerNameRegex =
        new(@"^[0-9A-Fa-f]{8}$", RegexOptions.Compiled);

    // Regex: detects hex-format values that look randomly generated — 16+ hex chars
    // with no repeating pattern, used to detect spoofed disk identifiers.
    private static readonly Regex RandomHexRegex =
        new(@"^[0-9A-Fa-f]{16,}$", RegexOptions.Compiled);

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.00, Name, "Checking disk serial spoofing artifacts...");
        await Task.Run(() => CheckDiskSerialSpoofing(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.15, Name, "Checking IDE controller serial entries...");
        await Task.Run(() => CheckIdeControllerSerials(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.25, Name, "Checking volume serial artifacts...");
        await Task.Run(() => CheckVolumeSerialArtifacts(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.33, Name, "Checking NIC/MAC address spoofing registry...");
        await Task.Run(() => CheckNicMacSpoofing(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.46, Name, "Checking SMBIOS/Motherboard spoofing registry...");
        await Task.Run(() => CheckSmbiosSpoofing(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.55, Name, "Checking BIOS registry values...");
        await Task.Run(() => CheckBiosRegistryValues(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.63, Name, "Checking CPU identifier spoofing...");
        await Task.Run(() => CheckCpuIdentifierSpoofing(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.70, Name, "Checking Volume Shadow Copy service state...");
        await Task.Run(() => CheckVssSpoofDisablement(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.77, Name, "Checking computer name randomization...");
        await Task.Run(() => CheckComputerNameRandomization(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.84, Name, "Checking GPU driver spoofing registry...");
        await Task.Run(() => CheckGpuDriverSpoofing(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.91, Name, "Checking USB device descriptor spoofing...");
        await Task.Run(() => CheckUsbDeviceDescriptors(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.96, Name, "Checking disk write-protect flags...");
        await Task.Run(() => CheckDiskWriteProtectFlags(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(1.00, Name, "HWID spoofer registry scan complete.");
    }

    // Checks HKLM\SYSTEM\CurrentControlSet\Services\disk\Parameters\StorageDevicePolicies
    // for write-protect flags that spoofer tools set to protect their modifications.
    private void CheckDiskWriteProtectFlags(ScanContext ctx, CancellationToken ct)
    {
        const string keyPath = @"SYSTEM\CurrentControlSet\Services\disk\Parameters\StorageDevicePolicies";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
            if (key is null) return;
            ctx.IncrementRegistryKeys();

            var writeProtect = key.GetValue("WriteProtect");
            if (writeProtect is int wpInt && wpInt != 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Disk write-protect flag enabled (spoofer artifact)",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{keyPath}\WriteProtect",
                    Reason   = "The WriteProtect value under StorageDevicePolicies is set to a non-zero " +
                               "value. HWID spoofer tools enable this flag to prevent the operating " +
                               "system from overwriting the modified disk serial numbers they inject. " +
                               "This flag is not set by any standard Windows component or legitimate " +
                               "application on consumer hardware.",
                    Detail   = $"WriteProtect = {wpInt}"
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // Scans HKLM\HARDWARE\DEVICEMAP\Scsi subtree for disk Identifier values that
    // look randomly generated (16+ uniform hex chars) — a pattern left by spoofers.
    private void CheckDiskSerialSpoofing(ScanContext ctx, CancellationToken ct)
    {
        const string scsiBase = @"HARDWARE\DEVICEMAP\Scsi";
        try
        {
            using var scsiKey = Registry.LocalMachine.OpenSubKey(scsiBase, writable: false);
            if (scsiKey is null) return;

            foreach (var portName in scsiKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var portKey = scsiKey.OpenSubKey(portName, writable: false);
                    if (portKey is null) continue;

                    foreach (var busName in portKey.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        try
                        {
                            using var busKey = portKey.OpenSubKey(busName, writable: false);
                            if (busKey is null) continue;

                            foreach (var targetName in busKey.GetSubKeyNames())
                            {
                                if (ct.IsCancellationRequested) return;
                                try
                                {
                                    using var targetKey = busKey.OpenSubKey(targetName, writable: false);
                                    if (targetKey is null) continue;

                                    foreach (var lunName in targetKey.GetSubKeyNames())
                                    {
                                        if (ct.IsCancellationRequested) return;
                                        ctx.IncrementRegistryKeys();
                                        try
                                        {
                                            using var lunKey = targetKey.OpenSubKey(lunName, writable: false);
                                            if (lunKey is null) continue;

                                            var identifier = lunKey.GetValue("Identifier") as string;
                                            if (string.IsNullOrWhiteSpace(identifier)) continue;

                                            var identifierClean = identifier.Replace(" ", "").Trim();
                                            InspectScsiIdentifier(ctx, identifier, identifierClean,
                                                $@"HKLM\{scsiBase}\{portName}\{busName}\{targetName}\{lunName}");
                                        }
                                        catch (UnauthorizedAccessException) { }
                                        catch { }
                                    }
                                }
                                catch (UnauthorizedAccessException) { }
                                catch { }
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                        catch { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    private void InspectScsiIdentifier(ScanContext ctx, string identifier, string clean, string location)
    {
        // All-zero serial — spoofer blanked it
        if (clean.Replace("0", "").Length == 0 && clean.Length >= 8)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "SCSI disk Identifier zeroed (spoofer artifact)",
                Risk     = RiskLevel.High,
                Location = location,
                Reason   = "The disk Identifier value in the SCSI device map registry path contains " +
                           "only zeros. HWID spoofers null out or replace genuine disk serial numbers " +
                           "to prevent anti-cheat systems from reading the real hardware fingerprint.",
                Detail   = $"Identifier = \"{identifier}\""
            });
            return;
        }

        // Repeating-pattern serial (e.g. all same character) — placeholder
        if (clean.Length >= 8 && clean.Distinct().Count() <= 2)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "SCSI disk Identifier has repeating placeholder pattern",
                Risk     = RiskLevel.Medium,
                Location = location,
                Reason   = "The disk Identifier value consists of at most two distinct characters in " +
                           "a repeating pattern. This is characteristic of placeholder values injected " +
                           "by HWID spoofer tools to replace the factory-assigned disk serial number.",
                Detail   = $"Identifier = \"{identifier}\""
            });
            return;
        }

        // Pure random hex without any manufacturer prefix — generated serial
        if (RandomHexRegex.IsMatch(clean) && clean.Length >= 20)
        {
            // Legitimate disk serials in this registry path are typically mixed
            // alphanumeric or contain spaces (model + serial). A pure hex string
            // of 20+ chars with no spaces strongly suggests a generated replacement.
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "SCSI disk Identifier appears randomly generated",
                Risk     = RiskLevel.Medium,
                Location = location,
                Reason   = "The disk Identifier value is a long contiguous hexadecimal string with no " +
                           "manufacturer-format spacing. Spoofer tools often substitute real disk " +
                           "serials with randomly generated hex strings to break hardware fingerprinting.",
                Detail   = $"Identifier = \"{identifier}\""
            });
        }
    }

    // Checks HKLM\SYSTEM\CurrentControlSet\Enum\IDE for spoofed serial numbers
    // on IDE/ATA controllers enumerated by Windows PnP.
    private void CheckIdeControllerSerials(ScanContext ctx, CancellationToken ct)
    {
        const string ideBase = @"SYSTEM\CurrentControlSet\Enum\IDE";
        try
        {
            using var ideKey = Registry.LocalMachine.OpenSubKey(ideBase, writable: false);
            if (ideKey is null) return;

            foreach (var deviceId in ideKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var deviceKey = ideKey.OpenSubKey(deviceId, writable: false);
                    if (deviceKey is null) continue;

                    foreach (var instanceId in deviceKey.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();
                        try
                        {
                            using var instanceKey = deviceKey.OpenSubKey(instanceId, writable: false);
                            if (instanceKey is null) continue;

                            var friendlyName = instanceKey.GetValue("FriendlyName") as string ?? "";
                            var deviceDesc   = instanceKey.GetValue("DeviceDesc") as string ?? "";

                            // The instance ID in IDE\<DeviceId>\<InstanceId> often encodes the serial.
                            // Spoofers substitute the real serial with all-zero strings.
                            var cleanId = instanceId.Replace("&", "").Replace("_", "").Trim();
                            if (cleanId.Replace("0", "").Length == 0 && cleanId.Length >= 8)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"IDE device instance ID is all zeros: {deviceDesc}",
                                    Risk     = RiskLevel.High,
                                    Location = $@"HKLM\{ideBase}\{deviceId}\{instanceId}",
                                    FileName = friendlyName,
                                    Reason   = "The IDE device instance ID contains only zeros. Windows " +
                                               "PnP normally encodes the real disk serial number into " +
                                               "this path. Zeroed instance IDs are a signature of HWID " +
                                               "spoofer tools that patch the disk serial number in the " +
                                               "device enumeration database.",
                                    Detail   = $"DeviceDesc: {deviceDesc} | FriendlyName: {friendlyName} | InstanceId: {instanceId}"
                                });
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                        catch { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // Checks HKLM\SYSTEM\CurrentControlSet\Enum\STORAGE\Volume for volume serial
    // number artifacts — spoofers modify these to change the volume fingerprint.
    private void CheckVolumeSerialArtifacts(ScanContext ctx, CancellationToken ct)
    {
        const string volBase = @"SYSTEM\CurrentControlSet\Enum\STORAGE\Volume";
        try
        {
            using var volKey = Registry.LocalMachine.OpenSubKey(volBase, writable: false);
            if (volKey is null) return;

            int count = 0;
            foreach (var instanceId in volKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                if (++count > 200) break;
                ctx.IncrementRegistryKeys();
                try
                {
                    using var instanceKey = volKey.OpenSubKey(instanceId, writable: false);
                    if (instanceKey is null) continue;

                    var deviceDesc = instanceKey.GetValue("DeviceDesc") as string ?? "";
                    var friendlyName = instanceKey.GetValue("FriendlyName") as string ?? "";

                    // Look for instance IDs that contain "VolumeId" with all-zero GUIDs
                    // e.g. {00000000-0000-0000-0000-000000000000}
                    if (instanceId.Contains("{00000000-0000-0000-0000-000000000000}",
                        StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Volume storage entry has null GUID (spoofer artifact)",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{volBase}\{instanceId}",
                            FileName = friendlyName,
                            Reason   = "A volume entry in the storage enumeration database has a " +
                                       "null GUID (all zeros). This pattern is left by HWID spoofer " +
                                       "tools that zero out or replace volume serial numbers to " +
                                       "prevent hardware fingerprinting through volume identifiers.",
                            Detail   = $"InstanceId: {instanceId} | DeviceDesc: {deviceDesc}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // Scans all subkeys of the NIC class GUID for NetworkAddress values (custom MAC)
    // and OriginalNetworkAddress values (original MAC saved before spoofing).
    private void CheckNicMacSpoofing(ScanContext ctx, CancellationToken ct)
    {
        var nicClassPath = $@"SYSTEM\CurrentControlSet\Control\Class\{NicClassGuid}";
        try
        {
            using var classKey = Registry.LocalMachine.OpenSubKey(nicClassPath, writable: false);
            if (classKey is null) return;

            foreach (var subkeyName in classKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();
                try
                {
                    using var adapterKey = classKey.OpenSubKey(subkeyName, writable: false);
                    if (adapterKey is null) continue;

                    var networkAddress    = adapterKey.GetValue("NetworkAddress") as string;
                    var originalAddress   = adapterKey.GetValue("OriginalNetworkAddress") as string;
                    var driverDesc        = adapterKey.GetValue("DriverDesc") as string ?? subkeyName;

                    if (!string.IsNullOrWhiteSpace(networkAddress))
                    {
                        var macClean = networkAddress.Replace("-", "").Replace(":", "")
                            .Replace(" ", "").ToUpperInvariant();

                        var isSpoofed = IsSuspiciousMac(macClean);
                        var riskLevel = isSpoofed ? RiskLevel.Critical : RiskLevel.High;
                        var spoofNote = isSpoofed
                            ? " The MAC address pattern (repeating octets or uniform nibbles) strongly " +
                              "indicates a spoofer-generated value."
                            : " Any custom NetworkAddress overrides the burned-in hardware MAC address.";

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Custom MAC address set via registry: {driverDesc}",
                            Risk     = riskLevel,
                            Location = $@"HKLM\{nicClassPath}\{subkeyName}\NetworkAddress",
                            Reason   = $"The NetworkAddress registry value on adapter '{driverDesc}' " +
                                       "overrides the hardware-burned MAC address with a custom value. " +
                                       "This is the primary registry mechanism used by MAC-address " +
                                       "spoofer tools and ban-evasion utilities." + spoofNote,
                            Detail   = $"NetworkAddress = {networkAddress} | Adapter = {driverDesc}"
                        });
                    }

                    if (!string.IsNullOrWhiteSpace(originalAddress))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"OriginalNetworkAddress present — MAC was spoofed: {driverDesc}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{nicClassPath}\{subkeyName}\OriginalNetworkAddress",
                            Reason   = "The OriginalNetworkAddress registry value stores the pre-spoof " +
                                       "hardware MAC address that was replaced. This value is written " +
                                       "exclusively by MAC-address spoofer tools when they back up the " +
                                       "original MAC before substituting a fake one. Its presence is " +
                                       "definitive evidence of MAC address spoofing.",
                            Detail   = $"OriginalNetworkAddress = {originalAddress} | Adapter = {driverDesc}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // Returns true if the MAC address looks spoofer-generated:
    // all same nibble, all same octet pairs, or well-known fake patterns.
    private static bool IsSuspiciousMac(string macClean12)
    {
        if (macClean12.Length < 12) return false;

        // All same character
        if (macClean12.Distinct().Count() == 1) return true;

        // Repeated octet pair pattern (e.g. AABBCCDDEEFF → AA BB CC DD EE FF all same)
        var octets = Enumerable.Range(0, 6)
            .Select(i => macClean12.Substring(i * 2, 2))
            .ToArray();
        if (octets.Distinct(StringComparer.OrdinalIgnoreCase).Count() <= 2) return true;

        // Known fake MACs
        var lower = macClean12.ToLowerInvariant();
        if (lower is "000000000000" or "ffffffffffff" or "deadbeefcafe"
                  or "010203040506" or "aabbccddeeff") return true;

        return false;
    }

    // Checks HKLM\SYSTEM\CurrentControlSet\Services\mssmbios\Data for a raw
    // SMBIOS table that has been altered by spoofer tools.
    private void CheckSmbiosSpoofing(ScanContext ctx, CancellationToken ct)
    {
        const string smbiosPath = @"SYSTEM\CurrentControlSet\Services\mssmbios\Data";
        if (ct.IsCancellationRequested) return;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(smbiosPath, writable: false);
            if (key is null) return;
            ctx.IncrementRegistryKeys();

            var smBiosData = key.GetValue("SMBiosData") as byte[];
            if (smBiosData is null || smBiosData.Length < 32) return;

            // Check for the SMBIOS anchor "_SM_" at offset 0; if it's missing, the
            // table has been corrupted or replaced entirely.
            var anchor = System.Text.Encoding.ASCII.GetString(smBiosData, 0, Math.Min(4, smBiosData.Length));
            if (!anchor.Equals("_SM_", StringComparison.Ordinal) &&
                !anchor.StartsWith("_SM", StringComparison.Ordinal))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Raw SMBIOS table anchor is invalid (possible spoofer tamper)",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{smbiosPath}\SMBiosData",
                    Reason   = "The raw SMBIOS data blob stored in the mssmbios service registry key " +
                               "does not start with the expected '_SM_' anchor. HWID spoofer tools " +
                               "that patch SMBIOS data in memory sometimes corrupt or rebuild the " +
                               "table structure, resulting in an invalid anchor in the registry copy.",
                    Detail   = $"First 4 bytes anchor: \"{anchor}\" (expected \"_SM_\") | Table size: {smBiosData.Length} bytes"
                });
            }

            // Check for all-zero SMBIOS data beyond the header — spoofers zero serial fields
            var nonZeroAfterHeader = smBiosData.Skip(32).Any(b => b != 0);
            if (!nonZeroAfterHeader && smBiosData.Length > 64)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "SMBIOS table body is entirely zeroed (spoofer artifact)",
                    Risk     = RiskLevel.Critical,
                    Location = $@"HKLM\{smbiosPath}\SMBiosData",
                    Reason   = "The raw SMBIOS data blob contains all-zero bytes after the first 32 " +
                               "bytes of header. Spoofer tools that zero out SMBIOS serials (serial " +
                               "number, UUID, chassis tag, board serial) will produce this pattern, " +
                               "effectively erasing the hardware fingerprint embedded in BIOS firmware.",
                    Detail   = $"SMBiosData size: {smBiosData.Length} bytes; body is entirely 0x00"
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }

        // Check HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation for
        // modified OEM info — spoofers sometimes rewrite this to generic values.
        CheckOemInformation(ctx, ct);
    }

    private void CheckOemInformation(ScanContext ctx, CancellationToken ct)
    {
        const string oemPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation";
        if (ct.IsCancellationRequested) return;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(oemPath, writable: false);
            if (key is null) return;
            ctx.IncrementRegistryKeys();

            var manufacturer = key.GetValue("Manufacturer") as string ?? "";
            var model        = key.GetValue("Model") as string ?? "";
            var supportUrl   = key.GetValue("SupportURL") as string ?? "";

            var combined = (manufacturer + " " + model + " " + supportUrl).ToLowerInvariant();

            foreach (var suspicious in SuspiciousBiosStrings)
            {
                if (combined.Contains(suspicious, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "OEMInformation contains suspicious placeholder value",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\{oemPath}",
                        Reason   = $"The OEMInformation registry key contains the string '{suspicious}' " +
                                   "in its Manufacturer, Model, or SupportURL fields. HWID spoofer tools " +
                                   "that rewrite system identity strings sometimes leave virtualisation " +
                                   "vendor names or placeholder text in these fields.",
                        Detail   = $"Manufacturer: {manufacturer} | Model: {model} | SupportURL: {supportUrl}"
                    });
                    break;
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // Checks HKLM\HARDWARE\DESCRIPTION\System\BIOS for spoofer-injected BIOS strings.
    private void CheckBiosRegistryValues(ScanContext ctx, CancellationToken ct)
    {
        const string biosPath = @"HARDWARE\DESCRIPTION\System\BIOS";
        if (ct.IsCancellationRequested) return;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(biosPath, writable: false);
            if (key is null) return;
            ctx.IncrementRegistryKeys();

            var biosVendor    = key.GetValue("BIOSVendor") as string ?? "";
            var biosVersion   = key.GetValue("BIOSVersion") as string ?? "";
            var biosDate      = key.GetValue("BIOSReleaseDate") as string ?? "";
            var sysManufacturer = key.GetValue("SystemManufacturer") as string ?? "";
            var sysProductName  = key.GetValue("SystemProductName") as string ?? "";
            var baseBoardMfg    = key.GetValue("BaseBoardManufacturer") as string ?? "";
            var baseBoardProduct = key.GetValue("BaseBoardProduct") as string ?? "";

            var allValues = new[]
            {
                ("BIOSVendor",            biosVendor),
                ("BIOSVersion",           biosVersion),
                ("BIOSReleaseDate",       biosDate),
                ("SystemManufacturer",    sysManufacturer),
                ("SystemProductName",     sysProductName),
                ("BaseBoardManufacturer", baseBoardMfg),
                ("BaseBoardProduct",      baseBoardProduct),
            };

            foreach (var (valueName, value) in allValues)
            {
                if (string.IsNullOrWhiteSpace(value)) continue;
                var lowerValue = value.ToLowerInvariant().Trim();

                foreach (var suspiciousStr in SuspiciousBiosStrings)
                {
                    if (lowerValue.Contains(suspiciousStr, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"BIOS registry value contains suspicious string: {valueName}",
                            Risk     = lowerValue.Contains("qemu") || lowerValue.Contains("virtualbox") ||
                                       lowerValue.Contains("vmware")
                                       ? RiskLevel.High
                                       : RiskLevel.Medium,
                            Location = $@"HKLM\{biosPath}\{valueName}",
                            Reason   = $"The BIOS registry value '{valueName}' contains the suspicious " +
                                       $"string '{suspiciousStr}'. This can indicate: (1) a hypervisor " +
                                       "or virtualisation platform used to spoof hardware identity; " +
                                       "(2) a spoofer tool that replaced the real BIOS strings with " +
                                       "placeholder values to defeat BIOS-based fingerprinting.",
                            Detail   = $"{valueName} = \"{value}\""
                        });
                        break;
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // Checks HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0 for spoofed CPU strings.
    private void CheckCpuIdentifierSpoofing(ScanContext ctx, CancellationToken ct)
    {
        const string cpuPath = @"HARDWARE\DESCRIPTION\System\CentralProcessor\0";
        if (ct.IsCancellationRequested) return;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(cpuPath, writable: false);
            if (key is null) return;
            ctx.IncrementRegistryKeys();

            var processorName  = key.GetValue("ProcessorNameString") as string ?? "";
            var identifier     = key.GetValue("Identifier") as string ?? "";
            var vendorId       = key.GetValue("VendorIdentifier") as string ?? "";

            if (!string.IsNullOrWhiteSpace(processorName))
            {
                var lowerName = processorName.ToLowerInvariant().Trim();
                foreach (var fakeName in FakeCpuNames)
                {
                    if (lowerName.Contains(fakeName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "CPU ProcessorNameString appears spoofed or generic",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{cpuPath}\ProcessorNameString",
                            Reason   = $"The CPU ProcessorNameString value '{processorName}' matches " +
                                       "a known generic or fake CPU name pattern. CPU-ID spoofer tools " +
                                       "replace the real processor brand string to prevent anti-cheat " +
                                       "systems from identifying the hardware through CPUID instructions " +
                                       "and their registry-cached equivalents.",
                            Detail   = $"ProcessorNameString = \"{processorName}\" | Identifier = \"{identifier}\""
                        });
                        break;
                    }
                }

                // Check for placeholder patterns in the name
                if (processorName.Trim().Length <= 4 || processorName.Replace("0", "").Replace(" ", "").Length == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "CPU ProcessorNameString is a placeholder value",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{cpuPath}\ProcessorNameString",
                        Reason   = "The ProcessorNameString value is extremely short or consists " +
                                   "entirely of zeros/spaces. Real CPU brand strings from Intel, AMD, " +
                                   "and ARM are 20–50 characters. A blank or minimal value indicates " +
                                   "a spoofer tool cleared or replaced the authentic CPU brand string.",
                        Detail   = $"ProcessorNameString = \"{processorName}\""
                    });
                }
            }

            if (!string.IsNullOrWhiteSpace(identifier))
            {
                // Expected format: "Intel64 Family N Model N Stepping N" or similar
                // A pure hex string or very short value suggests spoofing
                var identClean = identifier.Replace(" ", "");
                if (RandomHexRegex.IsMatch(identClean) && identClean.Length >= 8)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "CPU Identifier appears to be a random hex value",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\{cpuPath}\Identifier",
                        Reason   = "The CPU Identifier registry value is a contiguous hex string with " +
                                   "no standard family/model/stepping format. Legitimate CPU identifiers " +
                                   "from Windows hardware enumeration follow the pattern " +
                                   "'<Arch> Family N Model N Stepping N'. A pure hex value suggests " +
                                   "the field was rewritten by a CPU-ID spoofer.",
                        Detail   = $"Identifier = \"{identifier}\" | VendorIdentifier = \"{vendorId}\""
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // Checks VSS and shadow copy provider service Start values to detect spoofer
    // tools that disable VSS to prevent forensic volume shadow copy analysis.
    private void CheckVssSpoofDisablement(ScanContext ctx, CancellationToken ct)
    {
        var serviceChecks = new[]
        {
            (@"SYSTEM\CurrentControlSet\Services\VSS",   "VSS",   "Volume Shadow Copy service",
             "VSS disablement prevents forensic analysis via shadow copies and is a common " +
             "spoofer installation step to reduce detection surface after reboot."),
            (@"SYSTEM\CurrentControlSet\Services\swprv", "swprv", "Microsoft Software Shadow Copy Provider",
             "Shadow Copy Provider disablement removes the software VSS provider, " +
             "blocking all application-consistent shadow copy creation."),
        };

        foreach (var (regPath, svcName, svcDesc, context) in serviceChecks)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                var startValue = key.GetValue("Start") as int?;
                if (startValue == 4) // 4 = SERVICE_DISABLED
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"{svcName} service disabled — possible spoofer artifact",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{regPath}\Start",
                        Reason   = $"The {svcDesc} ({svcName}) has its Start value set to 4 (Disabled). " +
                                   context + " While VSS can be legitimately disabled on some configurations, " +
                                   "disablement combined with other HWID spoofer artifacts is strongly " +
                                   "indicative of a spoofer installation that targets this service.",
                        Detail   = $"Service: {svcName} | Start = 4 (Disabled)"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Checks the active vs pending computer names for mismatches and for
    // spoofer-generated 8-hex-char computer names.
    private void CheckComputerNameRandomization(ScanContext ctx, CancellationToken ct)
    {
        const string activeNamePath   = @"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName";
        const string pendingNamePath  = @"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName";

        if (ct.IsCancellationRequested) return;
        string? activeName = null;
        string? pendingName = null;

        try
        {
            using var activeKey = Registry.LocalMachine.OpenSubKey(activeNamePath, writable: false);
            ctx.IncrementRegistryKeys();
            activeName = activeKey?.GetValue("ComputerName") as string;
        }
        catch (UnauthorizedAccessException) { }
        catch { }

        try
        {
            using var pendingKey = Registry.LocalMachine.OpenSubKey(pendingNamePath, writable: false);
            ctx.IncrementRegistryKeys();
            pendingName = pendingKey?.GetValue("ComputerName") as string;
        }
        catch (UnauthorizedAccessException) { }
        catch { }

        // If both exist and differ, a rename is pending — spoofers rename the computer
        // to a randomised name and require a reboot to apply it.
        if (!string.IsNullOrWhiteSpace(activeName) && !string.IsNullOrWhiteSpace(pendingName) &&
            !activeName.Equals(pendingName, StringComparison.OrdinalIgnoreCase))
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "Computer name mismatch between active and pending registry keys",
                Risk     = RiskLevel.Medium,
                Location = $@"HKLM\{activeNamePath} vs HKLM\{pendingNamePath}",
                Reason   = $"The active computer name '{activeName}' differs from the pending computer " +
                           $"name '{pendingName}'. This indicates a computer rename that will take " +
                           "effect at next reboot. HWID spoofer tools rename the computer to a " +
                           "randomly generated identifier to break computer-name-based fingerprinting " +
                           "used by some anti-cheat systems.",
                Detail   = $"ActiveComputerName = \"{activeName}\" | ComputerName (pending) = \"{pendingName}\""
            });
        }

        // Check the active name for the spoofer 8-hex-char pattern
        foreach (var name in new[] { activeName, pendingName })
        {
            if (string.IsNullOrWhiteSpace(name)) continue;
            if (HexComputerNameRegex.IsMatch(name))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Computer name matches spoofer-generated hex pattern: {name}",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Control\ComputerName",
                    Reason   = $"The computer name '{name}' consists of exactly 8 hexadecimal characters. " +
                               "HWID spoofer tools routinely rename the machine using a randomly generated " +
                               "8-character hex string (e.g. 'A3F19C02') to defeat computer-name " +
                               "fingerprinting. Legitimate user-chosen computer names virtually never " +
                               "follow this exact pattern.",
                    Detail   = $"ComputerName = \"{name}\""
                });
                break; // Report once even if both active and pending match
            }
        }
    }

    // Scans the GPU class GUID subkeys for UserModeDriverName modifications that
    // indicate GPU identity spoofing.
    private void CheckGpuDriverSpoofing(ScanContext ctx, CancellationToken ct)
    {
        var gpuClassPath = $@"SYSTEM\CurrentControlSet\Control\Class\{GpuClassGuid}";
        try
        {
            using var classKey = Registry.LocalMachine.OpenSubKey(gpuClassPath, writable: false);
            if (classKey is null) return;

            foreach (var subkeyName in classKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();
                try
                {
                    using var adapterKey = classKey.OpenSubKey(subkeyName, writable: false);
                    if (adapterKey is null) continue;

                    var driverDesc      = adapterKey.GetValue("DriverDesc") as string ?? subkeyName;
                    var userModeDriver  = adapterKey.GetValue("UserModeDriverName") as string ?? "";
                    var userModeDriver3 = adapterKey.GetValue("UserModeDriverNameWow") as string ?? "";

                    // UserModeDriverName should point to a .dll in System32 (nvwgf2umx.dll,
                    // igdlh64.dll, aticfx64.dll, etc.). Any entry pointing to a user-land
                    // or temp path is suspicious.
                    foreach (var driverValue in new[] { userModeDriver, userModeDriver3 })
                    {
                        if (string.IsNullOrWhiteSpace(driverValue)) continue;

                        // Each entry can be comma-separated list of paths
                        var paths = driverValue.Split(',', StringSplitOptions.RemoveEmptyEntries);
                        foreach (var rawPath in paths)
                        {
                            var path = rawPath.Trim();
                            if (string.IsNullOrWhiteSpace(path)) continue;

                            var lower = path.ToLowerInvariant();
                            if (lower.Contains("\\temp\\") || lower.Contains("\\appdata\\") ||
                                lower.Contains("\\users\\") || lower.Contains("\\desktop\\") ||
                                lower.Contains("\\downloads\\") || lower.Contains("\\programdata\\"))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"GPU UserModeDriverName points to non-system path: {driverDesc}",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKLM\{gpuClassPath}\{subkeyName}\UserModeDriverName",
                                    FileName = System.IO.Path.GetFileName(path),
                                    Reason   = $"The GPU adapter '{driverDesc}' has its UserModeDriverName " +
                                               $"registry value pointing to '{path}', which is outside the " +
                                               "expected Windows system directories. GPU identity spoofer " +
                                               "tools intercept GPU name and VRAM queries by substituting " +
                                               "a proxy DLL in a user-writable path, allowing them to " +
                                               "report fake GPU information to anti-cheat systems.",
                                    Detail   = $"DriverDesc: {driverDesc} | UserModeDriverName path: {path}"
                                });
                            }
                        }
                    }

                    // Also check for DirectX database version anomalies via separate key
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }

        CheckDirectXDatabaseVersion(ctx, ct);
    }

    private void CheckDirectXDatabaseVersion(ScanContext ctx, CancellationToken ct)
    {
        const string dxPath = @"SOFTWARE\Microsoft\DirectX";
        if (ct.IsCancellationRequested) return;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(dxPath, writable: false);
            if (key is null) return;
            ctx.IncrementRegistryKeys();

            var dbVersion = key.GetValue("DatabaseVersion") as string ?? "";
            // A very old or zeroed database version can indicate GPU spoofer interference
            if (!string.IsNullOrWhiteSpace(dbVersion))
            {
                var versionParts = dbVersion.Split('.');
                if (versionParts.Length >= 2 &&
                    int.TryParse(versionParts[0], out int major) && major < 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "DirectX DatabaseVersion is anomalously old",
                        Risk     = RiskLevel.Low,
                        Location = $@"HKLM\{dxPath}\DatabaseVersion",
                        Reason   = $"The DirectX DatabaseVersion value is '{dbVersion}', which is " +
                                   "anomalously low for a modern Windows system. GPU spoofer tools " +
                                   "that tamper with DirectX registry entries to fake GPU capabilities " +
                                   "may corrupt or downgrade this version field as a side effect.",
                        Detail   = $"DatabaseVersion = \"{dbVersion}\""
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    // Scans HKLM\SYSTEM\CurrentControlSet\Enum\USB for devices with null or empty
    // SerialNumber values, indicating USB serial number spoofing.
    private void CheckUsbDeviceDescriptors(ScanContext ctx, CancellationToken ct)
    {
        const string usbBase = @"SYSTEM\CurrentControlSet\Enum\USB";
        try
        {
            using var usbKey = Registry.LocalMachine.OpenSubKey(usbBase, writable: false);
            if (usbKey is null) return;

            int deviceCount = 0;
            foreach (var vid in usbKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var vidKey = usbKey.OpenSubKey(vid, writable: false);
                    if (vidKey is null) continue;

                    foreach (var instanceId in vidKey.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        if (++deviceCount > 500) return; // bound the search
                        ctx.IncrementRegistryKeys();
                        try
                        {
                            using var instanceKey = vidKey.OpenSubKey(instanceId, writable: false);
                            if (instanceKey is null) continue;

                            var deviceDesc  = instanceKey.GetValue("DeviceDesc") as string ?? "";
                            var friendlyName = instanceKey.GetValue("FriendlyName") as string ?? "";
                            var displayName = !string.IsNullOrWhiteSpace(friendlyName) ? friendlyName : deviceDesc;

                            // The USB serial number is embedded in the instance ID path.
                            // A path segment that is exactly "0000000000000000" or all zeros
                            // indicates the serial was nullified by a spoofer.
                            var cleanInstance = instanceId.Replace("&", "").Trim();
                            if (cleanInstance.Replace("0", "").Length == 0 && cleanInstance.Length >= 8)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"USB device serial number nullified: {displayName}",
                                    Risk     = RiskLevel.High,
                                    Location = $@"HKLM\{usbBase}\{vid}\{instanceId}",
                                    FileName = displayName,
                                    Reason   = "The USB device instance ID contains only zeros, indicating " +
                                               "the USB serial number was zeroed out. HWID spoofer tools " +
                                               "null the USB serial number field to prevent anti-cheat systems " +
                                               "from using USB device history as part of the hardware " +
                                               "fingerprint. Legitimate USB devices have manufacturer-assigned " +
                                               "serial numbers embedded in their instance IDs.",
                                    Detail   = $"Device: {displayName} | VID: {vid} | InstanceId: {instanceId}"
                                });
                            }

                            // Check for the "Parameters" subkey with spoofed serial override
                            try
                            {
                                using var paramsKey = instanceKey.OpenSubKey("Device Parameters", writable: false);
                                if (paramsKey is not null)
                                {
                                    var serialOverride = paramsKey.GetValue("SerialNumber") as string;
                                    if (serialOverride is not null)
                                    {
                                        var cleanSerial = serialOverride.Replace("0", "").Trim();
                                        if (cleanSerial.Length == 0 && serialOverride.Length >= 4)
                                        {
                                            ctx.AddFinding(new Finding
                                            {
                                                Module   = Name,
                                                Title    = $"USB device SerialNumber parameter is all zeros: {displayName}",
                                                Risk     = RiskLevel.High,
                                                Location = $@"HKLM\{usbBase}\{vid}\{instanceId}\Device Parameters\SerialNumber",
                                                FileName = displayName,
                                                Reason   = "The USB device SerialNumber parameter value is all zeros. " +
                                                           "This value is written by HWID spoofer tools that blank out " +
                                                           "the USB serial number from the device descriptor, preventing " +
                                                           "the Windows USB stack from recording the real serial number " +
                                                           "in the enumeration database.",
                                                Detail   = $"SerialNumber = \"{serialOverride}\" | Device: {displayName}"
                                            });
                                        }
                                    }
                                }
                            }
                            catch (UnauthorizedAccessException) { }
                            catch { }
                        }
                        catch (UnauthorizedAccessException) { }
                        catch { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }
}
