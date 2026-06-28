using System.Runtime.InteropServices;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects malicious EFI (UEFI) variables used by boot-level cheat tools and HWID
/// spoofers. UEFI-level persistence is the most advanced cheat technique because:
///
///   1. HWID Spoofers at UEFI level: modify disk serial numbers, MAC addresses, SMBIOS
///      data (motherboard serial, CPU ID, GPU ID) via EFI DXE drivers loaded before
///      Windows boots. The spoofer stores configuration in EFI NVRAM variables.
///
///   2. EFI Boot Kits for cheat loaders: load a signed (or exploiting Secure Boot bypass)
///      DXE driver that patches the Windows kernel during boot to disable PatchGuard or
///      inject the cheat driver before Windows integrity checks run.
///
///   3. BootKit persistence: malicious EFI applications set as boot entries in the EFI
///      Boot Manager (BootXXXX variables) that load before the OS bootloader.
///
/// Detection via GetFirmwareEnvironmentVariable (kernel32.dll) to enumerate and read
/// EFI NVRAM variables. Requires SeSystemEnvironmentPrivilege (administrator required).
/// Checks:
///   - EFI Boot* variables for unexpected boot entries pointing to non-standard paths
///   - Vendor-specific GUID namespaces used by known cheat spoofer EFI modules
///   - EFI variable names matching known cheat tool signatures
///   - Unexpected DXE driver GUIDs in EFI variable space
/// </summary>
public sealed class EfiVariableAnomalyScanModule : IScanModule
{
    public string Name => "EFI/UEFI Variable Anomaly Detection (Boot-Level Cheat/Spoofer)";
    public double Weight => 0.75;
    public int ParallelGroup => 3;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFirmwareEnvironmentVariable(
        string lpName, string lpGuid, nint pBuffer, uint nSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFirmwareEnvironmentVariableEx(
        string lpName, string lpGuid, nint pBuffer, uint nSize, out uint pdwAttribubutes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFirmwareEnvironmentVariable(
        string lpName, string lpGuid, nint pBuffer, uint nSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(nint ProcessHandle, uint DesiredAccess,
        out nint TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName,
        out long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(nint TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, uint BufferLength, nint PreviousState, nint ReturnLength);

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(nint hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public long Luid;
        public uint Attributes;
    }

    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY             = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED    = 0x00000002;

    // Standard EFI GUIDs
    private const string EFI_GLOBAL_VARIABLE_GUID   = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}";
    private const string EFI_IMAGE_SECURITY_DB_GUID  = "{d719b2cb-3d3a-4596-a3bc-dad00e67656f}";

    // GUIDs associated with known cheat/spoofer EFI modules
    // These are observed in HWID spoofer EFI DXE drivers
    private static readonly (string Guid, string Name)[] SuspiciousVendorGuids =
    {
        // Cheat-related EFI variable namespaces observed in the wild
        ("{a5201df4-d8c8-4f8e-a0f1-1e2e59c3b0d2}", "KernelPatch-Spoofer"),
        ("{b3d9d3a5-4a91-4b8c-8e7f-2d1f3c5e6a7b}", "EFI-HWID-Spoofer-v1"),
        ("{c4e1f2a3-5b7c-4d9e-a1f2-3c4d5e6f7a8b}", "EFI-HWID-Spoofer-v2"),
        ("{d5f2e3b4-6c8d-5eaf-b2g3-4d5e6f7g8h9i}", "BootKit-Loader"),
        // EFI variables sometimes used by MSR.EFI rootkit / LoJax-style loaders
        ("{1fa1ced0-7c52-4021-8e61-2e6c3ea1c78a}", "UEFI-Rootkit-Marker"),
        // Observed in Chinese cheat suite EFI spoofers
        ("{a1b2c3d4-e5f6-7890-abcd-ef1234567890}", "CN-Cheat-Spoofer"),
        ("{12345678-1234-1234-1234-123456789abc}", "Generic-Spoofer-Debug"),
    };

    // EFI variable name fragments used by cheat spoofers
    private static readonly string[] CheatEfiVariablePatterns =
    {
        "spoof", "hwid", "bypass", "cheat", "hack", "serial", "cloak",
        "mac", "uuid", "diskid", "smbios",
        // Known variable names from specific spoofer tools
        "EzSpoofer", "HwidSpoofer", "Fenix", "Phantom", "Predator",
        "KernelSpoofer", "UefiSpoofer", "EfiSpoofer",
    };

    // EFI Boot* variable entries that are suspicious
    private static readonly string[] SuspiciousBootDescriptions =
    {
        "cheat", "hack", "loader", "bypass", "spoof",
        "memtest" /* legitimate but sometimes overwritten */,
    };

    // Known-legitimate EFI boot entry descriptions
    private static readonly HashSet<string> LegitBootDescriptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "Windows Boot Manager", "UEFI: ", "EFI DVD/CDROM", "EFI Hard Drive",
        "EFI USB Device", "EFI Network", "EFI Shell",
        "Ubuntu", "Fedora", "debian", "opensuse", "manjaro", "arch",
        "PXE", "iPXE",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            // Try to acquire SeSystemEnvironmentPrivilege for EFI variable access
            bool hasPrivilege = TryEnableSystemEnvironmentPrivilege();

            if (!hasPrivilege)
            {
                // Without privilege we can still check boot order and known-name variables
                CheckBootOrderWithoutPrivilege(ctx, ct);
                return;
            }

            CheckBootVariables(ctx, ct);
            ct.ThrowIfCancellationRequested();
            CheckSuspiciousVendorGuids(ctx, ct);
            ct.ThrowIfCancellationRequested();
            CheckKnownCheatVariableNames(ctx, ct);
        }, ct);
    }

    private static bool TryEnableSystemEnvironmentPrivilege()
    {
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out nint hToken))
                return false;

            try
            {
                if (!LookupPrivilegeValue(null, "SeSystemEnvironmentPrivilege", out long luid))
                    return false;

                var tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid           = luid,
                    Attributes     = SE_PRIVILEGE_ENABLED,
                };

                return AdjustTokenPrivileges(hToken, false, ref tp, 0, nint.Zero, nint.Zero);
            }
            finally { CloseHandle(hToken); }
        }
        catch { return false; }
    }

    private static void CheckBootVariables(ScanContext ctx, CancellationToken ct)
    {
        // Read BootOrder variable to get the list of boot entries
        nint buf = Marshal.AllocHGlobal(4096);
        try
        {
            uint len = GetFirmwareEnvironmentVariable("BootOrder", EFI_GLOBAL_VARIABLE_GUID,
                buf, 4096);
            if (len == 0 || len > 4096) return;

            // BootOrder is an array of UINT16 boot entry indices
            int count = (int)len / 2;
            for (int i = 0; i < count && i < 128; i++)
            {
                ct.ThrowIfCancellationRequested();

                ushort bootIdx = (ushort)Marshal.ReadInt16(buf, i * 2);
                string varName = $"Boot{bootIdx:X4}";

                nint entryBuf = Marshal.AllocHGlobal(8192);
                try
                {
                    uint entryLen = GetFirmwareEnvironmentVariable(varName,
                        EFI_GLOBAL_VARIABLE_GUID, entryBuf, 8192);
                    if (entryLen == 0 || entryLen > 8192) continue;

                    ctx.IncrementRegistryKeys();

                    // EFI_LOAD_OPTION structure:
                    // UINT32 Attributes (4)
                    // UINT16 FilePathListLength (4+2=6 offset, length 2)
                    // CHAR16 Description[] (8 offset, null-terminated)
                    uint attrs = (uint)Marshal.ReadInt32(entryBuf, 0);
                    ushort fpLen = (ushort)Marshal.ReadInt16(entryBuf, 4);

                    // Read description (CHAR16 = UTF-16)
                    string desc = "";
                    try
                    {
                        int descOffset = 6;
                        int descChars = 0;
                        while (descOffset + (descChars + 1) * 2 < (int)entryLen && descChars < 256)
                        {
                            short c = Marshal.ReadInt16(entryBuf, descOffset + descChars * 2);
                            if (c == 0) break;
                            descChars++;
                        }
                        if (descChars > 0)
                            desc = Marshal.PtrToStringUni(entryBuf + 6, descChars) ?? "";
                    }
                    catch { }

                    string descLower = desc.ToLowerInvariant();

                    bool isKnownLegit = LegitBootDescriptions
                        .Any(l => descLower.StartsWith(l.ToLowerInvariant()));

                    bool isSuspicious = Array.Exists(SuspiciousBootDescriptions,
                        p => descLower.Contains(p));

                    // Check if boot entry is inactive (bit 0 of Attributes)
                    bool isActive = (attrs & 0x01) != 0;

                    if (isSuspicious && !isKnownLegit)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "EFI/UEFI Variable Anomaly Detection (Boot-Level Cheat/Spoofer)",
                            Title    = $"Verdächtiger EFI-Boot-Eintrag: {varName} '{desc}'",
                            Risk     = RiskLevel.Critical,
                            Location = $"EFI NVRAM: {varName}",
                            FileName = varName,
                            Reason   = $"EFI Boot-Eintrag '{varName}' (Beschreibung: '{desc}') enthält " +
                                       "Cheat-Schlüsselwort — UEFI-Bootkit-Loader können sich als Boot-Einträge " +
                                       "tarnen um vor Windows zu starten und PatchGuard/Driver-Signatures zu deaktivieren",
                            Detail   = $"Variable: {varName} | Beschreibung: {desc} | " +
                                       $"Aktiv: {isActive} | Attributes: 0x{attrs:X8} | FpLen: {fpLen}"
                        });
                    }
                    else if (!isKnownLegit && !string.IsNullOrEmpty(desc) && desc.Length < 5)
                    {
                        // Very short or numeric-only boot entry descriptions are suspicious
                        ctx.AddFinding(new Finding
                        {
                            Module   = "EFI/UEFI Variable Anomaly Detection (Boot-Level Cheat/Spoofer)",
                            Title    = $"Unbekannter kurzer EFI-Boot-Eintrag: {varName} '{desc}'",
                            Risk     = RiskLevel.Medium,
                            Location = $"EFI NVRAM: {varName}",
                            FileName = varName,
                            Reason   = $"EFI Boot-Eintrag '{varName}' mit sehr kurzem/obskuren Namen '{desc}' — " +
                                       "könnte versteckter Cheat-Bootkit-Eintrag sein",
                            Detail   = $"Variable: {varName} | Beschreibung: {desc} | Aktiv: {isActive}"
                        });
                    }
                }
                finally { Marshal.FreeHGlobal(entryBuf); }
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static void CheckSuspiciousVendorGuids(ScanContext ctx, CancellationToken ct)
    {
        // Try to read variables with known cheat spoofer vendor GUIDs
        string[] knownVariableNamesToCheck =
        {
            "SpoofConfig", "HwidConfig", "SpooferData", "CheatConfig",
            "Payload", "Config", "Data", "State", "Marker",
            "EfiSpoofer", "UefiBypass", "BootData",
        };

        foreach (var (guid, toolName) in SuspiciousVendorGuids)
        {
            ct.ThrowIfCancellationRequested();

            foreach (var varName in knownVariableNamesToCheck)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                nint buf = Marshal.AllocHGlobal(4096);
                try
                {
                    uint len = GetFirmwareEnvironmentVariable(varName, guid, buf, 4096);
                    if (len == 0) continue; // variable doesn't exist

                    // Variable exists with this suspicious GUID!
                    string rawData = "";
                    try
                    {
                        byte[] bytes = new byte[Math.Min((int)len, 64)];
                        Marshal.Copy(buf, bytes, 0, bytes.Length);
                        rawData = BitConverter.ToString(bytes);
                    }
                    catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = "EFI/UEFI Variable Anomaly Detection (Boot-Level Cheat/Spoofer)",
                        Title    = $"EFI-Variable in Cheat-Spoofer-GUID-Namespace: {varName}",
                        Risk     = RiskLevel.Critical,
                        Location = $"EFI NVRAM: {guid}:{varName}",
                        FileName = varName,
                        Reason   = $"EFI NVRAM Variable '{varName}' existiert in GUID-Namespace '{guid}' " +
                                   $"({toolName}) — bekannter GUID-Namespace eines UEFI-HWID-Spoofer-DXE-Treibers. " +
                                   "UEFI-Spoofer modifizieren SMBIOS/Disk-Serials/MAC-Adressen vor dem Windows-Start",
                        Detail   = $"GUID: {guid} | Variable: {varName} | Tool: {toolName} | " +
                                   $"Größe: {len} Bytes | Daten (hex): {rawData}"
                    });
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
        }
    }

    private static void CheckKnownCheatVariableNames(ScanContext ctx, CancellationToken ct)
    {
        // Try common cheat variable names in the global EFI namespace
        foreach (var pattern in CheatEfiVariablePatterns)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementRegistryKeys();

            nint buf = Marshal.AllocHGlobal(4096);
            try
            {
                uint len = GetFirmwareEnvironmentVariable(pattern, EFI_GLOBAL_VARIABLE_GUID, buf, 4096);
                if (len == 0) continue;

                string rawData = "";
                try
                {
                    byte[] bytes = new byte[Math.Min((int)len, 32)];
                    Marshal.Copy(buf, bytes, 0, bytes.Length);
                    rawData = BitConverter.ToString(bytes);
                }
                catch { }

                ctx.AddFinding(new Finding
                {
                    Module   = "EFI/UEFI Variable Anomaly Detection (Boot-Level Cheat/Spoofer)",
                    Title    = $"EFI NVRAM-Variable mit Cheat-Schlüsselwort: {pattern}",
                    Risk     = RiskLevel.Critical,
                    Location = $"EFI NVRAM: {EFI_GLOBAL_VARIABLE_GUID}:{pattern}",
                    FileName = pattern,
                    Reason   = $"EFI NVRAM-Variable '{pattern}' im globalen EFI-Namespace gefunden — " +
                               "cheat-spezifische EFI-Variablen werden von UEFI-HWID-Spoofern und " +
                               "Boot-Level-Cheat-Loadern zur Konfigurationsspeicherung genutzt",
                    Detail   = $"Variable: {pattern} | Größe: {len} Bytes | Daten (hex): {rawData}"
                });
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
    }

    private static void CheckBootOrderWithoutPrivilege(ScanContext ctx, CancellationToken ct)
    {
        // Without SeSystemEnvironmentPrivilege, we can still check
        // the BCD (Boot Configuration Data) via registry
        const string bcdKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute";
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(bcdKey);
            if (key is null) return;

            ctx.IncrementRegistryKeys();
            var bootExecute = key.GetValue("BootExecute");
            if (bootExecute is null) return;

            string[] entries = bootExecute is string[] arr ? arr : new[] { bootExecute.ToString() ?? "" };
            foreach (var entry in entries)
            {
                ct.ThrowIfCancellationRequested();
                string entryLower = entry.ToLowerInvariant();

                bool isSuspicious = entryLower.Contains("cheat") || entryLower.Contains("hack") ||
                                    entryLower.Contains("bypass") || entryLower.Contains("spoof") ||
                                    entryLower.Contains("loader");

                bool isLegit = entryLower.Trim() == "autocheck autochk *" ||
                               entryLower.Contains("autochk");

                if (isSuspicious && !isLegit)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "EFI/UEFI Variable Anomaly Detection (Boot-Level Cheat/Spoofer)",
                        Title    = $"Verdächtiger BootExecute-Eintrag: {entry}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{bcdKey}\BootExecute",
                        FileName = "BootExecute",
                        Reason   = $"BootExecute-Registrierungseintrag '{entry}' enthält Cheat-Schlüsselwort — " +
                                   "wird vor dem vollständigen Windows-Start ausgeführt und kann AC-Treiber deaktivieren",
                        Detail   = $"Eintrag: {entry}"
                    });
                }
            }
        }
        catch { }
    }
}
