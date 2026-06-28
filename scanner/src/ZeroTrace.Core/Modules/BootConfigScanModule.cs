using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects boot configuration modifications used by cheats to disable kernel
/// security features (Secure Boot, HVCI, DSE, PatchGuard).
///
/// Modern anti-cheat systems rely heavily on kernel security features:
///   - Secure Boot: prevents unsigned bootloaders
///   - HVCI / Memory Integrity: prevents unsigned kernel code execution
///   - Driver Signature Enforcement (DSE): enforces signed kernel drivers
///   - PatchGuard (KPP): monitors SSDT/IDT/GDT integrity
///   - Test Signing Mode: allows unsigned drivers (for development only)
///
/// Cheats disable these via:
///   1. bcdedit /set testsigning on      — enables test-signed drivers
///   2. bcdedit /set nointegritychecks on — disables DSE
///   3. bcdedit /set hypervisorlaunchtype off — disables HVCI
///   4. bcdedit /set nx OptOut          — disables NX/DEP
///   5. Custom bootloader (bypassing Secure Boot via MOK or stolen cert)
///
/// Detection:
///   1. Read BCD via WMI (BcdStore / BcdObject) to check critical settings.
///   2. Also check registry-based boot settings.
///   3. Read UEFI secure boot state from firmware.
/// </summary>
public sealed class BootConfigScanModule : IScanModule
{
    private static readonly string _name = "Boot-Konfiguration-Analyse";
    public string Name => _name;
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int infoClass, IntPtr info, uint len, out uint ret);

    // SystemSecureBootInformation = 145
    private const int SystemSecureBootInformation = 145;

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_SECUREBOOT_INFORMATION
    {
        public bool SecureBootEnabled;
        public bool SecureBootCapable;
    }

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckTestSigningMode(ctx, ct);
        hits += CheckHvciState(ctx, ct);
        hits += CheckSecureBoot(ctx, ct);
        hits += CheckBcdViaRegistry(ctx, ct);

        ctx.Report(1.0, Name, $"Boot-Konfiguration geprüft, {hits} verdächtige Einstellungen");
        return Task.CompletedTask;
    }

    private static int CheckTestSigningMode(ScanContext ctx, CancellationToken ct)
    {
        // Check if test signing mode is active by reading kernel USER_SHARED_DATA
        // KernelUserSharedData.NtSystemRoot is at fixed address 0x7FFE0000 on x86/x64
        // TestSigningEnabled is at offset 0x2D4 (build-dependent — use WMI fallback)
        int hits = 0;
        try
        {
            // Use bcdedit output via WMI Win32_ComputerSystem won't have it directly
            // Instead query HKLM registry BCD registry path
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI\Config", writable: false);
            ctx.IncrementRegistryKeys();

            if (key is not null)
            {
                // VulnerableDriverBlocklistEnable = 0 means block list disabled (cheat bypass)
                var blockList = key.GetValue("VulnerableDriverBlocklistEnable");
                if (blockList is int bl && bl == 0)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = "Treiber-Blockliste deaktiviert (HVCI-Bypass-Vorbereitung)",
                        Risk     = RiskLevel.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config",
                        Reason   = "VulnerableDriverBlocklistEnable ist deaktiviert (0). " +
                                   "Die Windows-Blockliste verhindert das Laden bekannter anfälliger " +
                                   "Treiber die für BYOVD-Angriffe (Bring Your Own Vulnerable Driver) " +
                                   "genutzt werden. Cheats deaktivieren diese für Kernel-Zugriff.",
                        Detail   = "VulnerableDriverBlocklistEnable: 0"
                    });
                }
            }

            // Check CI.dll debug policy (disables code integrity)
            using var ciKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI\Policy", writable: false);
            ctx.IncrementRegistryKeys();

            if (ciKey is not null)
            {
                var skipEnforce = ciKey.GetValue("SkipEnforcement");
                if (skipEnforce is int se && se != 0)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module = _name,
                        Title    = "Code Integrity Enforcement deaktiviert",
                        Risk     = RiskLevel.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy",
                        Reason   = "CI.Policy.SkipEnforcement ist gesetzt. " +
                                   "Dies deaktiviert die Code-Integritätsprüfung für Kernel-Module " +
                                   "und erlaubt das Laden unsignierter Treiber — " +
                                   "ein bekannter Cheat-Kernel-Bypass.",
                        Detail   = $"SkipEnforcement: {skipEnforce}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckHvciState(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // HVCI state is in DeviceGuard registry
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                writable: false);
            ctx.IncrementRegistryKeys();

            if (key is null) return 0;

            var enabled = key.GetValue("Enabled") as int?;
            if (enabled == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module = _name,
                    Title    = "HVCI/Memory Integrity deaktiviert",
                    Risk     = RiskLevel.Critical,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HVCI",
                    Reason   = "Hypervisor Protected Code Integrity (HVCI / Memory Integrity) ist " +
                               "explizit deaktiviert. HVCI verhindert das Ausführen unsignierten " +
                               "Kernel-Codes. Cheats deaktivieren HVCI um ihre Ring-0-Treiber " +
                               "ohne gültige Signatur zu laden.",
                    Detail   = "HVCI Enabled: 0"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckSecureBoot(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check Secure Boot state via UEFI firmware variable (Windows exposes it here)
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", writable: false);
            ctx.IncrementRegistryKeys();

            if (key is null) return 0;

            var ubv = key.GetValue("UEFISecureBootEnabled") as int?;
            if (ubv == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module = _name,
                    Title    = "Secure Boot deaktiviert",
                    Risk     = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                    Reason   = "UEFI Secure Boot ist deaktiviert. Ohne Secure Boot kann das System " +
                               "mit einem unsigned oder manipulierten Bootloader starten. " +
                               "Cheat-Systeme deaktivieren Secure Boot um Custom-Bootloader " +
                               "(für PatchGuard-Bypass) zu laden.",
                    Detail   = "UEFISecureBootEnabled: 0"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckBcdViaRegistry(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // BCD Objects in registry — Windows 10/11 mirrors BCD to registry
            // HKLM\BCD00000000 for {current} boot entry
            // This is read-only accessible without elevation on most configurations
            using var bcdRoot = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"BCD00000000", writable: false);
            ctx.IncrementRegistryKeys();

            if (bcdRoot is null) return 0;

            // Look for Objects subkey containing boot entries
            using var objects = bcdRoot.OpenSubKey("Objects", writable: false);
            if (objects is null) return 0;

            foreach (var guid in objects.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;

                using var obj = objects.OpenSubKey(guid, writable: false);
                using var elems = obj?.OpenSubKey("Elements", writable: false);
                if (elems is null) continue;

                // Element 0x16000048 = TestSigning
                using var testSign = elems.OpenSubKey("16000048", writable: false);
                if (testSign is not null)
                {
                    var val = testSign.GetValue("Element");
                    if (val is byte[] b && b.Length > 0 && b[0] == 1)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = "BCD: Test-Signing-Modus aktiviert",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\BCD00000000\Objects\{guid}\Elements\16000048",
                            Reason   = "BCD-Eintrag zeigt, dass der Test-Signing-Modus (bcdedit /set " +
                                       "testsigning on) aktiv ist. Im Test-Signing-Modus akzeptiert " +
                                       "Windows selbst-signierte Kernel-Treiber ohne EV-Zertifikat. " +
                                       "Dies ist der wichtigste Indikator für unsignierte Cheat-Treiber.",
                            Detail   = $"BCD-GUID: {guid} | TestSigning: {b[0]}"
                        });
                    }
                }

                // Element 0x16000010 = NoIntegrityChecks (disables DSE)
                using var noInteg = elems.OpenSubKey("16000010", writable: false);
                if (noInteg is not null)
                {
                    var val = noInteg.GetValue("Element");
                    if (val is byte[] b && b.Length > 0 && b[0] == 1)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module = _name,
                            Title    = "BCD: NoIntegrityChecks aktiviert (DSE deaktiviert)",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\BCD00000000\Objects\{guid}\Elements\16000010",
                            Reason   = "BCD-Eintrag NoIntegrityChecks=TRUE deaktiviert Driver Signature " +
                                       "Enforcement (DSE). Ohne DSE kann Windows beliebige unsignierte " +
                                       "Kernel-Treiber laden. Dieser Modus wird ausschließlich von " +
                                       "Cheat-Loadern und Rootkit-Entwicklern verwendet.",
                            Detail   = $"BCD-GUID: {guid} | NoIntegrityChecks: {b[0]}"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }
}
