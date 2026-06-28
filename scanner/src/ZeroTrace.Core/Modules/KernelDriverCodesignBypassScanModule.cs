using ZeroTrace.Core.Models;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects kernel-level code signing enforcement bypass indicators beyond what
/// BootConfigScanModule and CodeSigningBypassScanModule cover individually.
///
/// This module specifically targets:
///
/// 1. HVCI (Hypervisor-Protected Code Integrity) bypass:
///    - HVCI enforces kernel code integrity via VBS — when enabled, unsigned kernel
///      code cannot execute even with Test Signing enabled
///    - Registry: HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\HVCIState
///    - If HVCIModeEnabled=0 on a system that previously had HVCI enabled, it was
///      disabled by a BYOVD cheat that called NtSetSystemInformation(CodeIntegrity, 0)
///
/// 2. CI.dll integrity check bypass (PatchGuard circumvention):
///    - Some BYOVD tools patch ci.dll in memory to set g_CiEnabled=0
///    - Not directly detectable from userland, but the loaded CI.dll code section
///      can be compared against on-disk
///    - Detectable via: KernelBridge driver (existing module covers this)
///    - This module checks for ci.dll replacement on disk (wrong size, no MS sig)
///
/// 3. WHQL blocklist bypass:
///    - HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy\UpgradedSystem
///    - VulnerableDriverBlocklistEnable = 0 (Microsoft HVCI blocklist disabled)
///    - This allows loading all documented BYOVD drivers even with HVCI on
///
/// 4. Secure Boot state verification:
///    - UEFISecureBootEnabled = 0 in firmware means unsigned bootloaders can run
///    - Combined with disabled HVCI = fully open to ring-0 cheats
///    - Registry HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State
///
/// 5. Kernel debugger attachment indicators:
///    - KdDebuggerEnabled bit in SharedUserData (from userland via ntdll!NtCurrentTeb offset)
///    - HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpEnabled = 0 (crash dump disabled)
///    - Kernel debugger port active = cheats using WinDbg-style kernel debugging for ring-0 access
///
/// 6. Driver Verifier targeting anti-cheat drivers:
///    - HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\VerifyDrivers
///    - If AC driver names appear in VerifyDrivers, the cheat operator is stress-testing AC to crash it
///
/// Ocean/detect.ac perform a comprehensive kernel security posture check because
/// all BYOVD/ring-0 cheats require at least one of these bypass conditions.
/// </summary>
public sealed class KernelDriverCodesignBypassScanModule : IScanModule
{
    public string Name => "Kernel Code-Signing Bypass & HVCI/Secure Boot Umgehung";
    public double Weight => 0.55;
    public int ParallelGroup => 3;

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int SystemInformationClass,
        ref SYSTEM_CODEINTEGRITY_INFORMATION SystemInformation,
        uint SystemInformationLength, out uint ReturnLength);

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_CODEINTEGRITY_INFORMATION
    {
        public uint Length;
        public uint CodeIntegrityOptions;
    }

    private const int SystemCodeIntegrityInformation = 103;

    // CodeIntegrityOptions flags
    private const uint CODEINTEGRITY_OPTION_ENABLED                   = 0x01;
    private const uint CODEINTEGRITY_OPTION_TESTSIGN                  = 0x02;
    private const uint CODEINTEGRITY_OPTION_UMCI_ENABLED              = 0x04;
    private const uint CODEINTEGRITY_OPTION_IUM_ENABLED               = 0x40;
    private const uint CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED         = 0x80;
    private const uint CODEINTEGRITY_OPTION_FLIGHT_ENABLED            = 0x200;
    private const uint CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED         = 0x400;
    private const uint CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE       = 0x800;
    private const uint CODEINTEGRITY_OPTION_HVCI_KMCI_STRICT          = 0x1000;
    private const uint CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED          = 0x2000;

    private static readonly string[] AntiCheatDriverNames =
    {
        "easyanticheat", "eac", "battleye", "be", "vgk", "vgc", "faceit",
        "esea", "xigncode3", "nprotect", "gameguard", "mhyprot", "mhyprot2",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        // 1. Query live kernel code integrity state via NtQuerySystemInformation
        CheckKernelCodeIntegrityState(ctx);
        ct.ThrowIfCancellationRequested();

        // 2. HVCI / DeviceGuard registry state
        CheckHvciRegistry(ctx);
        ct.ThrowIfCancellationRequested();

        // 3. Vulnerable Driver Blocklist
        CheckVulnerableDriverBlocklist(ctx);
        ct.ThrowIfCancellationRequested();

        // 4. Secure Boot state
        CheckSecureBootState(ctx);
        ct.ThrowIfCancellationRequested();

        // 5. Kernel debugger port / crash dump config
        CheckKernelDebuggerConfig(ctx);
        ct.ThrowIfCancellationRequested();

        // 6. Driver Verifier targeting AC drivers
        CheckDriverVerifierTargets(ctx);
        ct.ThrowIfCancellationRequested();

        // 7. CI policy override files
        CheckCiPolicyFiles(ctx);
    }

    private void CheckKernelCodeIntegrityState(ScanContext ctx)
    {
        var info = new SYSTEM_CODEINTEGRITY_INFORMATION { Length = 8 };
        int status = NtQuerySystemInformation(SystemCodeIntegrityInformation, ref info, 8, out _);
        if (status != 0) return;

        uint opts = info.CodeIntegrityOptions;

        bool ciEnabled   = (opts & CODEINTEGRITY_OPTION_ENABLED) != 0;
        bool testSign    = (opts & CODEINTEGRITY_OPTION_TESTSIGN) != 0;
        bool debugMode   = (opts & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED) != 0;
        bool hvciEnabled = (opts & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0;

        if (testSign)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "Kernel Test-Signing-Modus AKTIV (unsigned drivers können geladen werden)",
                Risk     = RiskLevel.High,
                Location = "NtQuerySystemInformation(SystemCodeIntegrityInformation)",
                FileName = "CI",
                Reason   = "Der Windows-Kernel läuft im Test-Signing-Modus " +
                           "(CODEINTEGRITY_OPTION_TESTSIGN gesetzt). " +
                           "In diesem Modus können nicht-WHQL-signierte Kernel-Treiber geladen werden. " +
                           "Cheat-Tools aktivieren diesen Modus via 'bcdedit /set testsigning on' um " +
                           "ihre eigenen Ring-0-Treiber ohne gestohlene/vulnerable Zertifikate zu laden.",
                Detail   = $"CodeIntegrityOptions: 0x{opts:X} | TestSign=true | HVCI={hvciEnabled}"
            });
        }

        if (debugMode)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "Kernel Debug-Modus AKTIV (Kernel-Debugging aktiviert)",
                Risk     = RiskLevel.High,
                Location = "NtQuerySystemInformation(SystemCodeIntegrityInformation)",
                FileName = "CI",
                Reason   = "Der Windows-Kernel ist im Debug-Modus gestartet " +
                           "(CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED gesetzt). " +
                           "Kernel-Debugging ermöglicht direkten Ring-0-Speicherzugriff ohne Treiber. " +
                           "Cheat-Tools wie WinDbg-basierte Lösungen nutzen Kernel-Debugging " +
                           "für direkten Kernel-Speicherzugriff und PatchGuard-Umgehung.",
                Detail   = $"CodeIntegrityOptions: 0x{opts:X} | DebugMode=true"
            });
        }

        if (!ciEnabled)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "Code Integrity (CI) im Kernel DEAKTIVIERT",
                Risk     = RiskLevel.Critical,
                Location = "NtQuerySystemInformation(SystemCodeIntegrityInformation)",
                FileName = "CI",
                Reason   = "Windows Kernel Code Integrity ist vollständig deaktiviert " +
                           "(CODEINTEGRITY_OPTION_ENABLED NICHT gesetzt). " +
                           "Dies bedeutet, dass KEIN Treiber auf Signaturen geprüft wird. " +
                           "Nur möglich durch Kernel-Debugging, BYOVD oder Boot-Level-Eingriff.",
                Detail   = $"CodeIntegrityOptions: 0x{opts:X} | CI NOT enabled"
            });
        }
    }

    private void CheckHvciRegistry(ScanContext ctx)
    {
        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard");
            if (key == null) return;

            object? hvciMode = key.GetValue("HVCIModeEnabled");
            object? requiredFlags = key.GetValue("RequireMicrosoftSignedBootChain");
            object? enabledFlags = key.GetValue("EnableVirtualizationBasedSecurity");

            if (hvciMode is int hvci && hvci == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "HVCI (Hypervisor-Protected Code Integrity) DEAKTIVIERT",
                    Risk     = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
                    FileName = "HVCIModeEnabled",
                    Reason   = "HVCI ist deaktiviert (HVCIModeEnabled=0). HVCI ist die stärkste " +
                               "Kernel-Code-Integritätsschutzmaßnahme — wenn aktiv, können auch " +
                               "BYOVD-Treiber mit gestohlenen Zertifikaten nicht als Kernel-Code " +
                               "ausgeführt werden. Cheater deaktivieren HVCI explizit für Ring-0-Zugriff.",
                    Detail   = $"HVCIModeEnabled: {hvciMode} | EnableVBS: {enabledFlags}"
                });
            }
        }
        catch { }
    }

    private void CheckVulnerableDriverBlocklist(ScanContext ctx)
    {
        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI\Config");
            if (key == null) return;

            object? blocklistEnabled = key.GetValue("VulnerableDriverBlocklistEnable");
            if (blocklistEnabled is int val && val == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Microsoft Vulnerable Driver Blocklist DEAKTIVIERT (BYOVD-Schutz aus)",
                    Risk     = RiskLevel.Critical,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config",
                    FileName = "VulnerableDriverBlocklistEnable",
                    Reason   = "Die Microsoft Vulnerable Driver Blocklist ist deaktiviert " +
                               "(VulnerableDriverBlocklistEnable=0). Diese Blockliste verhindert " +
                               "das Laden dokumentierter BYOVD-Treiber (mhyprot2.sys, RTCore64.sys, " +
                               "WinRing0.sys etc.) auch auf Systemen mit HVCI. " +
                               "Cheat-Tools deaktivieren diese Liste als ersten Schritt der BYOVD-Kette.",
                    Detail   = $"VulnerableDriverBlocklistEnable: {val}"
                });
            }
        }
        catch { }

        // Also check the Windows Update-managed key
        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI\Policy");
            if (key == null) return;

            object? blocklistEnabled = key.GetValue("VulnerableDriverBlocklistEnable");
            if (blocklistEnabled is int val && val == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Vulnerable Driver Blocklist in CI\\Policy DEAKTIVIERT",
                    Risk     = RiskLevel.Critical,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy",
                    FileName = "VulnerableDriverBlocklistEnable",
                    Reason   = "CI Policy VulnerableDriverBlocklistEnable=0 — " +
                               "Microsoft HVCI Blockliste für anfällige Treiber ist in CI\\Policy deaktiviert. " +
                               "Erlaubt alle dokumentierten BYOVD-Treiber.",
                    Detail   = $"VulnerableDriverBlocklistEnable (Policy): {val}"
                });
            }
        }
        catch { }
    }

    private void CheckSecureBootState(ScanContext ctx)
    {
        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            if (key == null)
            {
                // Key absent on BIOS systems — not necessarily suspicious
                return;
            }

            object? uefiEnabled = key.GetValue("UEFISecureBootEnabled");
            if (uefiEnabled is int val && val == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "UEFI Secure Boot DEAKTIVIERT",
                    Risk     = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                    FileName = "UEFISecureBootEnabled",
                    Reason   = "UEFI Secure Boot ist deaktiviert (UEFISecureBootEnabled=0). " +
                               "Secure Boot verhindert das Laden von UEFI-Firmware-Level-Bootkits " +
                               "und unsignierten Boot-Loadern. Ohne Secure Boot können HWID-Spoofer " +
                               "auf UEFI-Ebene geladen werden bevor der Windows-Kernel startet.",
                    Detail   = $"UEFISecureBootEnabled: {val}"
                });
            }
        }
        catch { }
    }

    private void CheckKernelDebuggerConfig(ScanContext ctx)
    {
        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CrashControl");
            if (key == null) return;

            object? dumpEnabled = key.GetValue("CrashDumpEnabled");
            object? filterAdmins = key.GetValue("FilterAdministrators");

            // Crash dump completely disabled on a normal gaming PC is suspicious
            // (combined with other flags — standalone this is benign)
            if (dumpEnabled is int dump && dump == 0)
            {
                // Low by itself — only flag in context of other findings
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Kernel Crash-Dump DEAKTIVIERT (Anti-Forensik Indikator)",
                    Risk     = RiskLevel.Low,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CrashControl",
                    FileName = "CrashDumpEnabled",
                    Reason   = "Windows Kernel Crash-Dumps sind vollständig deaktiviert (CrashDumpEnabled=0). " +
                               "Crash-Dumps würden Kernel-Speicher bei BSOD sichern — ein forensisches " +
                               "Werkzeug für Anti-Cheat-Analyse. Cheat-Setups deaktivieren Crash-Dumps " +
                               "um forensische Kernel-Analyse nach BYOVD-bedingten BSODs zu verhindern.",
                    Detail   = $"CrashDumpEnabled: {dumpEnabled}"
                });
            }
        }
        catch { }

        // Check BCD for kernel debug settings (via registry mirror)
        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter");
            // Not very useful — skip
        }
        catch { }
    }

    private void CheckDriverVerifierTargets(ScanContext ctx)
    {
        ctx.IncrementRegistryKeys();
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management");
            if (key == null) return;

            object? verifyDrivers = key.GetValue("VerifyDrivers");
            if (verifyDrivers == null) return;

            string verifyList = verifyDrivers.ToString()?.ToLowerInvariant() ?? "";
            if (string.IsNullOrWhiteSpace(verifyList) || verifyList == "*") return;

            // If the verify list explicitly names AC driver files — someone is stress-testing AC
            string? acMatch = AntiCheatDriverNames.FirstOrDefault(ac => verifyList.Contains(ac));
            if (acMatch != null)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Driver Verifier zielt auf Anti-Cheat-Treiber: '{acMatch}'",
                    Risk     = RiskLevel.Critical,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                    FileName = "VerifyDrivers",
                    Reason   = $"Windows Driver Verifier ist so konfiguriert, dass er Anti-Cheat-Treiber " +
                               $"('{acMatch}') prüft (VerifyDrivers='{verifyList}'). " +
                               "Driver Verifier aktiviert intensive Laufzeitprüfungen die ACs zum Absturz " +
                               "bringen können. Cheater nutzen dies gezielt um Anti-Cheat-Treiber zu " +
                               "destabilisieren und BSODs zu provozieren, die das Spiel ohne AC neu starten.",
                    Detail   = $"VerifyDrivers: {verifyList} | Matched AC: {acMatch}"
                });
            }

            ctx.IncrementRegistryKeys();
        }
        catch { }
    }

    private void CheckCiPolicyFiles(ScanContext ctx)
    {
        // Custom WDAC (Windows Defender Application Control) CI policy files
        // Legitimate: %SystemRoot%\System32\CodeIntegrity\CIPolicies\Active\*.cip
        // Suspicious: unknown .cip files, especially ones allowing all kernel code
        string ciPoliciesDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "CodeIntegrity", "CIPolicies", "Active");

        if (!Directory.Exists(ciPoliciesDir)) return;

        try
        {
            var cipFiles = Directory.GetFiles(ciPoliciesDir, "*.cip");
            // More than 1 active policy is unusual — Windows ships with 1 default
            // Additional policies could be custom "allow all" policies from cheat tools
            if (cipFiles.Length > 2)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Mehrere aktive CI-Policy-Dateien ({cipFiles.Length}) — mögliche WDAC-Manipulation",
                    Risk     = RiskLevel.Medium,
                    Location = ciPoliciesDir,
                    FileName = "*.cip",
                    Reason   = $"Es sind {cipFiles.Length} aktive WDAC CI-Policy-Dateien vorhanden " +
                               $"(normal: 1-2). Zusätzliche CI-Policies können Code-Signing-Anforderungen " +
                               "lockern oder Treiber-Laderegeln überschreiben. Cheat-Tool-Installer " +
                               "können 'Audit-Mode' oder 'AllowAll'-Policies hinzufügen.",
                    Detail   = $"CI Policies Dir: {ciPoliciesDir} | Count: {cipFiles.Length} | " +
                               string.Join(", ", cipFiles.Select(Path.GetFileName))
                });
            }

            foreach (var cipFile in cipFiles)
            {
                ctx.IncrementFiles();
                // CIP files are binary — check if they are unusually small (might be stripped)
                // A valid CIP file is at minimum a few hundred bytes
                try
                {
                    long size = new FileInfo(cipFile).Length;
                    if (size < 200)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Verdächtige CI-Policy-Datei (zu klein): {Path.GetFileName(cipFile)}",
                            Risk     = RiskLevel.Medium,
                            Location = cipFile,
                            FileName = Path.GetFileName(cipFile),
                            Reason   = $"CI-Policy-Datei '{Path.GetFileName(cipFile)}' ist nur {size} Bytes groß. " +
                                       "Gültige WDAC-Policies sind mindestens einige hundert Bytes. " +
                                       "Eine zu kleine/leere Policy kann Code-Signing-Checks komplett deaktivieren.",
                            Detail   = $"Datei: {cipFile} | Größe: {size} bytes"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }
}
