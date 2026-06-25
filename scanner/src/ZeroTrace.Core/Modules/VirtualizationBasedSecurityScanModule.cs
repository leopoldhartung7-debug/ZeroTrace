using Microsoft.Win32;
using System.Runtime.InteropServices;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Checks Virtualization-Based Security (VBS), Hypervisor-Protected Code Integrity (HVCI),
/// and Credential Guard status — which are targeted by kernel-level cheats.
///
/// VBS uses Windows Hypervisor to create an isolated memory region (Secure World / VSM)
/// that runs with higher privilege than Ring-0 (kernel). This Virtual Secure Mode:
///   - Runs Credential Guard to protect LSA secrets from kernel-level extraction
///   - Enforces HVCI (Hypervisor-Protected Code Integrity) — prevents unsigned code
///     from running in the kernel, blocking almost all BYOVD and kernel cheats
///
/// Cheats target VBS/HVCI because:
///   1. HVCI blocks all unsigned kernel code — cheat drivers can't load
///   2. Even BYOVD attacks need specially crafted vulnerabilities to work under HVCI
///   3. Credential Guard blocks Mimikatz-style LSASS extraction
///   4. VBS provides a hardware RoT (Root of Trust) that detects kernel manipulation
///
/// Registry paths:
///   HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\
///     EnableVirtualizationBasedSecurity (1 = enabled)
///     RequirePlatformSecurityFeatures (1 = Secure Boot, 3 = +DMA Protection)
///     HypervisorEnforcedCodeIntegrity (1 = HVCI enabled)
///     Locked (1 = UEFI-locked, tamper-resistant)
///   HKLM\SYSTEM\CurrentControlSet\Control\Lsa\
///     LsaCfgFlags (1 = Credential Guard, 2 = UEFI-locked)
///
/// Running state:
///   HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\
///     HypervisorEnforcedCodeIntegrity\Running (1 = HVCI active now)
///     CredentialGuard\Running (1 = CG active now)
/// </summary>
public sealed class VirtualizationBasedSecurityScanModule : IScanModule
{
    public string Name => "VBS/HVCI-Sicherheitsstatus";
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    private const string DeviceGuardKey =
        @"SYSTEM\CurrentControlSet\Control\DeviceGuard";
    private const string DeviceGuardScenariosKey =
        @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios";
    private const string LsaKey =
        @"SYSTEM\CurrentControlSet\Control\Lsa";

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int SystemInformationClass,
        IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckVbsConfiguration(ctx, ct);
        hits += CheckHvciStatus(ctx, ct);
        hits += CheckCredentialGuard(ctx, ct);
        hits += CheckVbsRunningState(ctx, ct);

        ctx.Report(1.0, Name, $"VBS/HVCI-Sicherheitsstatus geprüft, {hits} Probleme");
        return Task.CompletedTask;
    }

    private static int CheckVbsConfiguration(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(DeviceGuardKey, writable: false);
            if (key is null)
            {
                // VBS key missing entirely — VBS was never configured / explicitly removed
                ctx.AddFinding(new Finding
                {
                    Module   = "VBS/HVCI-Sicherheitsstatus",
                    Title    = "Virtualization-Based Security nicht konfiguriert",
                    Risk     = RiskLevel.Medium,
                    Location = $@"HKLM\{DeviceGuardKey}",
                    Reason   = "Der DeviceGuard-Registrierungsschlüssel fehlt. " +
                               "Virtualization-Based Security (VBS) ist nicht aktiviert. " +
                               "VBS/HVCI verhindert das Laden von unsigniertem Kernel-Code " +
                               "und ist damit der wirksamste Schutz gegen Kernel-Cheat-Treiber (BYOVD). " +
                               "Ohne VBS sind Kernel-Cheats deutlich einfacher zu betreiben.",
                    Detail   = $@"HKLM\{DeviceGuardKey}: nicht vorhanden"
                });
                return 1;
            }

            ctx.IncrementRegistryKeys();

            var vbsEnabled = key.GetValue("EnableVirtualizationBasedSecurity") as int? ?? 0;
            if (vbsEnabled == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "VBS/HVCI-Sicherheitsstatus",
                    Title    = "Virtualization-Based Security deaktiviert",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{DeviceGuardKey}",
                    Reason   = "EnableVirtualizationBasedSecurity = 0 — VBS ist ausgeschaltet. " +
                               "Ohne VBS kann HVCI nicht aktiv sein, und Kernel-Code-Integrität " +
                               "wird nicht durch den Hypervisor erzwungen. " +
                               "Cheat-Treiber, die im Ring-0 laufen, können nicht durch HVCI blockiert werden.",
                    Detail   = $"EnableVirtualizationBasedSecurity: {vbsEnabled}"
                });
            }

            // Check if HVCI is configured (not yet running state — that's in Scenarios)
            var hvciConfig = key.GetValue("HypervisorEnforcedCodeIntegrity") as int? ?? 0;
            if (hvciConfig == 0 && vbsEnabled != 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "VBS/HVCI-Sicherheitsstatus",
                    Title    = "HVCI nicht aktiviert (trotz VBS-Konfiguration)",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{DeviceGuardKey}",
                    Reason   = "HypervisorEnforcedCodeIntegrity = 0 — HVCI ist nicht aktiviert, " +
                               "obwohl VBS konfiguriert ist. " +
                               "HVCI ist das kritischste Feature: es erzwingt, dass jeder im " +
                               "Kernel ausgeführte Code digital signiert sein muss. " +
                               "Ohne HVCI können unsignierte Cheat-Treiber (BYOVD) weiterhin laden.",
                    Detail   = $"HVCI: {hvciConfig} | VBS: {vbsEnabled}"
                });
            }

            // Check if VBS was explicitly disabled (vs. never enabled)
            var locked = key.GetValue("Locked") as int? ?? 0;
            if (vbsEnabled == 0 && locked == 0)
            {
                // Not UEFI-locked = was explicitly changed in registry (potential tampering)
                // Only additional finding if there's evidence it was active before
            }
        }
        catch { }
        return hits;
    }

    private static int CheckHvciStatus(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var hvciKey = Registry.LocalMachine.OpenSubKey(
                DeviceGuardScenariosKey + @"\HypervisorEnforcedCodeIntegrity", writable: false);
            if (hvciKey is null) return 0;
            ctx.IncrementRegistryKeys();

            var enabled = hvciKey.GetValue("Enabled") as int? ?? 0;
            var running = hvciKey.GetValue("Running") as int? ?? 0;

            if (enabled == 1 && running == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "VBS/HVCI-Sicherheitsstatus",
                    Title    = "HVCI konfiguriert aber nicht aktiv",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{DeviceGuardScenariosKey}\HypervisorEnforcedCodeIntegrity",
                    Reason   = "HVCI ist konfiguriert (Enabled=1) aber läuft nicht (Running=0). " +
                               "Dies bedeutet, HVCI war aktiv aber wurde deaktiviert — " +
                               "möglicherweise durch einen Neustart nach Registry-Manipulation " +
                               "oder durch UEFI-Einstellungsänderung. " +
                               "Cheat-Tools können HVCI durch UEFI-Manipulation oder sichere " +
                               "Boot-Ketten-Angriffe deaktivieren.",
                    Detail   = $"HVCI Enabled: {enabled} | Running: {running}"
                });
            }
            else if (enabled == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "VBS/HVCI-Sicherheitsstatus",
                    Title    = "HVCI-Szenario deaktiviert",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{DeviceGuardScenariosKey}\HypervisorEnforcedCodeIntegrity",
                    Reason   = "Das HVCI-Szenario ist explizit deaktiviert. " +
                               "Hypervisor-Protected Code Integrity verhindert unsignierten " +
                               "Kernel-Code. Deaktiviert bedeutet, Kernel-Cheats (BYOVD) können laden.",
                    Detail   = $"HVCI Enabled: {enabled} | Running: {running}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckCredentialGuard(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var lsaKey = Registry.LocalMachine.OpenSubKey(LsaKey, writable: false);
            if (lsaKey is null) return 0;
            ctx.IncrementRegistryKeys();

            var lsaCfgFlags = lsaKey.GetValue("LsaCfgFlags") as int? ?? 0;

            // 0 = disabled, 1 = enabled, 2 = enabled + UEFI lock
            if (lsaCfgFlags == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "VBS/HVCI-Sicherheitsstatus",
                    Title    = "Credential Guard nicht aktiviert",
                    Risk     = RiskLevel.Medium,
                    Location = $@"HKLM\{LsaKey}",
                    Reason   = "LsaCfgFlags = 0 — Credential Guard ist deaktiviert. " +
                               "Credential Guard isoliert LSA-Secrets (NTLM-Hashes, Kerberos-Tickets) " +
                               "im Virtual Secure Mode und verhindert, dass Kernel-Code " +
                               "(wie Mimikatz oder Cheat-Exfiltration-Module) sie lesen kann. " +
                               "Ohne Credential Guard sind Credential-Dumps möglich.",
                    Detail   = $"LsaCfgFlags: {lsaCfgFlags} (0=deaktiviert, 1=aktiv, 2=UEFI-gesperrt)"
                });
                hits++;
            }
        }
        catch { }
        return hits;
    }

    private static int CheckVbsRunningState(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var cgKey = Registry.LocalMachine.OpenSubKey(
                DeviceGuardScenariosKey + @"\CredentialGuard", writable: false);
            if (cgKey is null) return 0;
            ctx.IncrementRegistryKeys();

            var cgEnabled = cgKey.GetValue("Enabled") as int? ?? 0;
            var cgRunning = cgKey.GetValue("Running") as int? ?? 0;

            if (cgEnabled == 1 && cgRunning == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "VBS/HVCI-Sicherheitsstatus",
                    Title    = "Credential Guard konfiguriert aber nicht aktiv",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\{DeviceGuardScenariosKey}\CredentialGuard",
                    Reason   = "Credential Guard ist konfiguriert (Enabled=1) aber läuft nicht (Running=0). " +
                               "Dies bedeutet, die Schutzfunktion ist nicht aktiv — " +
                               "LSASS-Secrets sind im normalen Kernel-Speicher und können durch " +
                               "Kernel-Code (Mimikatz, Cheat-Module mit Credential-Exfil) extrahiert werden.",
                    Detail   = $"CG Enabled: {cgEnabled} | Running: {cgRunning}"
                });
            }
        }
        catch { }
        return hits;
    }
}
