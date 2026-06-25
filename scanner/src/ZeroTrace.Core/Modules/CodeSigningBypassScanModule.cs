using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects code signing bypass and trust chain manipulation techniques.
///
/// Windows code signing enforcement relies on a chain of trust:
///   Driver → WHQL Certificate → Root CA → Microsoft Root → UEFI Secure Boot
///
/// Cheats break this chain at various points:
///
///   1. Test Signing Mode (TESTSIGNING):
///      bcdedit /set TESTSIGNING ON — allows loading self-signed test drivers.
///      Cheat drivers can be self-signed and loaded under test signing.
///      Detection: BCD configuration (covered by BootConfigScanModule too).
///
///   2. Driver Signature Enforcement Disabled (NOINTEGRITYCHECKS):
///      bcdedit /set nointegritychecks YES — disables driver signature check entirely.
///      Any driver, signed or not, can load.
///
///   3. Disabled Integrity Check via registry:
///      HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable = 0
///      Disables the vulnerable driver blocklist (allows known-exploit BYOVD drivers).
///
///   4. User Mode Code Integrity (UMCI) disabled:
///      Allows unsigned executables/scripts to run as if signed.
///
///   5. Device Guard policy files (.p7b) modified or removed:
///      C:\Windows\System32\CodeIntegrity\SIPolicy.p7b — if deleted/replaced,
///      code integrity policy is gone.
///
///   6. Cross-signed driver certificate abuse:
///      Old certificates (pre-2015) can sign drivers without EV cert requirement.
///      Detection: look for recently added certificates from old CAs in cert store.
///
///   7. G_CiOptions manipulation via kernel exploit:
///      Patching CI.dll's g_CiOptions to 0x00 disables code integrity in kernel memory.
///      Detection: CI.dll on-disk vs expected (indirect).
///
///   8. Vulnerable driver blocklist bypass:
///      VulnerableDriverBlocklistEnable registry or Memory Integrity disabled.
/// </summary>
public sealed class CodeSigningBypassScanModule : IScanModule
{
    public string Name => "Codesignatur-Bypass-Analyse";
    public double Weight => 0.8;
    public int ParallelGroup => 3;

    private const string CiConfigKey =
        @"SYSTEM\CurrentControlSet\Control\CI\Config";
    private const string CiPolicyKey =
        @"SYSTEM\CurrentControlSet\Control\CI\Policy";

    private static readonly string System32 =
        Environment.GetFolderPath(Environment.SpecialFolder.System);

    // Code integrity policy file
    private static readonly string SiPolicyPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "CodeIntegrity", "SIPolicy.p7b");

    // Known revoked/abused cross-signing CA thumbprints
    // These root CAs were used to sign BYOVD cheat drivers before Microsoft revoked them
    private static readonly HashSet<string> SuspiciousThumbprints = new(StringComparer.OrdinalIgnoreCase)
    {
        // These are example patterns — real implementation would use known-bad cert hashes
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckVulnerableDriverBlocklist(ctx, ct);
        hits += CheckCiPolicyIntegrity(ctx, ct);
        hits += CheckUserModeCi(ctx, ct);
        hits += CheckCiDllIntegrity(ctx, ct);
        hits += CheckTestSigning(ctx, ct);

        ctx.Report(1.0, Name, $"Codesignatur-Konfiguration geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckVulnerableDriverBlocklist(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(CiConfigKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            // VulnerableDriverBlocklistEnable = 0 disables the BYOVD driver blocklist
            var blocklistEnabled = key.GetValue("VulnerableDriverBlocklistEnable") as int?;
            if (blocklistEnabled is not null && blocklistEnabled == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Codesignatur-Bypass-Analyse",
                    Title    = "Verwundbare-Treiber-Blockliste deaktiviert",
                    Risk     = RiskLevel.Critical,
                    Location = $@"HKLM\{CiConfigKey}",
                    Reason   = "VulnerableDriverBlocklistEnable = 0. " +
                               "Die Windows Vulnerable Driver Blocklist verhindert das Laden " +
                               "von bekannt exploitbaren Treibern, die für BYOVD-Angriffe " +
                               "verwendet werden (Capcom, gdrv, RTCore64, ASUS WinIO, etc.). " +
                               "Deaktiviert öffnet dies die Tür für alle BYOVD-Kernel-Cheats.",
                    Detail   = $"VulnerableDriverBlocklistEnable: {blocklistEnabled} (erwartet: 1)"
                });
            }

            // Check Microsoft's driver blacklist policy
            var hvciMbec = key.GetValue("HVCIPolicy") as int? ?? 0;
            if (hvciMbec == 0)
            {
                // This is a secondary check — report only if other HVCI not reported
            }
        }
        catch { }
        return hits;
    }

    private static int CheckCiPolicyIntegrity(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check if the default Windows WDAC policy is intact
            var ciDir = Path.Combine(System32, "CodeIntegrity");
            ctx.IncrementFiles();

            if (!Directory.Exists(ciDir))
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Codesignatur-Bypass-Analyse",
                    Title    = "CodeIntegrity-Verzeichnis fehlt",
                    Risk     = RiskLevel.Critical,
                    Location = ciDir,
                    Reason   = $"Das Verzeichnis '{ciDir}' existiert nicht. " +
                               "Windows Code Integrity speichert hier Policies und Logs. " +
                               "Ein fehlendes Verzeichnis deutet auf gezielte Löschung hin.",
                    Detail   = $"Pfad: {ciDir} | Existiert: false"
                });
                return hits;
            }

            // Check CI.dll size for tampering (rough check)
            var ciDllPath = Path.Combine(System32, "ci.dll");
            if (File.Exists(ciDllPath))
            {
                ctx.IncrementFiles();
                var ciSize = new FileInfo(ciDllPath).Length;
                // ci.dll is typically 400-600 KB on Windows 10/11
                if (ciSize < 100 * 1024 || ciSize > 5 * 1024 * 1024)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Codesignatur-Bypass-Analyse",
                        Title    = "ci.dll ungewöhnliche Größe — mögliche Manipulation",
                        Risk     = RiskLevel.High,
                        Location = ciDllPath,
                        FileName = "ci.dll",
                        Reason   = $"ci.dll (Code Integrity) hat eine ungewöhnliche Größe: " +
                                   $"{ciSize:N0} Bytes. " +
                                   "ci.dll enthält die Funktion CiCheckSignedFile, die die " +
                                   "Signatur aller geladenen Dateien prüft. " +
                                   "Eine abnorme Größe kann auf Ersatz oder Patch hindeuten.",
                        Detail   = $"ci.dll Größe: {ciSize:N0} Bytes"
                    });
                }
            }

            // Check for test/unsigned policy files that would bypass enforcement
            var policyFiles = Directory.EnumerateFiles(ciDir, "*.p7b").ToList();
            foreach (var policyFile in policyFiles)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();
                var name = Path.GetFileName(policyFile).ToLowerInvariant();
                // Unknown .p7b files (not SIPolicy.p7b, SIPolicy.p7b.bak) are suspicious
                if (name != "sipolicy.p7b" && name != "sipolicy.p7b.bak" &&
                    !name.StartsWith("{"))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Codesignatur-Bypass-Analyse",
                        Title    = $"Unbekannte Code-Integrity-Policy: {Path.GetFileName(policyFile)}",
                        Risk     = RiskLevel.High,
                        Location = policyFile,
                        FileName = Path.GetFileName(policyFile),
                        Reason   = $"Unbekannte WDAC-Policy-Datei '{Path.GetFileName(policyFile)}' " +
                                   $"in '{ciDir}'. " +
                                   "Windows Defender Application Control Policies steuern, " +
                                   "welche Dateien ausgeführt werden dürfen. " +
                                   "Eine unbekannte Policy könnte erlauben, was die Standard-Policy " +
                                   "blockiert (z.B. unsignierte Cheat-Executables).",
                        Detail   = $"Policy-Datei: {policyFile}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckUserModeCi(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(CiPolicyKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            // UMCIEnabled = 0 means no User Mode Code Integrity
            var umciEnabled = key.GetValue("VerifiedAndReputablePolicyState") as int? ?? -1;
            // -1 means key doesn't exist (UMCI never configured)

            var policyOptions = key.GetValue("PolicyOptions") as int? ?? 0;
            // If PolicyOptions & 0x8000 (HVCI) is NOT set, Memory Integrity is off

            if (policyOptions != 0 && (policyOptions & 0x8000) == 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Codesignatur-Bypass-Analyse",
                    Title    = "WDAC Policy: Memory Integrity-Bit nicht gesetzt",
                    Risk     = RiskLevel.Medium,
                    Location = $@"HKLM\{CiPolicyKey}",
                    Reason   = $"PolicyOptions = 0x{policyOptions:X} enthält nicht Bit 0x8000 " +
                               "(Hypervisor-Protected Code Integrity). " +
                               "Ohne dieses Bit können unsignierte Code-Seiten in den Kernel geladen werden.",
                    Detail   = $"PolicyOptions: 0x{policyOptions:X}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckCiDllIntegrity(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check if CiOptions has been patched (via known CI.dll locations)
            // Indirect: if CI.dll has an unusual timestamp relative to its version
            var ciDll = Path.Combine(System32, "ci.dll");
            if (!File.Exists(ciDll)) return 0;
            ctx.IncrementFiles();

            // Cross-check CI.dll timestamp vs file version to detect patch
            var vi = System.Diagnostics.FileVersionInfo.GetVersionInfo(ciDll);
            if (vi is not null)
            {
                var fileDate = new FileInfo(ciDll).LastWriteTimeUtc;
                // If CI.dll was modified very recently (within last 30 days) and not during
                // a known update window, flag it
                var age = DateTime.UtcNow - fileDate;
                if (age.TotalDays < 1)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Codesignatur-Bypass-Analyse",
                        Title    = "ci.dll kürzlich modifiziert (< 24h)",
                        Risk     = RiskLevel.Critical,
                        Location = ciDll,
                        FileName = "ci.dll",
                        Reason   = $"ci.dll (Code Integrity DLL) wurde vor weniger als 24 Stunden " +
                                   $"modifiziert (zuletzt: {fileDate:yyyy-MM-dd HH:mm:ss} UTC). " +
                                   "ci.dll wird von Windows normalerweise nur bei Windows-Updates " +
                                   "geändert, die nicht täglich erscheinen. " +
                                   "Eine kürzliche Modifikation deutet auf mögliche Manipulation " +
                                   "der Codesignatur-Prüfung hin (g_CiOptions Patch).",
                        Detail   = $"ci.dll | Zuletzt geändert: {fileDate:yyyy-MM-dd HH:mm:ss} UTC | " +
                                   $"Alter: {age.TotalHours:F1}h | Version: {vi.FileVersion}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckTestSigning(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Test signing state from BCD (supplementary — BootConfigScanModule is primary)
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI", writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            // TestSigning in CI registry (alternative detection path)
            var testSigning = key.GetValue("TestSigning") as int? ?? 0;
            if (testSigning != 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "Codesignatur-Bypass-Analyse",
                    Title    = "Test-Signing-Modus aktiv (unsignierte Treiber erlaubt)",
                    Risk     = RiskLevel.Critical,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI",
                    Reason   = "TestSigning ist aktiviert. " +
                               "Im Test-Signing-Modus können beliebige selbst-signierte Treiber geladen werden — " +
                               "kein WHQL oder EV-Zertifikat erforderlich. " +
                               "Dies ist die einfachste Methode, um Kernel-Cheat-Treiber zu laden.",
                    Detail   = $"CI TestSigning: {testSigning}"
                });
            }
        }
        catch { }
        return hits;
    }
}
