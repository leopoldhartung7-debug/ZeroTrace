using Microsoft.Win32;
using System.Diagnostics;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Driver Signature Enforcement (DSE) bypass / disabling.
///
/// DSE is the kernel feature that requires loaded drivers to be Authenticode-signed
/// by a Microsoft-trusted CA. Cheats use BYOVD (Bring Your Own Vulnerable Driver)
/// attacks to disable DSE so they can load arbitrary unsigned drivers (cheat
/// drivers, DMA driver shims). Common DSE bypass paths:
///
///   1. bcdedit /set testsigning on            — Test Signing Mode
///   2. bcdedit /set nointegritychecks on      — NoIntegrityChecks (removed in newer Windows)
///   3. BCD element 0x16000048 (TESTSIGNING)
///   4. NtSetSystemEnvironmentValueEx → tweak CI.dll g_CiOptions in memory (vulnerable-driver class)
///   5. HKLM\SYSTEM\CurrentControlSet\Control\CI\Config — Code Integrity policy edits
///   6. Reduced CI policies via SecureBoot disabled
///
/// This module reports on every persistent state that indicates DSE has been or
/// could be circumvented — both Ocean and detect.ac flag any of these on a
/// scanned system as Critical because they have no legitimate user-facing reason
/// to be set.
/// </summary>
public sealed class DriverSignatureEnforcementScanModule : IScanModule
{
    public string Name => "Driver Signature Enforcement (DSE) Bypass Detection";
    public double Weight => 0.75;
    public int ParallelGroup => 3;

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            CheckTestSigningMode(ctx);
            CheckBcdElements(ctx);
            CheckCiPolicy(ctx);
            CheckSecureBoot(ctx);
            CheckRecentBcdeditUse(ctx);
        }, ct);
    }

    private static void CheckTestSigningMode(ScanContext ctx)
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\CI");
            // CI policy entries
            if (key is not null)
            {
                ctx.IncrementRegistryKeys();
                var protectedMode = key.GetValue("ProtectedMode") as int?;
                if (protectedMode is 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Driver Signature Enforcement (DSE) Bypass Detection",
                        Title    = "Code Integrity: ProtectedMode = 0",
                        Risk     = RiskLevel.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\ProtectedMode",
                        FileName = "CI",
                        Reason   = "Code Integrity ProtectedMode ist auf 0 gesetzt — schaltet wichtige " +
                                   "CI-Schutzmechanismen ab. Kein legitimes Programm setzt diesen Wert; " +
                                   "Cheat-Tools (insbesondere DMA-Loader) deaktivieren dies, um unsignierte " +
                                   "Treiber zu laden.",
                        Detail   = "ProtectedMode = 0"
                    });
                }
            }
        }
        catch { }

        try
        {
            // SYSTEM\Setup\SystemSetupInProgress = 1 lifts DSE during install
            using RegistryKey? setupKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\Setup");
            if (setupKey is not null)
            {
                var inProgress = setupKey.GetValue("SystemSetupInProgress") as int?;
                if (inProgress is 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Driver Signature Enforcement (DSE) Bypass Detection",
                        Title    = "SystemSetupInProgress=1 — DSE während Setup deaktiviert",
                        Risk     = RiskLevel.Critical,
                        Location = @"HKLM\SYSTEM\Setup\SystemSetupInProgress",
                        Reason   = "Windows befindet sich angeblich im Setup-Modus (SystemSetupInProgress=1) " +
                                   "— in diesem Zustand erzwingt Windows keine Treibersignaturen. Cheats " +
                                   "missbrauchen dieses Flag, um permanent unsignierte Treiber laden zu können.",
                        Detail   = "SystemSetupInProgress = 1"
                    });
                }
            }
        }
        catch { }
    }

    private static void CheckBcdElements(ScanContext ctx)
    {
        // BCD is stored in the registry under HKLM\BCD00000000 — but is not
        // directly readable. Use bcdedit via shell for the canonical readout.
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName  = "bcdedit.exe",
                Arguments = "/enum {current}",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };

            using var proc = Process.Start(psi);
            if (proc is null) return;
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(10000);

            string lower = output.ToLowerInvariant();

            if (System.Text.RegularExpressions.Regex.IsMatch(lower,
                @"testsigning\s+yes"))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Driver Signature Enforcement (DSE) Bypass Detection",
                    Title    = "BCD: testsigning = Yes (Test Signing Mode aktiv)",
                    Risk     = RiskLevel.Critical,
                    Location = "BCD {current} testsigning",
                    Reason   = "Test Signing Mode ist aktiviert (bcdedit /set testsigning on). " +
                               "Im Test Signing Mode lädt Windows Treiber mit beliebigen, auch " +
                               "selbst-erstellten Zertifikaten — die Standard-Methode um Cheat-Treiber " +
                               "zu laden. Auch der Watermark 'Test Mode' wird auf dem Desktop angezeigt.",
                    Detail   = "BCD-Eintrag {current} | testsigning = Yes"
                });
            }

            if (System.Text.RegularExpressions.Regex.IsMatch(lower,
                @"nointegritychecks\s+yes"))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Driver Signature Enforcement (DSE) Bypass Detection",
                    Title    = "BCD: nointegritychecks = Yes (DSE komplett aus)",
                    Risk     = RiskLevel.Critical,
                    Location = "BCD {current} nointegritychecks",
                    Reason   = "Driver Signature Enforcement ist komplett deaktiviert. Beliebige " +
                               "unsignierte Treiber können vom Kernel geladen werden. Kein legitimes " +
                               "Endbenutzer-Szenario rechtfertigt diese Einstellung.",
                    Detail   = "BCD-Eintrag {current} | nointegritychecks = Yes"
                });
            }

            if (System.Text.RegularExpressions.Regex.IsMatch(lower,
                @"disable_integrity_checks") ||
                lower.Contains("disableintegritychecks"))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Driver Signature Enforcement (DSE) Bypass Detection",
                    Title    = "BCD: DisableIntegrityChecks aktiv",
                    Risk     = RiskLevel.High,
                    Location = "BCD loadoptions DISABLE_INTEGRITY_CHECKS",
                    Reason   = "BCD-Loadoptions enthält DISABLE_INTEGRITY_CHECKS — alte aber " +
                               "noch funktionierende Methode zur DSE-Umgehung.",
                    Detail   = "Boot loadoptions contains DISABLE_INTEGRITY_CHECKS"
                });
            }
        }
        catch { }
    }

    private static void CheckCiPolicy(ScanContext ctx)
    {
        // \Windows\System32\CodeIntegrity\SiPolicy.p7b or .cip files —
        // unusual extra policy files indicate WDAC custom policy installed
        try
        {
            string ciDir = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "CodeIntegrity");
            if (!System.IO.Directory.Exists(ciDir)) return;

            foreach (string file in System.IO.Directory.GetFiles(ciDir))
            {
                ctx.IncrementFiles();
                string name = System.IO.Path.GetFileName(file).ToLowerInvariant();
                if (name == "sipolicy.p7b" || name == "driver.stl") continue;
                if (!name.EndsWith(".p7b") && !name.EndsWith(".cip")) continue;

                var info = new System.IO.FileInfo(file);
                ctx.AddFinding(new Finding
                {
                    Module   = "Driver Signature Enforcement (DSE) Bypass Detection",
                    Title    = $"Unbekannte WDAC-CI-Policy-Datei: {name}",
                    Risk     = RiskLevel.High,
                    Location = file,
                    FileName = name,
                    Reason   = $"Unerwartete Code-Integrity-Policy-Datei '{name}' im " +
                               $"CodeIntegrity-Verzeichnis. Standardmäßig liegt dort nur sipolicy.p7b. " +
                               "Custom WDAC-Policies können von Cheats genutzt werden, um " +
                               "Sperrlisten für vulnerable Treiber abzuschwächen.",
                    Detail   = $"Datei: {file} | Größe: {info.Length} | " +
                               $"Geändert: {info.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss}Z"
                });
            }
        }
        catch { }
    }

    private static void CheckSecureBoot(ScanContext ctx)
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            if (key is null)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Driver Signature Enforcement (DSE) Bypass Detection",
                    Title    = "Secure Boot Status nicht verfügbar",
                    Risk     = RiskLevel.Medium,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
                    Reason   = "Secure-Boot-Statusschlüssel fehlt — System läuft entweder im Legacy " +
                               "BIOS-Modus oder Secure Boot ist abgeschaltet. Ohne Secure Boot kann " +
                               "ein Bootkit signierte aber vulnerable Treiber laden, um DSE zu umgehen.",
                    Detail   = "SecureBoot\\State Schlüssel nicht vorhanden"
                });
                return;
            }

            ctx.IncrementRegistryKeys();
            var ubre = key.GetValue("UEFISecureBootEnabled") as int?;
            if (ubre is not 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Driver Signature Enforcement (DSE) Bypass Detection",
                    Title    = "Secure Boot ist deaktiviert",
                    Risk     = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled",
                    Reason   = "UEFISecureBootEnabled = " + (ubre?.ToString() ?? "<null>") +
                               ". Mit ausgeschaltetem Secure Boot kann der Bootloader " +
                               "ausgetauscht werden, um DSE bei Boot zu deaktivieren — die " +
                               "vollständige Voraussetzung für Boot-Time-Cheats/Spoofer.",
                    Detail   = "UEFISecureBootEnabled = " + (ubre?.ToString() ?? "<missing>")
                });
            }
        }
        catch { }
    }

    private static void CheckRecentBcdeditUse(ScanContext ctx)
    {
        // PowerShell history grep is handled in PowerShellHistoryDeepScanModule —
        // here we look for bcdedit invocation in command-line history of running
        // processes (already covered elsewhere). Instead, check Prefetch for
        // BCDEDIT.EXE-* which proves recent invocation.
        try
        {
            string prefetch = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "..", "Prefetch");
            prefetch = System.IO.Path.GetFullPath(prefetch);
            if (!System.IO.Directory.Exists(prefetch)) return;

            string[] files = System.IO.Directory.GetFiles(prefetch, "BCDEDIT.EXE-*.pf");
            if (files.Length == 0) return;

            DateTime mostRecent = DateTime.MinValue;
            foreach (string f in files)
            {
                var info = new System.IO.FileInfo(f);
                if (info.LastWriteTimeUtc > mostRecent) mostRecent = info.LastWriteTimeUtc;
            }

            // Only flag if executed within last 30 days
            if ((DateTime.UtcNow - mostRecent).TotalDays > 30) return;

            ctx.AddFinding(new Finding
            {
                Module   = "Driver Signature Enforcement (DSE) Bypass Detection",
                Title    = $"bcdedit.exe wurde kürzlich ausgeführt ({mostRecent:yyyy-MM-dd})",
                Risk     = RiskLevel.Medium,
                Location = files[0],
                FileName = "BCDEDIT.EXE",
                Reason   = $"Prefetch-Eintrag für bcdedit.exe (zuletzt {mostRecent:yyyy-MM-dd HH:mm} UTC) " +
                           "innerhalb der letzten 30 Tage. bcdedit wird üblicherweise nur einmalig " +
                           "von Admins genutzt — frische Ausführungen korrelieren stark mit DSE-Bypass-" +
                           "Versuchen (testsigning on / nointegritychecks on).",
                Detail   = $"Prefetch-Dateien: {files.Length} | Neueste Ausführung: {mostRecent:yyyy-MM-dd HH:mm:ss}Z"
            });
        }
        catch { }
    }
}
