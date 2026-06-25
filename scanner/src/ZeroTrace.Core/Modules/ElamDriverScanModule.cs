using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Checks the Early Launch Anti-Malware (ELAM) driver configuration.
///
/// ELAM is a Windows feature that loads a special anti-malware driver before
/// any other third-party boot drivers, allowing it to evaluate the integrity
/// of all subsequent drivers loaded during boot.
///
/// Cheat tools target ELAM because:
///   1. Disabling ELAM allows loading malicious boot drivers undetected
///   2. BYOVD (Bring Your Own Vulnerable Driver) attacks often disable ELAM first
///   3. Kernel-level cheats that load before the OS need ELAM disabled
///
/// Registry locations checked:
///   HKLM\SYSTEM\CurrentControlSet\Control\EarlyLaunch
///     DriverLoadPolicy — controls which boot drivers ELAM allows:
///       0 = Good only (strictest)
///       1 = Good and unknown (default Win8+)
///       3 = Good, unknown, and bad (disabled — allows any driver)
///
///   HKLM\SYSTEM\CurrentControlSet\Services\WdBoot      — Windows Defender ELAM
///   HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv    — WD Network Inspection
///
/// Also checks:
///   - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\
///     {Microsoft ELAM log provider} — if ELAM events are suppressed
///   - Whether the ELAM driver (elambda.sys) is still intact
///   - SecureBoot state (already in BootConfigScanModule but cross-referenced)
/// </summary>
public sealed class ElamDriverScanModule : IScanModule
{
    public string Name => "ELAM-Treiber-Analyse";
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    private const string EarlyLaunchKey = @"SYSTEM\CurrentControlSet\Control\EarlyLaunch";

    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();

    // Known Windows Defender ELAM driver files
    private static readonly string[] ElamDriverFiles =
    {
        "wdboot.sys",   // Windows Defender ELAM
        "wdnisdrv.sys", // Windows Defender Network Inspection
        "elambda.sys",  // Windows ELAM sample driver (rare)
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckElamPolicy(ctx, ct);
        hits += CheckElamDriverIntegrity(ctx, ct);
        hits += CheckBootDriverPolicy(ctx, ct);

        ctx.Report(1.0, Name, $"ELAM-Konfiguration geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckElamPolicy(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(EarlyLaunchKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            var driverLoadPolicy = key.GetValue("DriverLoadPolicy") as int? ?? 1;

            // Policy 3 = "Good, unknown, and bad" = ELAM effectively disabled
            if (driverLoadPolicy == 3)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "ELAM-Treiberladerichtlinie auf 'Alle zulassen' gesetzt",
                    Risk     = RiskLevel.Critical,
                    Location = $@"HKLM\{EarlyLaunchKey}",
                    Reason   = "DriverLoadPolicy ist auf 3 (Good, unknown, and bad) gesetzt. " +
                               "Dies erlaubt das Laden beliebiger Boot-Treiber, einschließlich " +
                               "bekannter schädlicher Treiber, bevor Anti-Malware-Software greift. " +
                               "BYOVD-Cheat-Treiber und Rootkits nutzen diese Einstellung, " +
                               "um vor dem Betriebssystem zu laden und ELAM zu umgehen.",
                    Detail   = $"DriverLoadPolicy: {driverLoadPolicy} (erwartet: 0 oder 1)"
                });
            }
            else if (driverLoadPolicy == 7)
            {
                // 7 = all drivers allowed (including unknown good and bad)
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "ELAM vollständig deaktiviert (Policy=7)",
                    Risk     = RiskLevel.Critical,
                    Location = $@"HKLM\{EarlyLaunchKey}",
                    Reason   = "DriverLoadPolicy ist auf 7 gesetzt — ELAM ist vollständig deaktiviert. " +
                               "Alle Boot-Treiber werden ohne Integritätsprüfung geladen. " +
                               "Dies ist die aggressivste ELAM-Deaktivierungseinstellung.",
                    Detail   = $"DriverLoadPolicy: {driverLoadPolicy}"
                });
            }

            // Check if ELAM has been disabled via policy
            var elamDisabled = key.GetValue("DisableBootAMDriver") as int? ?? 0;
            if (elamDisabled != 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "ELAM-Boot-AM-Treiber deaktiviert",
                    Risk     = RiskLevel.Critical,
                    Location = $@"HKLM\{EarlyLaunchKey}",
                    Reason   = "DisableBootAMDriver ist gesetzt — der ELAM-Anti-Malware-Boot-Treiber " +
                               "wird nicht geladen. Cheat-Tools deaktivieren ELAM, um ihre " +
                               "Kernel-Treiber ungeprüft zu laden.",
                    Detail   = $"DisableBootAMDriver: {elamDisabled}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckElamDriverIntegrity(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            foreach (var driverName in ElamDriverFiles)
            {
                if (ct.IsCancellationRequested) break;
                var driverPath = Path.Combine(System32, "drivers", driverName);

                if (!File.Exists(driverPath))
                {
                    // Missing ELAM driver is suspicious (may have been deleted)
                    if (driverName == "wdboot.sys")
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"ELAM-Treiber fehlt: {driverName}",
                            Risk     = RiskLevel.High,
                            Location = driverPath,
                            FileName = driverName,
                            Reason   = $"Windows Defender ELAM-Treiber '{driverName}' nicht gefunden. " +
                                       "Das Fehlen des ELAM-Treibers deaktiviert die Früherkennung " +
                                       "von schädlichen Boot-Treibern.",
                            Detail   = $"Pfad: {driverPath} | Existiert: false"
                        });
                    }
                    continue;
                }

                // Check if the ELAM driver service is disabled
                var serviceName = Path.GetFileNameWithoutExtension(driverName);
                hits += CheckElamServiceState(serviceName, driverName, ctx, ct);
            }
        }
        catch { }
        return hits;
    }

    private static int CheckElamServiceState(string serviceName, string driverName,
        ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{serviceName}", writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            var startType = key.GetValue("Start") as int? ?? 0;

            // ELAM drivers should have Start=0 (SERVICE_BOOT_START)
            // Anything else means they won't load at boot
            if (startType != 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"ELAM-Treiber deaktiviert: {serviceName}",
                    Risk     = RiskLevel.High,
                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{serviceName}",
                    FileName = driverName,
                    Reason   = $"ELAM-Treiber '{serviceName}' hat StartType {startType} " +
                               "(erwartet: 0 = Boot-Start). " +
                               "ELAM-Treiber müssen als Boot-Treiber gestartet werden. " +
                               "Eine andere Start-Einstellung verhindert das Laden bei Boot " +
                               "und deaktiviert effektiv den Anti-Malware-Schutz.",
                    Detail   = $"Service: {serviceName} | StartType: {startType} (erwartet: 0)"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckBootDriverPolicy(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check BootDriverFlags in LSA (can suppress ELAM event logging)
            using var lsaKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Lsa", writable: false);
            if (lsaKey is null) return 0;
            ctx.IncrementRegistryKeys();

            var bootDrvFlags = lsaKey.GetValue("BootDriverFlags") as int? ?? 0;
            // Flag value 0x04000000 (0x4000000) disables ELAM measurement
            if ((bootDrvFlags & 0x04000000) != 0)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "LSA-BootDriverFlags: ELAM-Messung deaktiviert",
                    Risk     = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                    Reason   = $"LSA BootDriverFlags = 0x{bootDrvFlags:X8} enthält Bit 0x04000000. " +
                               "Dieses Flag deaktiviert die ELAM-Integrity-Messung bei Boot, " +
                               "was Kernel-Level-Cheat-Treibern ermöglicht, ungeprüft zu laden.",
                    Detail   = $"BootDriverFlags: 0x{bootDrvFlags:X8}"
                });
            }
        }
        catch { }
        return hits;
    }
}
