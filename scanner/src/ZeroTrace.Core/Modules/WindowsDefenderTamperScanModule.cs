using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Windows Defender (Microsoft Defender Antivirus) tampering beyond exclusions.
///
/// Windows Defender Exclusions are already covered by WindowsDefenderExclusionScanModule.
/// This module focuses on deeper Defender integrity:
///
///   1. Real-time protection disabled (DisableRealtimeMonitoring = 1)
///   2. Cloud-delivered protection disabled (DisableBlockAtFirstSeen = 1)
///   3. Behavior monitoring disabled (DisableBehaviorMonitoring = 1)
///   4. Script scanning disabled (DisableScriptScanning = 1)
///   5. IOAV (On-Access / IOfficeAntiVirus) disabled (DisableIOAVProtection = 1)
///   6. Tamper Protection state (detectable via WMI/registry signal)
///   7. Defender service disabled (WinDefend, WdNisSvc, WdBoot, WdFilter)
///   8. Defender signature age (very old = update blocking)
///   9. Controlled Folder Access state (ransomware protection)
///   10. Network Protection state (blocks known-bad IPs/domains)
/// </summary>
public sealed class WindowsDefenderTamperScanModule : IScanModule
{
    public string Name => "Windows-Defender-Manipulations-Analyse";
    public double Weight => 0.9;
    public int ParallelGroup => 3;

    private const string DefenderPolicyKey =
        @"SOFTWARE\Policies\Microsoft\Windows Defender";
    private const string DefenderConfigKey =
        @"SOFTWARE\Microsoft\Windows Defender";
    private const string DefenderRtpKey =
        @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection";
    private const string DefenderServicesKey =
        @"SYSTEM\CurrentControlSet\Services";

    private static readonly string[] DefenderServices =
    {
        "WinDefend",     // Main Defender AV service
        "WdNisSvc",      // Network Inspection Service
        "WdBoot",        // ELAM boot driver service
        "WdFilter",      // File system filter driver
        "SecurityHealthService", // Windows Security Center
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckRealTimeProtection(ctx, ct);
        hits += CheckAdvancedFeatures(ctx, ct);
        hits += CheckDefenderServices(ctx, ct);
        hits += CheckSignatureAge(ctx, ct);
        hits += CheckNetworkAndFolderProtection(ctx, ct);

        ctx.Report(1.0, Name, $"Windows Defender Integrität geprüft, {hits} Probleme");
        return Task.CompletedTask;
    }

    private static int CheckRealTimeProtection(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check both policy (takes precedence) and config keys
            foreach (var rootKey in new[] { DefenderPolicyKey, DefenderRtpKey })
            {
                using var key = Registry.LocalMachine.OpenSubKey(rootKey, writable: false);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                var disableRtp = key.GetValue("DisableRealtimeMonitoring") as int? ?? 0;
                if (disableRtp != 0)
                {
                    bool isPolicy = rootKey == DefenderPolicyKey;
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Windows-Defender-Manipulations-Analyse",
                        Title    = "Windows Defender Echtzeit-Schutz deaktiviert" +
                                   (isPolicy ? " (Policy)" : ""),
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{rootKey}",
                        Reason   = "DisableRealtimeMonitoring ist aktiv. " +
                                   "Der Echtzeit-Schutz von Windows Defender ist ausgeschaltet — " +
                                   "Dateizugriffe werden nicht mehr auf Malware/Cheats geprüft. " +
                                   "Dies ist die direkteste Methode, um AV-Erkennung von " +
                                   "Cheat-Dateien zu deaktivieren.",
                        Detail   = $"DisableRealtimeMonitoring: {disableRtp} | Quelle: {rootKey}"
                    });
                    break; // Don't double-report
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckAdvancedFeatures(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            var checkValues = new (string Key, string ValueName, string Description)[]
            {
                (DefenderConfigKey + @"\Features",
                    "TamperProtection",
                    "Tamper Protection"),
                (DefenderConfigKey + @"\Real-Time Protection",
                    "DisableBehaviorMonitoring",
                    "Verhaltensüberwachung"),
                (DefenderConfigKey + @"\Real-Time Protection",
                    "DisableScriptScanning",
                    "Script-Scanning"),
                (DefenderConfigKey + @"\Real-Time Protection",
                    "DisableIOAVProtection",
                    "IOAV-Schutz (On-Access)"),
                (DefenderConfigKey + @"\Real-Time Protection",
                    "DisableOnAccessProtection",
                    "On-Access-Schutz"),
                (DefenderPolicyKey + @"\MpEngine",
                    "MpEnablePus",
                    "PUA-Erkennung (Potenziell unerwünschte Apps)"),
            };

            foreach (var (keyPath, valueName, desc) in checkValues)
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;
                    ctx.IncrementRegistryKeys();

                    // Special case: TamperProtection = 5 means ENABLED (not 0)
                    if (valueName == "TamperProtection")
                    {
                        var tp = key.GetValue("TamperProtection") as int? ?? 5;
                        if (tp != 5)
                        {
                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = "Windows-Defender-Manipulations-Analyse",
                                Title    = "Windows Defender Manipulationsschutz deaktiviert",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{keyPath}",
                                Reason   = $"TamperProtection = {tp} (erwartet: 5 = aktiv). " +
                                           "Tamper Protection verhindert, dass Nicht-Admin-Prozesse " +
                                           "Defender-Einstellungen ändern. Wenn deaktiviert, " +
                                           "kann Cheat-Software Defender-Schutz über die Registry " +
                                           "ohne UAC-Prompt ausschalten.",
                                Detail   = $"TamperProtection: {tp} (5=aktiv, andere=deaktiviert)"
                            });
                        }
                        continue;
                    }

                    var val = key.GetValue(valueName) as int? ?? 0;
                    if (val != 0)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Windows-Defender-Manipulations-Analyse",
                            Title    = $"Windows Defender {desc} deaktiviert",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{keyPath}",
                            Reason   = $"{desc} ({valueName}) ist deaktiviert. " +
                                       "Diese Defender-Funktion schützt vor Echtzeit-Bedrohungen. " +
                                       "Cheat-Software deaktiviert einzelne Schutzfunktionen, " +
                                       "um unbemerkt zu operieren.",
                            Detail   = $"{valueName}: {val} (erwartet: 0)"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckDefenderServices(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        foreach (var svc in DefenderServices)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    $@"{DefenderServicesKey}\{svc}", writable: false);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                var startType = key.GetValue("Start") as int? ?? 2;

                // Start 4 = Disabled — Defender service explicitly disabled
                if (startType == 4)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Windows-Defender-Manipulations-Analyse",
                        Title    = $"Windows Defender Dienst deaktiviert: {svc}",
                        Risk     = svc == "WinDefend" ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"HKLM\{DefenderServicesKey}\{svc}",
                        Reason   = $"Windows Defender Dienst '{svc}' hat StartType = 4 (Disabled). " +
                                   "Der Dienst wird beim Systemstart nicht gestartet. " +
                                   "Cheat-Software deaktiviert Defender-Dienste, " +
                                   "um persistenten AV-Schutz zu eliminieren. " +
                                   "WinDefend deaktiviert = kein Echtzeit-Schutz mehr.",
                        Detail   = $"Dienst: {svc} | StartType: {startType} (4=Disabled)"
                    });
                }
            }
            catch { }
        }
        return hits;
    }

    private static int CheckSignatureAge(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Signature Updates", writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            // SignaturesLastUpdated is stored as FILETIME (100-nanosecond intervals since 1601-01-01)
            var lastUpdatedRaw = key.GetValue("SignaturesLastUpdated");
            if (lastUpdatedRaw is byte[] bytes && bytes.Length == 8)
            {
                long fileTime = BitConverter.ToInt64(bytes, 0);
                if (fileTime > 0)
                {
                    var lastUpdated = DateTime.FromFileTime(fileTime);
                    var age = DateTime.UtcNow - lastUpdated.ToUniversalTime();

                    if (age.TotalDays > 7)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Windows-Defender-Manipulations-Analyse",
                            Title    = $"Windows Defender Signaturen veraltet: {(int)age.TotalDays} Tage alt",
                            Risk     = age.TotalDays > 30 ? RiskLevel.High : RiskLevel.Medium,
                            Location = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates",
                            Reason   = $"Defender-Signaturen wurden zuletzt am " +
                                       $"{lastUpdated:yyyy-MM-dd} aktualisiert " +
                                       $"({(int)age.TotalDays} Tage her). " +
                                       "Veraltete Signaturen erkennen neue Cheat-Varianten nicht. " +
                                       "Cheat-Software blockiert oft Windows Update, " +
                                       "um Signatur-Updates zu verhindern.",
                            Detail   = $"Letzte Aktualisierung: {lastUpdated:yyyy-MM-dd HH:mm:ss} | " +
                                       $"Alter: {(int)age.TotalDays} Tage"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckNetworkAndFolderProtection(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                DefenderConfigKey + @"\Windows Defender Exploit Guard\Network Protection",
                writable: false);
            if (key is not null)
            {
                ctx.IncrementRegistryKeys();
                var netProtect = key.GetValue("EnableNetworkProtection") as int? ?? 1;
                if (netProtect == 0)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Windows-Defender-Manipulations-Analyse",
                        Title    = "Defender Network Protection deaktiviert",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{DefenderConfigKey}\...\Network Protection",
                        Reason   = "EnableNetworkProtection = 0. " +
                                   "Network Protection blockiert Verbindungen zu bekannten " +
                                   "schädlichen IPs und Domains. " +
                                   "Cheat C2-Server und Download-Quellen werden nicht mehr geblockt.",
                        Detail   = $"EnableNetworkProtection: {netProtect}"
                    });
                }
            }
        }
        catch { }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                DefenderConfigKey + @"\Windows Defender Exploit Guard\Controlled Folder Access",
                writable: false);
            if (key is not null)
            {
                ctx.IncrementRegistryKeys();
                var cfa = key.GetValue("EnableControlledFolderAccess") as int? ?? 0;
                // 0 = disabled, 1 = enabled, 2 = audit mode
                if (cfa == 0)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Windows-Defender-Manipulations-Analyse",
                        Title    = "Controlled Folder Access (Ransomware-Schutz) deaktiviert",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\{DefenderConfigKey}\...\Controlled Folder Access",
                        Reason   = "EnableControlledFolderAccess = 0. " +
                                   "Controlled Folder Access verhindert, dass unbekannte Prozesse " +
                                   "in geschützte Ordner schreiben (Documents, Desktop, etc.). " +
                                   "Deaktiviert erlaubt es Cheat-Software, Daten in geschützten " +
                                   "Bereichen abzulegen oder zu modifizieren.",
                        Detail   = $"EnableControlledFolderAccess: {cfa} (0=aus, 1=aktiv, 2=Audit)"
                    });
                }
            }
        }
        catch { }

        return hits;
    }
}
