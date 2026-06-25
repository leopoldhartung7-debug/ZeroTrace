using Microsoft.Win32;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Windows Defender and antivirus tampering by cheat software.
///
/// Cheat loaders universally require disabling or weakening antivirus/EDR before
/// running because:
///   1. Cheat executables are detected as malware by most AV solutions
///   2. The injection techniques used by cheats (WriteProcessMemory + CreateRemoteThread)
///      are flagged by AMSI and behavioral detection
///
/// Common AV tampering techniques:
///   - Set-MpPreference -DisableRealtimeMonitoring $true (PowerShell)
///   - Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender (GPO disabling)
///   - Adding exclusions: HKLM\...\Exclusions\Paths, Processes
///   - Tamper Protection bypass: registry + elevation
///   - AMSI bypass: reflection-based or in-memory patching
///   - Disabling SmartScreen
///
/// This module focuses on the RESULTS of AV tampering visible in registry state,
/// complementing the PowerShell history module (which looks at the commands used).
///
/// Detection:
///   - HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1
///   - HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring
///   - HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths (non-standard entries)
///   - HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes (cheat process names)
///   - TamperProtection status in Windows Security registry
///   - Windows SmartScreen disabled
/// </summary>
public sealed class AntiVirusTamperScanModule : IScanModule
{
    public string Name => "Windows Defender / AV Manipulations-Erkennung";
    public double Weight => 0.75;
    public int ParallelGroup => 3;

    private static readonly string[] SuspiciousExclusionPatterns =
    {
        // Cheat-related path patterns
        "cheat", "hack", "aimbot", "injector", "loader",
        "gamesense", "onetap", "fatality",
        "neverlose", "skeet",
        "2take1", "kiddion",
        "spoofer", "hwid",
        "triggerbot", "bypass",
        "\\temp\\", "\\downloads\\",    // temp/downloads exclusions are suspicious
        "\\appdata\\local\\temp\\",
        "\\appdata\\roaming\\",         // broad AppData exclusion
        // Generic suspicious paths
        "c:\\users\\public\\",
        "c:\\windows\\temp\\",
    };

    private static readonly string[] SuspiciousProcessExclusions =
    {
        "cheat", "hack", "injector", "loader",
        "aimbot", "bypass", "spoofer",
        "gamesense", "onetap", "fatality",
        "kiddion", "2take1",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanDefenderPolicyDisable(ctx, ct);
        ScanDefenderRealTimeMonitoring(ctx, ct);
        ScanDefenderExclusions(ctx, ct);
        ScanTamperProtection(ctx, ct);
        ScanSmartScreen(ctx, ct);
    }

    private void ScanDefenderPolicyDisable(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            // GPO-based disabling (HKLM\SOFTWARE\Policies\Microsoft\Windows Defender)
            using var policyKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows Defender", writable: false);
            if (policyKey is null) return;

            ctx.IncrementRegistryKeys();
            int disabled = (int)(policyKey.GetValue("DisableAntiSpyware") ?? 0);
            int disabled2 = (int)(policyKey.GetValue("DisableAntiVirus") ?? 0);

            if (disabled != 0 || disabled2 != 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Windows Defender via GPO deaktiviert (DisableAntiSpyware=1)",
                    Risk     = RiskLevel.Critical,
                    Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
                    FileName = "Windows Defender Policy",
                    Reason   = "Windows Defender ist via Gruppenrichtlinie deaktiviert " +
                               "(DisableAntiSpyware=1 oder DisableAntiVirus=1). Dies ist eine klassische " +
                               "Cheat-Loader-Vorbereitung: AV via Registry-GPO deaktivieren, damit der " +
                               "Cheat-Injector nicht erkannt wird. Ocean und detect.ac flaggen dies als " +
                               "Critical.",
                    Detail   = $"DisableAntiSpyware: {disabled} | DisableAntiVirus: {disabled2}"
                });
            }

            // Also check per-feature policy keys
            string[] subKeys = { "Real-Time Protection", "Spynet", "MpEngine" };
            foreach (string sub in subKeys)
            {
                ct.ThrowIfCancellationRequested();
                using var subKey = policyKey.OpenSubKey(sub, false);
                if (subKey is null) continue;

                ctx.IncrementRegistryKeys();
                int rtDisabled = (int)(subKey.GetValue("DisableRealtimeMonitoring") ?? 0);
                if (rtDisabled != 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Defender Echtzeit-Schutz via GPO deaktiviert: {sub}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\{sub}",
                        FileName = "DisableRealtimeMonitoring",
                        Reason   = $"DisableRealtimeMonitoring in '{sub}' auf 1 gesetzt. Dieser " +
                                   "Registry-Key deaktiviert den Echtzeit-Schutz von Windows Defender. " +
                                   "Cheat-Installer setzen diesen Key als ersten Schritt der Installation.",
                        Detail   = $"Key: {sub}\\DisableRealtimeMonitoring = {rtDisabled}"
                    });
                }
            }
        }
        catch { }
    }

    private void ScanDefenderRealTimeMonitoring(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var defKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", writable: false);
            if (defKey is null) return;

            ctx.IncrementRegistryKeys();
            int rtDisabled = (int)(defKey.GetValue("DisableRealtimeMonitoring") ?? 0);
            int behavDisabled = (int)(defKey.GetValue("DisableBehaviorMonitoring") ?? 0);
            int ioavDisabled = (int)(defKey.GetValue("DisableIOAVProtection") ?? 0);

            if (rtDisabled != 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Defender Echtzeit-Schutz deaktiviert (DisableRealtimeMonitoring=1)",
                    Risk     = RiskLevel.Critical,
                    Location = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
                    FileName = "DisableRealtimeMonitoring",
                    Reason   = "Windows Defender Echtzeit-Schutz ist deaktiviert. Dies ist der " +
                               "primäre Schritt beim Cheat-Setup: ohne Echtzeit-Schutz kann der " +
                               "Cheat-Injector unerkannt laufen. Ocean und detect.ac flaggen dies " +
                               "als primäres Manipulations-Signal.",
                    Detail   = $"DisableRealtimeMonitoring: {rtDisabled} | " +
                               $"DisableBehaviorMonitoring: {behavDisabled} | " +
                               $"DisableIOAVProtection: {ioavDisabled}"
                });
            }
        }
        catch { }
    }

    private void ScanDefenderExclusions(ScanContext ctx, CancellationToken ct)
    {
        string[] exclusionKeyPaths =
        {
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes",
        };

        foreach (string keyPath in exclusionKeyPaths)
        {
            ct.ThrowIfCancellationRequested();
            bool isProcessKey = keyPath.Contains("Processes");

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath, false);
                if (key is null) continue;

                foreach (string valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    string lower = valueName.ToLowerInvariant();

                    var patterns = isProcessKey ? SuspiciousProcessExclusions : SuspiciousExclusionPatterns;
                    foreach (string pattern in patterns)
                    {
                        if (!lower.Contains(pattern.ToLowerInvariant())) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Verdächtige Defender-Ausnahme: {valueName}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{keyPath}",
                            FileName = valueName,
                            Reason   = $"Windows Defender Ausnahme für '{valueName}' enthält " +
                                       $"verdächtiges Muster '{pattern}'. Cheat-Loader fügen sich selbst " +
                                       "zu Defender-Ausnahmen hinzu, damit ihr Prozess/Pfad nicht gescannt " +
                                       "wird. Ocean und detect.ac flaggen Cheat-Keyword-Ausnahmen als Critical.",
                            Detail   = $"Ausnahme-Key: {keyPath} | Wert: {valueName} | Match: '{pattern}'"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }

    private void ScanTamperProtection(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var tpKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Features", writable: false);
            if (tpKey is null) return;

            ctx.IncrementRegistryKeys();
            int tamperProtection = (int)(tpKey.GetValue("TamperProtection") ?? 5);
            // 5 = enabled, 4 = disabled by policy, 0/1 = disabled
            if (tamperProtection is 0 or 1 or 4)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Defender Tamper Protection deaktiviert (TamperProtection={tamperProtection})",
                    Risk     = RiskLevel.High,
                    Location = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Features",
                    FileName = "TamperProtection",
                    Reason   = $"Windows Defender Tamper Protection ist deaktiviert (Wert={tamperProtection}). " +
                               "Tamper Protection verhindert, dass Software Defender-Einstellungen ändert. " +
                               "Wird von Cheat-Loaders deaktiviert, bevor sie Defender-Schutz ausschalten.",
                    Detail   = $"TamperProtection: {tamperProtection} (5=aktiv, 0/1/4=deaktiviert)"
                });
            }
        }
        catch { }
    }

    private void ScanSmartScreen(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var ssKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\System", writable: false);
            if (ssKey is null) return;

            ctx.IncrementRegistryKeys();
            int ssEnabled = (int)(ssKey.GetValue("EnableSmartScreen") ?? 1);
            if (ssEnabled == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = "Windows SmartScreen deaktiviert",
                    Risk     = RiskLevel.High,
                    Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
                    FileName = "SmartScreen",
                    Reason   = "Windows SmartScreen ist deaktiviert (EnableSmartScreen=0). SmartScreen " +
                               "warnt vor unbekannten/unsignierten Downloads. Cheat-Loader deaktivieren " +
                               "SmartScreen, damit der Download-Dialog nicht erscheint.",
                    Detail   = $"EnableSmartScreen: {ssEnabled} (0=deaktiviert)"
                });
            }
        }
        catch { }
    }
}
