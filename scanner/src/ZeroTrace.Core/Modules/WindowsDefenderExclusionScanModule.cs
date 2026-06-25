using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans Windows Defender (and other AV product) exclusion lists for entries
/// added by cheat tools or loaders.
///
/// Cheats routinely add AV exclusions before injecting to prevent their DLLs
/// from being quarantined. Paths in user-writable locations (Temp, Downloads,
/// AppData, Desktop) or process names matching cheat infrastructure are highly
/// suspicious. Legitimate software rarely needs to exclude itself from AV —
/// and when it does, it installs to Program Files and uses signed binaries.
///
/// Detection approach:
///   1. Windows Defender exclusion paths — HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
///   2. Windows Defender exclusion processes — \Exclusions\Processes
///   3. Windows Defender exclusion extensions — \Exclusions\Extensions (e.g. .che, .sys added)
///   4. Defender real-time protection disabled via policy
///   5. MpPreference tamper-protection bypass indicators
/// </summary>
public sealed class WindowsDefenderExclusionScanModule : IScanModule
{
    public string Name => "AV-Ausschlüsse";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    // Suspicious path fragments — user-writable locations or cheat-named dirs
    private static readonly string[] SuspiciousPathFragments =
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\desktop\",
        @"\appdata\local\temp\", @"\appdata\roaming\",
        // Known cheat directory names
        "cheat", "hack", "inject", "spoofer", "hwid", "loader", "bypass",
        "aimbot", "wallhack", "esp", "radar", "triggerbot", "rapidfire",
        "kiddion", "2take1", "cherax", "ozark", "tsunami", "rxce",
        "gamesense", "onetap", "neverlose", "fatality", "aimware",
        "fecurity", "aimlabs_cheat", "valorhack", "apexhack",
        "memprocfs", "pcileech", "leechcore",
        "evilcheats", "gamerpride", "exvalid", "ohwow", "rustez",
        "predatorlegends", "carbonstrike", "luciddreams",
    };

    // Suspicious extension exclusions — cheat tools often use these
    private static readonly string[] SuspiciousExtensions =
    {
        ".che", ".cheat", ".hack", ".inject", ".loader",
        ".gg",  // sometimes used by cheat license files
    };

    // Suspicious process name fragments
    private static readonly string[] SuspiciousProcessFragments =
    {
        "inject", "loader", "cheat", "hack", "spoof", "bypass",
        "kiddion", "cherax", "ozark", "tsunami", "2take1",
        "aimbot", "triggerbot", "memprocfs", "pcileech",
        "evilcheats", "gamerpride", "predatorlegend",
    };

    private static readonly string[] DefenderExclusionKeys =
    {
        @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
        @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
        @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
        @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
        @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        CheckExclusions(ctx, ct);
        CheckDefenderDisabled(ctx, ct);
        CheckTamperProtection(ctx, ct);
        ctx.Report(1.0, "AV-Ausschlüsse", "AV-Ausschluss-Analyse abgeschlossen");
        return Task.CompletedTask;
    }

    private void CheckExclusions(ScanContext ctx, CancellationToken ct)
    {
        foreach (var keyPath in DefenderExclusionKeys)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
                if (key is null) continue;

                bool isProcessKey  = keyPath.Contains("Processes",  StringComparison.OrdinalIgnoreCase);
                bool isExtKey      = keyPath.Contains("Extensions", StringComparison.OrdinalIgnoreCase);

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    var entryLower = valueName.ToLowerInvariant();

                    bool suspicious = false;
                    string reason = "";

                    if (isExtKey)
                    {
                        suspicious = SuspiciousExtensions.Any(e =>
                            entryLower.TrimStart('.') == e.TrimStart('.'));
                        reason = $"Ungewöhnliche Dateiendung von AV-Scan ausgeschlossen: '{valueName}'";
                    }
                    else if (isProcessKey)
                    {
                        suspicious = SuspiciousProcessFragments.Any(f =>
                            entryLower.Contains(f));
                        reason = $"Prozess von AV-Scan ausgeschlossen: '{valueName}'";
                    }
                    else
                    {
                        // Path exclusion — check for user-writable or suspicious paths
                        suspicious = IsSuspiciousPath(entryLower);
                        reason = $"Pfad von AV-Scan ausgeschlossen: '{valueName}'";
                    }

                    if (!suspicious) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtiger AV-Ausschluss: {Path.GetFileName(valueName)}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{keyPath}",
                        FileName = valueName,
                        Reason   = reason + " — Cheat-Software fügt häufig AV-Ausschlüsse " +
                                   "vor der Injektion hinzu, um Erkennung zu umgehen.",
                        Detail   = $"Registrierungspfad: HKLM\\{keyPath}\\{valueName}"
                    });
                }
            }
            catch { }
        }
    }

    private static bool IsSuspiciousPath(string pathLower)
    {
        // Always flag user-writable OS paths
        if (pathLower.Contains(@"\temp\") || pathLower.Contains(@"\tmp\") ||
            pathLower.Contains(@"\downloads\") || pathLower.Contains(@"\desktop\") ||
            pathLower.Contains(@"\appdata\local\temp"))
            return true;

        // Flag AppData if not a known legitimate app
        if (pathLower.Contains(@"\appdata\"))
        {
            // Known legitimate apps that live in AppData — skip them
            var knownLegit = new[] { "discord", "spotify", "slack", "teams", "onedrive",
                                      "chrome", "firefox", "edge", "steam", "epic" };
            if (!knownLegit.Any(l => pathLower.Contains(l)))
                return true;
        }

        return SuspiciousPathFragments.Any(f => pathLower.Contains(f));
    }

    private static void CheckDefenderDisabled(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            // Check if Defender real-time protection is disabled via policy
            using var policyKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows Defender", writable: false);
            if (policyKey is not null)
            {
                var disableAV = policyKey.GetValue("DisableAntiVirus");
                if (disableAV is int dav && dav == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "AV-Ausschlüsse",
                        Title    = "Windows Defender per Richtlinie deaktiviert",
                        Risk     = RiskLevel.Critical,
                        Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
                        Reason   = "Windows Defender AntiVirus wurde über eine Gruppenrichtlinie " +
                                   "vollständig deaktiviert (DisableAntiVirus=1). " +
                                   "Cheats und Rootkits deaktivieren AV, bevor sie injizieren.",
                        Detail   = "DisableAntiVirus = 1"
                    });
                }

                using var rtpKey = policyKey.OpenSubKey("Real-Time Protection", writable: false);
                if (rtpKey is not null)
                {
                    var disableRTP = rtpKey.GetValue("DisableRealtimeMonitoring");
                    if (disableRTP is int drtp && drtp == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "AV-Ausschlüsse",
                            Title    = "Defender Echtzeit-Schutz deaktiviert",
                            Risk     = RiskLevel.High,
                            Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                            Reason   = "Der Windows Defender Echtzeit-Schutz wurde per Richtlinie " +
                                       "deaktiviert. Dies ist ein typisches Vorgehen von Cheat-Loadern " +
                                       "und BYOVD-Exploits.",
                            Detail   = "DisableRealtimeMonitoring = 1"
                        });
                    }
                }
            }
        }
        catch { }
    }

    private static void CheckTamperProtection(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            // Tamper Protection state: 0=Disabled, 1=Enabled, 5=Enabled (enterprise)
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Features", writable: false);
            if (key is null) return;

            var tp = key.GetValue("TamperProtection");
            if (tp is int tpVal && tpVal == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "AV-Ausschlüsse",
                    Title    = "Defender Manipulationsschutz deaktiviert",
                    Risk     = RiskLevel.High,
                    Location = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Features",
                    Reason   = "Der Windows Defender Manipulationsschutz (Tamper Protection) ist " +
                               "deaktiviert (TamperProtection=0). Wenn dieser Schutz fehlt, können " +
                               "Cheat-Loader die AV-Konfiguration ohne Benutzerinteraktion ändern.",
                    Detail   = "TamperProtection = 0"
                });
            }
        }
        catch { }
    }
}
