using System.Diagnostics.Eventing.Reader;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Read-only timeline module. Answers two questions that matter for an
/// anti-cheat host check:
///   1) Was the real-time virus protection (Windows Defender) switched OFF and
///      back ON? Cheaters routinely disable protection while injecting, then
///      re-enable it. Reported with the exact times.
///   2) When was the PC last powered off and on? Useful context (e.g. a reboot
///      to load a kernel-mode cheat driver).
/// Everything is read from the Windows event log. Nothing is changed, and no
/// content beyond protection-state and power events is collected. All failures
/// (no permission, channel missing) degrade to a short informational note.
/// </summary>
public sealed class SecurityTimelineScanModule : IScanModule
{
    public string Name => "System & Schutz";
    public double Weight => 0.5;

    private const string DefenderLog = "Microsoft-Windows-Windows Defender/Operational";
    private const string SystemLog = "System";
    private static readonly TimeSpan Window = TimeSpan.FromDays(30);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ScanDefenderToggles(ctx, ct);
        ctx.Report(0.34, "Echtzeitschutz", "Schutzstatus-Verlauf geprueft");

        ScanCodeIntegrity(ctx);
        ctx.Report(0.67, "Code-Integritaet", "Treiber-Signaturpruefung geprueft");

        ScanPowerTimeline(ctx, ct);
        ctx.Report(1.0, "An/Aus", "System-An/Aus-Verlauf geprueft");
        return Task.CompletedTask;
    }

    // --- driver-signing bypass: test-signing / code integrity ------------------

    [System.Runtime.InteropServices.DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int infoClass, ref CodeIntegrityInfo info, int len, out int ret);

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct CodeIntegrityInfo { public uint Length; public uint Options; }

    private void ScanCodeIntegrity(ScanContext ctx)
    {
        const int SystemCodeIntegrityInformation = 103;
        const uint CODEINTEGRITY_ENABLED = 0x01;
        const uint CODEINTEGRITY_TESTSIGN = 0x02;

        uint options;
        try
        {
            var info = new CodeIntegrityInfo { Length = 8 };
            int status = NtQuerySystemInformation(SystemCodeIntegrityInformation, ref info, 8, out _);
            if (status != 0) return; // could not query -> stay silent
            options = info.Options;
        }
        catch { return; }

        bool enabled = (options & CODEINTEGRITY_ENABLED) != 0;
        bool testSign = (options & CODEINTEGRITY_TESTSIGN) != 0;

        if (testSign)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Test-Signing aktiv (Treiber-Signatur-Bypass)",
                Risk = RiskLevel.High,
                Location = "Code Integrity",
                Reason = "Der Test-Signing-Modus ist aktiv. Damit lassen sich auch nicht " +
                         "vertrauenswuerdig signierte Kernel-Treiber laden – ein gaengiger Weg, " +
                         "die Treiber-Signaturpruefung zu umgehen und Kernel-Cheats zu starten.",
                Detail = "bcdedit-Flag testsigning. Fuer normalen Spielbetrieb nicht noetig."
            });
        }
        else if (!enabled)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Code-Integritaet deaktiviert",
                Risk = RiskLevel.High,
                Location = "Code Integrity",
                Reason = "Die Kernel-Code-Integritaet (Signaturpruefung) ist nicht aktiv. " +
                         "Unsignierte Treiber koennen geladen werden – typischer Bypass fuer " +
                         "Kernel-Cheats/Spoofer.",
                Detail = "Empfehlung: Secure Boot + Speicher-Integritaet (HVCI) aktivieren."
            });
        }
        else
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Treiber-Signaturpruefung aktiv",
                Risk = RiskLevel.Low,
                Location = "Code Integrity",
                Reason = "Code-Integritaet aktiv, kein Test-Signing. Unsignierte Kernel-Treiber " +
                         "werden blockiert (gutes Zeichen)."
            });
        }
    }

    // --- 1) Real-time protection turned off / on -------------------------------

    private void ScanDefenderToggles(ScanContext ctx, CancellationToken ct)
    {
        // 5001 = real-time protection disabled, 5000 = enabled,
        // 5007 = configuration changed, 5013 = tamper protection blocked a change.
        const string xpath =
            "*[System[(EventID=5001 or EventID=5000 or EventID=5007 or EventID=5013)]]";

        var disabled = new List<DateTime>();
        var enabled = new List<DateTime>();
        int configChanges = 0, tamperBlocks = 0;
        bool readAny = false;

        try
        {
            foreach (var rec in ReadRecent(DefenderLog, xpath, 200, ct))
            {
                readAny = true;
                var when = rec.TimeCreated?.ToLocalTime();
                if (when is null || DateTime.Now - when.Value > Window) { rec.Dispose(); continue; }
                switch (rec.Id)
                {
                    case 5001: disabled.Add(when.Value); break;
                    case 5000: enabled.Add(when.Value); break;
                    case 5007: configChanges++; break;
                    case 5013: tamperBlocks++; break;
                }
                rec.Dispose();
            }
        }
        catch
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Schutzstatus nicht lesbar",
                Risk = RiskLevel.Low,
                Location = DefenderLog,
                Reason = "Das Defender-Ereignisprotokoll konnte nicht gelesen werden " +
                         "(fehlende Rechte oder Defender nicht aktiv). Ohne Administrator-" +
                         "rechte ist dieser Verlauf evtl. nicht verfuegbar."
            });
            return;
        }

        if (disabled.Count > 0)
        {
            string offTimes = string.Join(", ", disabled.Take(6).Select(d => d.ToString("yyyy-MM-dd HH:mm")));
            string onTimes = enabled.Count > 0
                ? string.Join(", ", enabled.Take(6).Select(d => d.ToString("yyyy-MM-dd HH:mm")))
                : "kein Wieder-Einschalten protokolliert";

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Echtzeitschutz wurde deaktiviert",
                Risk = RiskLevel.High,
                Location = DefenderLog,
                Reason = $"Der Echtzeit-Virenschutz wurde im Zeitraum {disabled.Count}x ausgeschaltet. " +
                         "Das Deaktivieren des Schutzes ist ein typisches Muster vor dem Laden eines Cheats.",
                Detail = $"Aus: {offTimes} \u00b7 Wieder an: {onTimes}" +
                         (tamperBlocks > 0 ? $" \u00b7 Manipulationsschutz blockierte {tamperBlocks}x" : "")
            });
        }
        else if (configChanges > 0 || tamperBlocks > 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Aenderungen am Schutzstatus",
                Risk = RiskLevel.Low,
                Location = DefenderLog,
                Reason = "Der Echtzeitschutz blieb aktiv, es gab aber Konfigurationsaenderungen.",
                Detail = $"Konfig-Aenderungen: {configChanges}" +
                         (tamperBlocks > 0 ? $" \u00b7 Manipulationsschutz blockierte {tamperBlocks}x" : "")
            });
        }
        else if (readAny)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Echtzeitschutz durchgehend aktiv",
                Risk = RiskLevel.Low,
                Location = DefenderLog,
                Reason = "Im geprueften Zeitraum wurde kein Deaktivieren des Echtzeitschutzes protokolliert."
            });
        }
    }

    // --- 2) System powered off / on -------------------------------------------

    private void ScanPowerTimeline(ScanContext ctx, CancellationToken ct)
    {
        // 6005 = event log started (~boot/on), 6006 = clean shutdown (off),
        // 1074 = shutdown/restart initiated, 6008 = previous shutdown unexpected,
        // 41   = kernel power (dirty/unexpected reboot).
        const string xpath =
            "*[System[(EventID=6005 or EventID=6006 or EventID=1074 or EventID=6008 or EventID=41)]]";

        var lines = new List<string>();
        try
        {
            foreach (var rec in ReadRecent(SystemLog, xpath, 60, ct))
            {
                var when = rec.TimeCreated?.ToLocalTime();
                if (when is null || DateTime.Now - when.Value > Window) { rec.Dispose(); continue; }
                string what = rec.Id switch
                {
                    6005 => "AN (Hochfahren)",
                    6006 => "AUS (sauber heruntergefahren)",
                    1074 => "AUS/Neustart angefordert",
                    6008 => "AUS (unerwartet)",
                    41   => "AUS (unerwartet, Kernel-Power)",
                    _    => $"Ereignis {rec.Id}"
                };
                lines.Add($"{when.Value:yyyy-MM-dd HH:mm} \u2013 {what}");
                rec.Dispose();
                if (lines.Count >= 10) break;
            }
        }
        catch
        {
            return; // System log unreadable -> skip quietly (power timeline is context only)
        }

        if (lines.Count == 0) return;

        ctx.AddFinding(new Finding
        {
            Module = Name,
            Title = "System-An/Aus-Zeitleiste",
            Risk = RiskLevel.Low,
            Location = SystemLog,
            Reason = "Letzte An-/Aus-Zeitpunkte des Rechners (nur zur Einordnung, kein Cheat-Hinweis an sich).",
            Detail = string.Join("  \u00b7  ", lines)
        });
    }

    // --- helper ----------------------------------------------------------------

    /// <summary>
    /// Reads up to <paramref name="max"/> most-recent records from a log channel
    /// matching the XPath. Newest-first. Read-only.
    /// </summary>
    private static IEnumerable<EventRecord> ReadRecent(string logName, string xpath, int max, CancellationToken ct)
    {
        var query = new EventLogQuery(logName, PathType.LogName, xpath) { ReverseDirection = true };
        using var reader = new EventLogReader(query);
        int n = 0;
        while (n++ < max)
        {
            if (ct.IsCancellationRequested) yield break;
            EventRecord? rec = reader.ReadEvent();
            if (rec is null) yield break;
            yield return rec;
        }
    }
}
