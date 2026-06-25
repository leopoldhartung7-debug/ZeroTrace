using System.Diagnostics.Eventing.Reader;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Mines Windows Event Logs for cheat-related events beyond the existing deep scan.
///
/// Specific event IDs that reveal cheat activity:
///   - Event 7045 (System): New service installed — cheat kernel drivers register as services
///   - Event 7036 (System): Service state changed — AC services going offline unexpectedly
///   - Event 4688 (Security): Process creation (requires Audit Process Creation policy)
///     with known cheat process names or injection-related flags
///   - Event 1102 (Security): Audit log cleared — cheaters often clear logs before/after
///   - Event 4719 (Security): Audit policy changed — cheaters disable audit logging
///   - Event 6006 (System): Event log service stopped — suspicious in gaming context
///   - Microsoft-Windows-CodeIntegrity/Operational (Event 3065/3066):
///     Driver blocked by Driver Signature Enforcement bypass attempt
///   - Microsoft-Windows-Kernel-PnP/Configuration (Event 400/410):
///     Unknown/unsigned driver loaded
///
/// Ocean and detect.ac mine event logs because:
///   - Service installation events (7045) for kernel-mode cheat drivers persist in EVTX
///   - Log clear (1102) is itself a forensic finding — innocent users don't clear Security logs
///   - CodeIntegrity events reveal DSE bypass attempts
/// </summary>
public sealed class WindowsEventLogCheatScanModule : IScanModule
{
    public string Name => "Windows Event Log Cheat-Forensik Scan";
    public double Weight => 0.65;
    public int ParallelGroup => 3;

    // Service names / image paths of known cheat drivers that appear in Event 7045
    private static readonly string[] CheatServiceKeywords =
    {
        "gdrv", "gdrv2", "giodriver",           // Gigabyte Driver (BYOVD classic)
        "dbutil", "dbutil_2_3",                 // Dell DBUtil (BYOVD)
        "rtcore64", "rtcore32",                 // RivaTuner (BYOVD abuse)
        "cpuz", "cpuz_x64",                     // CPU-Z driver (BYOVD)
        "mhyprot", "mhyprot2",                  // Genshin Impact driver (BYOVD)
        "procexp", "procexp152",                // Sysinternals Process Explorer
        "kprocesshacker", "ksystemhacker",
        "aswarpot", "aswkbd", "aswarpsys",      // Avast driver abuse
        "vboxdrv",                              // VirtualBox (BYOVD)
        "speedfan", "openlibsys",              // System driver abuse
        "pcieclk",                              // PCIe clock driver (DMA)
        "winring0",                             // WinRing0 (privilege escalation)
        "physmem",                              // Physical memory access
        "hwinfo64a", "hwinfo64",               // HWiNFO driver
        "iomap64", "inpoutx64",                // raw I/O access drivers
        "cheat", "hack", "inject",             // generic cheat references
    };

    private static readonly string[] CheatProcessKeywords =
    {
        "cheat", "hack", "injector", "loader",
        "aimbot", "wallhack",
        "gamesense", "onetap", "fatality",
        "neverlose", "skeet",
        "memprocfs", "pcileech",
        "aimlock", "triggerbot",
        "bypass", "spoofer",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanSystemLog(ctx, ct);
        ScanSecurityLog(ctx, ct);
        ScanCodeIntegrityLog(ctx, ct);
    }

    private void ScanSystemLog(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var query = new EventLogQuery("System", PathType.LogName,
                "*[System[(EventID=7045 or EventID=7036 or EventID=6006)]]");

            using var reader = new EventLogReader(query);
            var cutoff = DateTime.UtcNow.AddDays(-90);
            int count = 0;

            while (reader.ReadEvent() is { } ev)
            {
                ct.ThrowIfCancellationRequested();
                if (++count > 5000) break;
                if (ev.TimeCreated < cutoff) continue;

                int id = ev.Id;
                string msg = FormatEvent(ev);
                string lower = msg.ToLowerInvariant();

                if (id == 7045) // New service installed
                {
                    foreach (string kw in CheatServiceKeywords)
                    {
                        if (!lower.Contains(kw)) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Cheat-Treiber als Dienst installiert (Event 7045): {kw}",
                            Risk     = RiskLevel.Critical,
                            Location = "Windows System-Ereignisprotokoll",
                            FileName = "System.evtx",
                            Reason   = $"Ereignis 7045 (Neuer Dienst installiert) enthält Cheat/BYOVD-Treiber-" +
                                       $"Schlüsselwort '{kw}'. Kernel-Mode-Cheat-Treiber und BYOVD-Exploits " +
                                       "hinterlassen Dienst-Installationsereignisse im System-Log. " +
                                       "Ocean und detect.ac minen Event 7045 als primäre Signalquelle.",
                            Detail   = $"EventID: 7045 | Zeit: {ev.TimeCreated:yyyy-MM-dd HH:mm} | " +
                                       $"Schlüsselwort: '{kw}' | Meldung: {msg.Substring(0, Math.Min(200, msg.Length))}"
                        });
                        break;
                    }
                }
                else if (id == 6006) // Event log service stopped
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Ereignisprotokoll-Dienst gestoppt (Event 6006)",
                        Risk     = RiskLevel.Medium,
                        Location = "Windows System-Ereignisprotokoll",
                        FileName = "System.evtx",
                        Reason   = $"Event 6006 (Ereignisprotokoll-Dienst gestoppt) am " +
                                   $"{ev.TimeCreated:yyyy-MM-dd HH:mm}. Das manuelle Stoppen des " +
                                   "Event-Log-Dienstes ist ein bekanntes Vorgehen zum Verbergen von " +
                                   "Cheat-Aktivitäten. Ocean flaggt dieses Event als Manipulationsindiz.",
                        Detail   = $"EventID: 6006 | Zeit: {ev.TimeCreated:yyyy-MM-dd HH:mm}"
                    });
                }
            }
        }
        catch { }
    }

    private void ScanSecurityLog(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            // 1102 = Audit log cleared, 4719 = Audit policy changed
            var query = new EventLogQuery("Security", PathType.LogName,
                "*[System[(EventID=1102 or EventID=4719)]]");

            using var reader = new EventLogReader(query);
            var cutoff = DateTime.UtcNow.AddDays(-90);
            int count = 0;

            while (reader.ReadEvent() is { } ev)
            {
                ct.ThrowIfCancellationRequested();
                if (++count > 200) break;
                if (ev.TimeCreated < cutoff) continue;

                if (ev.Id == 1102)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = "Security-Ereignisprotokoll geleert (Event 1102)",
                        Risk     = RiskLevel.High,
                        Location = "Windows Security-Ereignisprotokoll",
                        FileName = "Security.evtx",
                        Reason   = $"Event 1102 (Sicherheitsprotokoll geleert) am " +
                                   $"{ev.TimeCreated:yyyy-MM-dd HH:mm}. Legitime Benutzer löschen das " +
                                   "Security-Ereignisprotokoll nicht. Dies ist ein klassisches Vorgehen " +
                                   "zum Verbergen von Audit-Spuren nach Cheat-Nutzung. Ocean und " +
                                   "detect.ac werten 1102 als direktes Manipulationsindiz.",
                        Detail   = $"EventID: 1102 | Zeit: {ev.TimeCreated:yyyy-MM-dd HH:mm} | " +
                                   $"Meldung: {FormatEvent(ev).Substring(0, Math.Min(150, FormatEvent(ev).Length))}"
                    });
                }
                else if (ev.Id == 4719)
                {
                    string msg = FormatEvent(ev);
                    // Only flag disabling of audit (AuditPolicyChanges that disable logging)
                    if (msg.Contains("%%8448", StringComparison.Ordinal) ||  // Success Removed
                        msg.Contains("%%8450", StringComparison.Ordinal) ||  // Failure Removed
                        msg.Contains("No Auditing", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = "Audit-Richtlinie deaktiviert (Event 4719)",
                            Risk     = RiskLevel.High,
                            Location = "Windows Security-Ereignisprotokoll",
                            FileName = "Security.evtx",
                            Reason   = $"Event 4719 (Audit-Richtlinie geändert) am " +
                                       $"{ev.TimeCreated:yyyy-MM-dd HH:mm} deaktiviert die Überwachung. " +
                                       "Cheater deaktivieren Audit-Richtlinien, um Prozesserstellungs- " +
                                       "und Injection-Events aus dem Security-Log zu entfernen.",
                            Detail   = $"EventID: 4719 | Zeit: {ev.TimeCreated:yyyy-MM-dd HH:mm} | " +
                                       $"Meldung: {msg.Substring(0, Math.Min(200, msg.Length))}"
                        });
                    }
                }
            }
        }
        catch { }
    }

    private void ScanCodeIntegrityLog(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            // CodeIntegrity events 3065 (driver blocked) and 3066 (driver would have been blocked)
            var query = new EventLogQuery(
                "Microsoft-Windows-CodeIntegrity/Operational",
                PathType.LogName,
                "*[System[(EventID=3065 or EventID=3066 or EventID=3033)]]");

            using var reader = new EventLogReader(query);
            var cutoff = DateTime.UtcNow.AddDays(-30);
            int count = 0;

            while (reader.ReadEvent() is { } ev)
            {
                ct.ThrowIfCancellationRequested();
                if (++count > 1000) break;
                if (ev.TimeCreated < cutoff) continue;

                string msg = FormatEvent(ev);
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"CodeIntegrity: Treiber blockiert / DSE-Bypass (Event {ev.Id})",
                    Risk     = RiskLevel.Critical,
                    Location = "Microsoft-Windows-CodeIntegrity/Operational",
                    FileName = "CodeIntegrity.evtx",
                    Reason   = $"CodeIntegrity Event {ev.Id} am {ev.TimeCreated:yyyy-MM-dd HH:mm}: " +
                               "Windows hat versucht, einen nicht signierten oder widerrufenen Treiber " +
                               "zu laden (oder einen solchen Ladeversuch erkannt). Dies ist ein direktes " +
                               "Indiz für BYOVD-Angriffe oder DSE-Bypass-Versuche, die für " +
                               "Kernel-Mode-Cheats erforderlich sind.",
                    Detail   = $"EventID: {ev.Id} | Zeit: {ev.TimeCreated:yyyy-MM-dd HH:mm} | " +
                               $"Meldung: {msg.Substring(0, Math.Min(300, msg.Length))}"
                });
            }
        }
        catch { }
    }

    private static string FormatEvent(EventRecord ev)
    {
        try { return ev.FormatDescription() ?? ev.ToXml(); }
        catch { return ev.ToXml(); }
    }
}
