using System.Diagnostics.Eventing.Reader;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects manipulation of Windows event logs — a common anti-forensics step
/// performed by cheat loaders and rootkits:
///
///   1. Cleared logs: EventID 1102 (Security) / 104 (System) indicate a log was
///      explicitly wiped. Anti-cheat engines log to Security/System; wiping these
///      destroys evidence of cheat driver activity.
///
///   2. Abnormally short log spans: if the oldest Security/System event is very
///      recent (< 7 days) on a machine that has been running for months, the log
///      was almost certainly cleared.
///
///   3. Suspiciously small logs: a Security log under 512 KB on a machine that
///      has been online for weeks means auditing was disabled or the log wiped.
///
///   4. Audit policy tampering: subcategory "Process Creation" disabled in the
///      effective audit policy (cheats disable it to hide process-creation events).
///
///   5. Windows Event Log service tampered: the service start type changed to
///      Disabled or the binary path modified.
/// </summary>
public sealed class EventLogTamperScanModule : IScanModule
{
    public string Name => "Ereignisprotokoll";
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    // Machines on for more than this many days should have older log entries.
    private const int MinExpectedLogAgeDays = 7;
    // Security log smaller than this on a week-old machine is suspicious.
    private const long MinSecurityLogBytes = 512 * 1024;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        CheckClearEvents(ctx, ct);
        CheckLogSpan(ctx, ct);
        CheckAuditPolicy(ctx, ct);
        CheckEventLogService(ctx, ct);
        ctx.Report(1.0, "Ereignisprotokoll", "Ereignisprotokoll-Analyse abgeschlossen");
        return Task.CompletedTask;
    }

    // ── 1. Explicit clear events ──────────────────────────────────────────────

    private static void CheckClearEvents(ScanContext ctx, CancellationToken ct)
    {
        // EventID 1102 in Security log = "The audit log was cleared"
        // EventID 104 in System log = "The System log file was cleared"
        var queries = new[]
        {
            ("Security", 1102, "Sicherheitsprotokoll geleert"),
            ("System",   104,  "Systemprotokoll geleert"),
        };

        foreach (var (logName, eventId, desc) in queries)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                var query = new EventLogQuery(logName, PathType.LogName,
                    $"*[System[EventID={eventId}]]");
                using var reader = new EventLogReader(query);
                var events = new List<(DateTime time, string? user)>();

                for (EventRecord? rec = reader.ReadEvent(); rec is not null; rec = reader.ReadEvent())
                {
                    if (ct.IsCancellationRequested) break;
                    using (rec)
                    {
                        var t = rec.TimeCreated ?? DateTime.MinValue;
                        // Only flag events within last 90 days to avoid ancient noise
                        if ((DateTime.UtcNow - t.ToUniversalTime()).TotalDays > 90) continue;
                        string? user = null;
                        try { user = rec.UserId?.Value; } catch { }
                        events.Add((t, user));
                    }
                }

                if (events.Count == 0) continue;

                // Most recent clear event
                var latest = events.MaxBy(e => e.time);
                ctx.AddFinding(new Finding
                {
                    Module   = "Ereignisprotokoll",
                    Title    = desc,
                    Risk     = RiskLevel.High,
                    Location = $"Ereignislog\\{logName}",
                    Reason   = $"{logName}-Protokoll wurde {events.Count}× explizit geleert " +
                               $"(zuletzt: {latest.time:yyyy-MM-dd HH:mm} UTC" +
                               (latest.user is { Length: > 0 } ? $", Benutzer: {latest.user}" : "") +
                               "). Anti-Cheat-Aktivität kann dadurch verborgen werden.",
                    Detail   = $"Gesamt Lösch-Ereignisse in den letzten 90 Tagen: {events.Count}"
                });
            }
            catch (UnauthorizedAccessException)
            {
                // Requires elevation for Security log — skip silently
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Log not present or inaccessible
                _ = ex;
            }
        }
    }

    // ── 2. Short log span (log was wiped) ────────────────────────────────────

    private static void CheckLogSpan(ScanContext ctx, CancellationToken ct)
    {
        var uptimeDays = Environment.TickCount64 / 86_400_000.0;
        if (uptimeDays < MinExpectedLogAgeDays) return; // machine recently booted

        var logsToCheck = new[]
        {
            ("Security", MinSecurityLogBytes),
            ("System",   128 * 1024L),
        };

        foreach (var (logName, minBytes) in logsToCheck)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                var session = new EventLogSession();
                var info = session.GetLogInformation(logName, PathType.LogName);
                long sizeBytes = info.FileSize ?? 0;

                // Find oldest event timestamp
                var oldestQuery = new EventLogQuery(logName, PathType.LogName)
                {
                    ReverseDirection = true
                };
                DateTime? oldest = null;
                try
                {
                    using var reader = new EventLogReader(oldestQuery);
                    using var rec = reader.ReadEvent();
                    if (rec is not null) oldest = rec.TimeCreated;
                }
                catch { }

                if (oldest.HasValue)
                {
                    var logAgeDays = (DateTime.UtcNow - oldest.Value.ToUniversalTime()).TotalDays;
                    if (logAgeDays < MinExpectedLogAgeDays && uptimeDays > MinExpectedLogAgeDays * 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = "Ereignisprotokoll",
                            Title    = $"{logName}-Protokoll ungewöhnlich kurz",
                            Risk     = RiskLevel.Medium,
                            Location = $"Ereignislog\\{logName}",
                            Reason   = $"System läuft seit {uptimeDays:F0} Tagen, aber der älteste " +
                                       $"{logName}-Eintrag ist nur {logAgeDays:F1} Tage alt. " +
                                       "Das deutet auf ein geleerte Ereignisprotokoll hin.",
                            Detail   = $"Log-Größe: {sizeBytes / 1024} KB | Ältester Eintrag: {oldest.Value:yyyy-MM-dd}"
                        });
                    }
                }

                // Also flag extremely small logs on old machines
                if (sizeBytes < minBytes && uptimeDays > MinExpectedLogAgeDays * 3)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = "Ereignisprotokoll",
                        Title    = $"{logName}-Protokoll auffällig klein",
                        Risk     = RiskLevel.Low,
                        Location = $"Ereignislog\\{logName}",
                        Reason   = $"{logName}-Protokoll ist nur {sizeBytes / 1024} KB groß " +
                                   $"bei {uptimeDays:F0} Betriebstagen. Möglicherweise wurde " +
                                   "die Protokollierung deaktiviert oder das Log geleert.",
                        Detail   = $"Größe: {sizeBytes / 1024} KB (Mindest erwartet: {minBytes / 1024} KB)"
                    });
                }
            }
            catch { }
        }
    }

    // ── 3. Audit policy: Process Creation disabled ────────────────────────────

    private static void CheckAuditPolicy(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            // Read effective audit policy from registry — documented location
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Lsa\Audit", writable: false);
            if (key is null) return;

            // ProcessCreationAudit = 0 means "No Auditing" for process creation
            var val = key.GetValue("ProcessCreationAudit");
            if (val is int intVal && intVal == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Ereignisprotokoll",
                    Title    = "Prozesserstellungs-Überwachung deaktiviert",
                    Risk     = RiskLevel.Medium,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Audit",
                    Reason   = "Die Windows-Überwachungsrichtlinie für Prozesserstellung (EventID 4688) " +
                               "ist deaktiviert. Cheat-Loader deaktivieren diese, um keine Spuren " +
                               "beim Starten von Injektions-Prozessen zu hinterlassen.",
                    Detail   = "ProcessCreationAudit = 0 (No Auditing)"
                });
            }
        }
        catch { }
    }

    // ── 4. Windows Event Log service tampered ─────────────────────────────────

    private static void CheckEventLogService(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\EventLog", writable: false);
            if (key is null) return;

            var startType = key.GetValue("Start");
            if (startType is int st && st >= 4) // 4 = Disabled
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Ereignisprotokoll",
                    Title    = "Windows-Ereignisprotokolldienst deaktiviert",
                    Risk     = RiskLevel.Critical,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog",
                    Reason   = "Der Windows-Ereignisprotokolldienst (EventLog) wurde deaktiviert (StartType=4). " +
                               "Dies ist ein starker Indikator für Rootkit- oder Cheat-Loader-Aktivität, " +
                               "die Protokollierung vollständig zu verhindern.",
                    Detail   = $"Start = {st} (4=Disabled, 5=Manually disabled by rootkit)"
                });
            }

            // Check if the service binary was replaced
            var imagePath = key.GetValue("ImagePath") as string ?? "";
            if (imagePath.Length > 0 && !imagePath.Contains("svchost", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Ereignisprotokoll",
                    Title    = "EventLog-Dienst Binärpfad manipuliert",
                    Risk     = RiskLevel.Critical,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services\EventLog",
                    Reason   = "Der Binärpfad des Windows-Ereignisprotokolldiensts zeigt nicht auf " +
                               "svchost.exe. Ein Rootkit könnte den Dienst umgeleitet haben.",
                    Detail   = $"ImagePath: {imagePath}"
                });
            }
        }
        catch { }
    }
}
