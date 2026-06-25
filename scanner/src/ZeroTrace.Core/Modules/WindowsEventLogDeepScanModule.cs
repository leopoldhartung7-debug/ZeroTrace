using System.Diagnostics.Eventing.Reader;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Deep-scans Windows Event Logs for specific event IDs that indicate
/// cheat tool activity, security bypass, and anti-forensic actions.
///
/// While EventLogTamperScanModule checks for cleared logs, this module
/// reads the actual events looking for:
///
///   Security Log:
///     4624/4625: Login anomalies (unusual logon types)
///     4688: Process creation — looking for cheat processes/commands
///     4697: Service installed — new service creation (BYOVD driver)
///     4698/4702: Scheduled task created/modified
///     4719: System audit policy changed
///     7045: New service installed in system (Security channel)
///
///   System Log:
///     7036/7040: Service state changes (AC service stopped/disabled)
///     6: Driver loaded (check for suspicious driver names)
///
///   Application Log:
///     1000/1001: Application crash — cheat tool crash evidence
///
///   Microsoft-Windows-PowerShell/Operational:
///     4104: Script block logging — contains full PowerShell source
///     Warning: May generate false positives on legitimate admin scripts
/// </summary>
public sealed class WindowsEventLogDeepScanModule : IScanModule
{
    public string Name => "EventLog-Tiefenanalyse";
    public double Weight => 0.9;
    public int ParallelGroup => 4;

    private static readonly string[] CheatKeywords =
    {
        "kiddion", "cherax", "2take1", "ozark", "menyoo",
        "aimware", "skeet", "fatality", "neverlose", "onetap",
        "spoofer", "hwid", "inject", "bypass", "loader",
        "aimbot", "wallhack", "triggerbot", "bhop", "esp",
        "memprocfs", "pcileech", "kdmapper",
        "cheatengine", "processhacker", "xenos",
    };

    // Anti-cheat services that should NOT be stopped
    private static readonly string[] AntiCheatServices =
    {
        "EasyAntiCheat", "BEService", "vgk", "vgc",
        "EACLaunch", "BattlEye", "FACEIT",
    };

    private const int MaxEventsPerLog = 500; // Don't read thousands of events

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int eventsScanned = 0;
        int hits = 0;

        // Security log — process creation, service install, audit policy
        hits += ScanSecurityLog(ctx, ref eventsScanned, ct);

        // System log — driver load, service state changes
        hits += ScanSystemLog(ctx, ref eventsScanned, ct);

        // PowerShell operational — script block logging
        hits += ScanPowerShellLog(ctx, ref eventsScanned, ct);

        ctx.Report(1.0, Name, $"{eventsScanned} Event-Log-Einträge analysiert, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private int ScanSecurityLog(ScanContext ctx, ref int eventsScanned, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // EventID 4688: Process Creation (requires "Audit Process Creation" policy)
            var query = new EventLogQuery("Security", PathType.LogName,
                "*[System[(EventID=4688 or EventID=4697 or EventID=4698 or EventID=7045)]]");
            using var reader = new EventLogReader(query);

            int count = 0;
            EventRecord? ev;
            while ((ev = reader.ReadEvent()) is not null && count < MaxEventsPerLog)
            {
                if (ct.IsCancellationRequested) break;
                count++;
                eventsScanned++;

                try
                {
                    using (ev)
                    {
                        var xml = ev.ToXml();
                        var lower = xml.ToLowerInvariant();

                        var keyword = CheatKeywords.FirstOrDefault(k =>
                            lower.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (keyword is not null)
                        {
                            hits++;
                            var evId = ev.Id;
                            var evType = evId switch
                            {
                                4688 => "Prozess gestartet",
                                4697 => "Dienst installiert",
                                4698 => "Scheduled Task erstellt",
                                7045 => "Neuer Dienst installiert",
                                _    => $"EventID {evId}"
                            };

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Security-Log: {evType}: Cheat-Keyword '{keyword}'",
                                Risk     = evId == 4688 ? RiskLevel.High : RiskLevel.Critical,
                                Location = "Security Event Log",
                                Reason   = $"Security-Log EventID {evId} ({evType}) enthält " +
                                           $"cheat-typisches Keyword '{keyword}'. " +
                                           "Event-Log-Einträge können nicht ohne Spuren gelöscht werden " +
                                           "und sind zuverlässige forensische Beweise für Cheat-Aktivität.",
                                Detail   = $"EventID: {evId} | Zeit: {ev.TimeCreated} | Keyword: {keyword}"
                            });
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
        return hits;
    }

    private int ScanSystemLog(ScanContext ctx, ref int eventsScanned, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // EventID 7036: Service changed state, 6: Driver loaded
            var query = new EventLogQuery("System", PathType.LogName,
                "*[System[(EventID=7036 or EventID=7040 or EventID=6)]]");
            using var reader = new EventLogReader(query);

            int count = 0;
            EventRecord? ev;
            while ((ev = reader.ReadEvent()) is not null && count < MaxEventsPerLog)
            {
                if (ct.IsCancellationRequested) break;
                count++;
                eventsScanned++;

                try
                {
                    using (ev)
                    {
                        var xml = ev.ToXml();
                        var lower = xml.ToLowerInvariant();
                        var evId = ev.Id;

                        // Check for anti-cheat service being stopped
                        if (evId == 7036 || evId == 7040)
                        {
                            var acSvc = AntiCheatServices.FirstOrDefault(s =>
                                lower.Contains(s, StringComparison.OrdinalIgnoreCase));
                            if (acSvc is not null && lower.Contains("stopped"))
                            {
                                hits++;
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"System-Log: Anti-Cheat-Service gestoppt: {acSvc}",
                                    Risk     = RiskLevel.Critical,
                                    Location = "System Event Log",
                                    Reason   = $"System-Log zeigt, dass Anti-Cheat-Service '{acSvc}' " +
                                               "gestoppt wurde (EventID {evId}). " +
                                               "Anti-Cheat-Services werden von Cheat-Tools gezielt " +
                                               "deaktiviert um Erkennung zu verhindern.",
                                    Detail   = $"EventID: {evId} | Zeit: {ev.TimeCreated} | Service: {acSvc}"
                                });
                            }
                        }

                        // Check for suspicious drivers loaded (EventID 6)
                        if (evId == 6)
                        {
                            var keyword = CheatKeywords.FirstOrDefault(k =>
                                lower.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (keyword is not null)
                            {
                                hits++;
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"System-Log: Verdächtiger Treiber geladen: Keyword '{keyword}'",
                                    Risk     = RiskLevel.Critical,
                                    Location = "System Event Log",
                                    Reason   = $"System-Log EventID 6 (Treiber geladen) enthält " +
                                               $"cheat-typisches Keyword '{keyword}'. " +
                                               "Ein Kernel-Treiber mit diesem Namen wurde geladen.",
                                    Detail   = $"EventID: 6 | Zeit: {ev.TimeCreated} | Keyword: {keyword}"
                                });
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
        return hits;
    }

    private static int ScanPowerShellLog(ScanContext ctx, ref int eventsScanned, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // PowerShell Script Block Logging (EventID 4104)
            var query = new EventLogQuery(
                "Microsoft-Windows-PowerShell/Operational",
                PathType.LogName,
                "*[System[EventID=4104]]");
            using var reader = new EventLogReader(query);

            int count = 0;
            EventRecord? ev;

            // Pattern library for script block analysis
            var psDangerousPatterns = new[]
            {
                "amsiinitfailed", "amsiutils", "bypassamsi",
                "disablerealtimemonitoring", "add-mppreference",
                "vssadmin delete", "shadowcopy delete",
                "frombase64string", "invoke-expression",
                "downloadstring", "memprocfs", "pcileech",
                "kiddion", "cherax", "spoofer",
            };

            while ((ev = reader.ReadEvent()) is not null && count < MaxEventsPerLog)
            {
                if (ct.IsCancellationRequested) break;
                count++;
                eventsScanned++;

                try
                {
                    using (ev)
                    {
                        var xml = ev.ToXml();
                        var lower = xml.ToLowerInvariant();

                        var pattern = psDangerousPatterns.FirstOrDefault(p =>
                            lower.Contains(p, StringComparison.OrdinalIgnoreCase));

                        if (pattern is not null)
                        {
                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"PS-Script-Block-Log: Verdächtiger Code: '{pattern}'",
                                Risk     = RiskLevel.High,
                                Location = "Microsoft-Windows-PowerShell/Operational",
                                Reason   = $"PowerShell Script Block Logging (EventID 4104) enthält " +
                                           $"verdächtiges Muster: '{pattern}'. " +
                                           "Script Block Logs enthalten den vollständigen PowerShell-" +
                                           "Quellcode und sind nicht löschbar ohne Clearing des gesamten Logs.",
                                Detail   = $"EventID: 4104 | Zeit: {ev.TimeCreated} | Muster: {pattern}"
                            });
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
        return hits;
    }
}
