using System.Management;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects Volume Shadow Copy (VSS) deletion — a common anti-forensics
/// technique used by ransomware, rootkits, and cheat tools that want to
/// destroy backup evidence.
///
/// VSS maintains point-in-time snapshots of the system. Forensic investigators
/// use VSS copies to recover deleted files and reconstruct timelines. Cheat
/// software and its associated loaders delete VSS copies to:
///   1. Destroy evidence of previously installed cheat files.
///   2. Prevent recovery of deleted cheat configuration files.
///   3. Hide the fact that the system was modified at a specific point in time.
///
/// Detection signals:
///   1. Zero or very few VSS copies despite being a likely active system
///      (machine uptime > 30 days).
///
///   2. Event log evidence: EventID 524 in System log (VSS copy deleted),
///      or PowerShell/CMD command history containing 'vssadmin delete shadows'.
///
///   3. Registry: VssService start type changed to Disabled.
///
///   4. WMI: Win32_ShadowCopy query — if empty on a month-old machine and
///      System Restore is supposed to be enabled, deletion is likely.
///
///   5. PowerShell command history (ConsoleHost_history.txt) containing
///      shadow deletion commands.
/// </summary>
public sealed class VolumeShadowScanModule : IScanModule
{
    public string Name => "Volume-Shadow-Copy";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    // VSS deletion commands found in PS history or event logs
    private static readonly string[] VssDeletionCommands =
    {
        "vssadmin delete shadows",
        "vssadmin.exe delete",
        "wmic shadowcopy delete",
        "wmic shadowcopy call delete",
        "Get-WmiObject Win32_Shadowcopy | ForEach-Object { $_.Delete() }",
        "gwmi win32_shadowcopy",
        "(Get-WmiObject -Class Win32_ShadowCopy)",
        "Win32_ShadowCopy).Delete()",
        "shadow copy",
        "shadowcopy delete",
        // bcdedit is used by some ransomware to disable recovery
        "bcdedit /set {default} recoveryenabled No",
        "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, "Volume-Shadow-Copy", "Prüfe VSS-Kopien...");
        CheckVssCount(ctx, ct);

        ctx.Report(0.3, "Volume-Shadow-Copy", "Prüfe VSS-Dienst...");
        CheckVssService(ctx, ct);

        ctx.Report(0.5, "Volume-Shadow-Copy", "Prüfe PowerShell-Verlauf...");
        CheckPsHistory(ctx, ct);

        ctx.Report(0.8, "Volume-Shadow-Copy", "Prüfe Ereignisprotokoll...");
        CheckVssEventLog(ctx, ct);

        ctx.Report(1.0, "Volume-Shadow-Copy", "VSS-Analyse abgeschlossen");
        return Task.CompletedTask;
    }

    private static void CheckVssCount(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var uptimeDays = Environment.TickCount64 / 86_400_000.0;
        if (uptimeDays < 14) return; // Too new to have shadow copies

        try
        {
            int shadowCount = 0;
            using var searcher = new ManagementObjectSearcher(
                "SELECT ID, InstallDate, VolumeName FROM Win32_ShadowCopy");
            foreach (ManagementObject shadow in searcher.Get())
            {
                if (ct.IsCancellationRequested) return;
                shadowCount++;
            }

            // Check if System Protection (VSS) is enabled
            bool systemProtectionEnabled = false;
            try
            {
                using var regKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore", writable: false);
                if (regKey is not null)
                {
                    var rpSession = regKey.GetValue("RPSessionInterval") as int?;
                    systemProtectionEnabled = rpSession is > 0;
                }
            }
            catch { }

            if (shadowCount == 0 && uptimeDays > 30)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Volume-Shadow-Copy",
                    Title    = "Keine Volume Shadow Copies vorhanden",
                    Risk     = RiskLevel.Medium,
                    Location = "WMI\\Win32_ShadowCopy",
                    Reason   = $"System läuft seit {uptimeDays:F0} Tagen, hat aber null Volume Shadow Copies. " +
                               "Gelöschte VSS-Kopien sind ein typisches Anti-Forensik-Vorgehen " +
                               "von Cheat-Loadern, Rootkits und RATs, die vorherige Aktivitäten " +
                               "aus Backups entfernen wollen.",
                    Detail   = $"VSS-Kopien: 0 | Betriebszeit: {uptimeDays:F0} Tage | " +
                               $"Systemschutz: {(systemProtectionEnabled ? "aktiv" : "unbekannt")}"
                });
            }
        }
        catch { }
    }

    private static void CheckVssService(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\VSS", writable: false);
            if (key is null) return;

            var start = key.GetValue("Start") as int? ?? 3;
            if (start >= 4) // Disabled
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Volume-Shadow-Copy",
                    Title    = "Volume Shadow Copy Service deaktiviert",
                    Risk     = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services\VSS",
                    Reason   = "Der Volume Shadow Copy Service (VSS) wurde deaktiviert " +
                               "(StartType=4). Ohne VSS können keine Systemwiederherstellungspunkte " +
                               "erstellt werden und bestehende Backups wurden möglicherweise gelöscht.",
                    Detail   = $"StartType: {start} (4=Disabled)"
                });
            }
        }
        catch { }
    }

    private static void CheckPsHistory(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var historyFile = Path.Combine(profile,
            @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");

        if (!File.Exists(historyFile)) return;

        try
        {
            var lines = File.ReadAllLines(historyFile);
            foreach (var line in lines)
            {
                if (ct.IsCancellationRequested) return;
                var lower = line.ToLowerInvariant().Trim();
                if (lower.Length == 0) continue;

                var hit = VssDeletionCommands.FirstOrDefault(cmd =>
                    lower.Contains(cmd.ToLowerInvariant()));
                if (hit is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = "Volume-Shadow-Copy",
                    Title    = "VSS-Löschbefehl in PowerShell-Verlauf",
                    Risk     = RiskLevel.High,
                    Location = historyFile,
                    Reason   = $"PowerShell-Verlauf enthält VSS-Löschbefehl: '{line.Trim()}'. " +
                               "Das gezielte Löschen von Shadow Copies dient der Vernichtung " +
                               "forensischer Beweise für frühere Cheat-Aktivitäten.",
                    Detail   = $"Befehl: {line.Trim()}"
                });
            }
        }
        catch { }
    }

    private static void CheckVssEventLog(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;
        try
        {
            // EventID 8193 and 8194 = VSS errors; 524 = backup deleted
            // Check for bulk shadow deletions in the last 90 days
            var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                "System", System.Diagnostics.Eventing.Reader.PathType.LogName,
                "*[System[EventID=8193 or EventID=8194 or EventID=524]]");

            using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query);
            int errCount = 0;
            for (var rec = reader.ReadEvent(); rec is not null; rec = reader.ReadEvent())
            {
                if (ct.IsCancellationRequested) break;
                using (rec)
                {
                    var t = rec.TimeCreated ?? DateTime.MinValue;
                    if ((DateTime.UtcNow - t.ToUniversalTime()).TotalDays > 90) continue;
                    errCount++;
                }
            }

            if (errCount >= 3)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = "Volume-Shadow-Copy",
                    Title    = $"Häufige VSS-Fehler im Systemprotokoll ({errCount}×)",
                    Risk     = RiskLevel.Medium,
                    Location = "Ereignislog\\System",
                    Reason   = $"Das Systemprotokoll enthält {errCount} VSS-Fehler/-Lösch-Ereignisse " +
                               "in den letzten 90 Tagen. Häufige VSS-Fehler entstehen oft durch " +
                               "erzwungenes Löschen oder VSS-Blocker.",
                    Detail   = $"VSS-Ereignisse (8193/8194/524): {errCount} in 90 Tagen"
                });
            }
        }
        catch { }
    }
}
