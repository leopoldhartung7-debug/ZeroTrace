using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans Windows Task Scheduler for cheat-related and persistence tasks.
///
/// Cheat loaders use Task Scheduler for:
///   - Auto-launching the cheat loader on logon (persistence)
///   - Running elevation scripts at startup without UAC prompt (task with highest privilege)
///   - Scheduling HWID spoofer to run before game launch
///   - Running cleanup scripts after gaming sessions to remove cheat artifacts
///
/// Ocean and detect.ac scan scheduled tasks because:
///   - Tasks with non-standard names running from AppData/Temp/Downloads are suspicious
///   - Elevated tasks with no publisher that run on logon are classic cheat persistence
///   - Tasks named after cheat tools are direct evidence
///
/// Detection methods:
///   - Walk %SystemRoot%\System32\Tasks\ (XML files for registered tasks)
///   - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
///   - Check for: Action points to %APPDATA%, %TEMP%, %DOWNLOADS%
///   - Check for: cheat-keyword task names
///   - Check for: highest privilege tasks with unknown/empty authors
/// </summary>
public sealed class SuspiciousScheduledTaskScanModule : IScanModule
{
    public string Name => "Verdächtige Geplante Aufgaben (Cheat-Persistenz) Scan";
    public double Weight => 0.55;
    public int ParallelGroup => 3;

    private static readonly string[] CheatTaskKeywords =
    {
        "cheat", "hack", "injector", "loader",
        "aimbot", "wallhack", "esp", "bypass",
        "spoofer", "hwid",
        "gamesense", "onetap", "fatality",
        "neverlose", "skeet",
        "kiddion", "2take1", "stand",
        "memprocfs", "pcileech", "dma",
        "no recoil", "norecoil", "triggerbot",
        "bhop", "rage hack",
    };

    private static readonly string[] SuspiciousPathPatterns =
    {
        @"\appdata\local\temp\",
        @"\appdata\roaming\temp\",
        @"\users\public\",
        @"\windows\temp\",
        @"\downloads\",
        @"\desktop\",
        "%temp%",
        "%tmp%",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanTaskXmlFiles(ctx, ct);
        ScanTaskCacheRegistry(ctx, ct);
    }

    private void ScanTaskXmlFiles(ScanContext ctx, CancellationToken ct)
    {
        string tasksDir = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");

        if (!System.IO.Directory.Exists(tasksDir)) return;

        try
        {
            foreach (string file in System.IO.Directory.EnumerateFiles(
                         tasksDir, "*", System.IO.SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                var info = new System.IO.FileInfo(file);
                if (info.Length == 0 || info.Length > 512 * 1024) continue;

                ctx.IncrementFiles();

                string taskName = System.IO.Path.GetFileName(file).ToLowerInvariant();
                string content;
                try { content = System.IO.File.ReadAllText(file); }
                catch { continue; }

                string lower = content.ToLowerInvariant();

                // Check task name for cheat keywords
                foreach (string kw in CheatTaskKeywords)
                {
                    if (!taskName.Contains(kw)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Aufgabe in Task Scheduler: {System.IO.Path.GetFileName(file)}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"Geplante Aufgabe '{System.IO.Path.GetFileName(file)}' enthält " +
                                   $"Cheat-Schlüsselwort '{kw}' im Aufgabennamen. Cheat-Loader registrieren " +
                                   "häufig geplante Aufgaben für Autostart / Persistenz. Ocean und detect.ac " +
                                   "scannen Task Scheduler als Persistence-Quelle.",
                        Detail   = $"Aufgabe: {file} | Schlüsselwort: '{kw}'"
                    });
                    break;
                }

                // Check action executable path for suspicious locations
                foreach (string pathPat in SuspiciousPathPatterns)
                {
                    if (!lower.Contains(pathPat)) continue;

                    // Also check if the task is elevated (RunLevel=HighestAvailable)
                    bool elevated = lower.Contains("highestavailable") ||
                                    lower.Contains("leaststartprivilege");
                    bool noPublisher = !lower.Contains("<author>") ||
                                      lower.Contains("<author></author>");

                    if (!elevated) break; // only flag elevated tasks from suspicious paths

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Erhöhte geplante Aufgabe aus verdächtigem Pfad: {System.IO.Path.GetFileName(file)}",
                        Risk     = noPublisher ? RiskLevel.High : RiskLevel.Medium,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"Geplante Aufgabe '{System.IO.Path.GetFileName(file)}' läuft mit " +
                                   $"erhöhten Rechten (HighestAvailable) und verweist auf einen " +
                                   $"verdächtigen Pfad (Match: '{pathPat}'). Cheat-Loader nutzen " +
                                   "erhöhte Tasks für UAC-freien Kernel-Treiber-Load.",
                        Detail   = $"Aufgabe: {file} | Pfad-Muster: '{pathPat}' | " +
                                   $"Erhöht: {elevated} | Ohne Publisher: {noPublisher}"
                    });
                    break;
                }

                // Check content for cheat keywords (action executable names)
                foreach (string kw in CheatTaskKeywords)
                {
                    if (!lower.Contains(kw)) continue;

                    int idx = lower.IndexOf(kw, StringComparison.Ordinal);
                    int start = Math.Max(0, idx - 60);
                    int end = Math.Min(content.Length, idx + kw.Length + 100);
                    string snippet = content.Substring(start, end - start)
                                             .Replace('\n', ' ').Replace('\r', ' ').Trim();

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Cheat-Referenz in geplanter Aufgabe: '{kw}' in {System.IO.Path.GetFileName(file)}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = System.IO.Path.GetFileName(file),
                        Reason   = $"Geplante Aufgabe '{System.IO.Path.GetFileName(file)}' verweist auf " +
                                   $"Cheat-Schlüsselwort '{kw}' im Aktionspfad oder Argument. Dies belegt " +
                                   "die Nutzung von Task Scheduler für Cheat-Autostart.",
                        Detail   = $"Aufgabe: {file} | Schlüsselwort: '{kw}' | Kontext: \"{snippet}\""
                    });
                    return; // one finding per task file
                }
            }
        }
        catch { }
    }

    private void ScanTaskCacheRegistry(ScanContext ctx, CancellationToken ct)
    {
        // The TaskCache stores the last run time and hash — useful for recently deleted tasks
        try
        {
            using var tasksKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
                writable: false);
            if (tasksKey is null) return;

            foreach (string taskGuid in tasksKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                try
                {
                    using var taskKey = tasksKey.OpenSubKey(taskGuid, writable: false);
                    if (taskKey is null) continue;

                    string? path   = taskKey.GetValue("Path") as string ?? "";
                    string? actions = null;
                    byte[]? actionsBytes = taskKey.GetValue("Actions") as byte[];
                    if (actionsBytes is not null)
                        actions = System.Text.Encoding.Unicode.GetString(actionsBytes).ToLowerInvariant();

                    string combined = $"{path} {actions}".ToLowerInvariant();

                    foreach (string kw in CheatTaskKeywords)
                    {
                        if (!combined.Contains(kw)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Cheat-Aufgabe im TaskCache: '{path}'",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{taskGuid}",
                            FileName = System.IO.Path.GetFileName(path ?? ""),
                            Reason   = $"TaskCache enthält geplante Aufgabe '{path}' mit Cheat-Schlüsselwort " +
                                       $"'{kw}'. TaskCache-Einträge können auch für gelöschte Aufgaben " +
                                       "erhalten bleiben und belegen frühere Cheat-Persistenz.",
                            Detail   = $"Task-Pfad: {path} | Schlüsselwort: '{kw}' | GUID: {taskGuid}"
                        });
                        break;
                    }
                }
                catch { }
            }
        }
        catch { }
    }
}
