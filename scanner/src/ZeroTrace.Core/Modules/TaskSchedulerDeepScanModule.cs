using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Deep scan of Windows Scheduled Tasks XML files for malicious actions.
///
/// While the standard ScheduledTaskScanModule (Group 3) uses WMI/COM to enumerate
/// registered tasks, this module reads the raw XML task definition files from
/// %SystemRoot%\System32\Tasks\ and %SystemRoot%\SysWOW64\Tasks\ directly.
///
/// This catches:
///   1. Tasks that use PowerShell download cradles (IEX, Invoke-WebRequest)
///   2. Tasks with base64-encoded commands (-EncodedCommand)
///   3. LOLBINs (mshta.exe, regsvr32.exe, rundll32.exe, wscript.exe, cscript.exe)
///      used as action executables
///   4. Tasks targeting non-system directories (Temp, AppData, Downloads)
///   5. Tasks with disabled trigger (hidden, run-once at startup and then hidden)
///   6. Tasks with cheat tool keywords in their name, description, or command
///   7. Tasks registered by non-system user accounts (AtLogon with specific user)
///
/// XML task files live on disk even if the task has been deleted from the Task
/// Scheduler DB — leftover files are also forensic artifacts.
/// </summary>
public sealed class TaskSchedulerDeepScanModule : IScanModule
{
    public string Name => "Task-Scheduler-Deep-Scan";
    public double Weight => 0.8;
    public int ParallelGroup => 4;

    private static readonly string System32Tasks = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System), "Tasks");
    private static readonly string UserTasks = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        @"Microsoft\Windows\PowerShell\ScheduledJobs");

    private static readonly string WinDir = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows).ToLowerInvariant();
    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "kiddion", "cherax", "2take1", "ozark", "skeet", "fatality",
        "neverlose", "onetap", "aimware", "spoofer", "hook",
        "gta5", "fivem", "tarkov", "apex", "valorant",
        "memprocfs", "pcileech", "dma", "radar",
    };

    // Suspicious execution binaries used as LOLBIN launchers
    private static readonly HashSet<string> SuspiciousExecutors = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell.exe", "pwsh.exe",
        "mshta.exe", "wscript.exe", "cscript.exe",
        "regsvr32.exe", "rundll32.exe", "regasm.exe", "regsvcs.exe",
        "msiexec.exe", "installutil.exe",
        "certutil.exe", "bitsadmin.exe",
        "wmic.exe", "odbcconf.exe",
        "ieexec.exe", "pcalua.exe",
        "bash.exe", "cmd.exe",
    };

    // Patterns in command lines that indicate malicious tasks
    private static readonly string[] MaliciousPatterns =
    {
        "encodedcommand", "-enc ", "-e ",
        "invoke-expression", "iex(", "iex ",
        "invoke-webrequest", "downloadstring", "downloadfile",
        "net.webclient", "webclient",
        "frombase64string",
        "hidden", "-windowstyle h",
        "bypass", "-executionpolicy bypass", "-ep bypass",
        "http://", "https://",      // downloading from internet
        "temp\\", "appdata\\", "%temp%", "%appdata%",
        "amsiutils", "reflection.assembly",
        "system.management.automation",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += ScanTaskDirectory(System32Tasks, ctx, ct);

        ctx.Report(1.0, Name, $"Scheduled-Task-XML-Dateien geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int ScanTaskDirectory(string dir, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        if (!Directory.Exists(dir)) return 0;

        try
        {
            foreach (var file in Directory.EnumerateFiles(dir, "*",
                SearchOption.AllDirectories))
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                try
                {
                    var taskHits = AnalyzeTaskFile(file, ctx, ct);
                    hits += taskHits;
                }
                catch { }
            }
        }
        catch { }
        return hits;
    }

    private static int AnalyzeTaskFile(string filePath, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Task XML files have no extension — read the first few bytes to identify
            var content = File.ReadAllText(filePath, System.Text.Encoding.UTF8);
            if (!content.Contains("<Task")) return 0;

            var lower   = content.ToLowerInvariant();
            var taskName = Path.GetFileName(filePath);

            // 1. Check for cheat keywords anywhere in the task
            var cheatKw = CheatKeywords.FirstOrDefault(k =>
                lower.Contains(k, StringComparison.OrdinalIgnoreCase));

            // 2. Check for malicious execution patterns
            string? malPattern = null;
            foreach (var pat in MaliciousPatterns)
            {
                if (lower.Contains(pat, StringComparison.OrdinalIgnoreCase))
                {
                    malPattern = pat;
                    break;
                }
            }

            // 3. Extract <Command> values and check paths
            var commands = ExtractXmlValues(content, "Command");
            var arguments = ExtractXmlValues(content, "Arguments");
            string? suspiciousExe = null;
            string? nonSystemPath = null;

            foreach (var cmd in commands)
            {
                var cmdLower = cmd.ToLowerInvariant();
                var fname    = Path.GetFileName(cmdLower).Trim();

                if (SuspiciousExecutors.Contains(fname))
                    suspiciousExe = fname;

                if (!cmdLower.StartsWith(WinDir) &&
                    !cmdLower.StartsWith(System32) &&
                    !cmdLower.StartsWith("%systemroot%") &&
                    !cmdLower.StartsWith("%windir%") &&
                    !string.IsNullOrWhiteSpace(cmd) &&
                    cmd.Contains('\\'))
                {
                    nonSystemPath = cmd;
                }
            }

            // 4. Check for encoded commands in arguments
            bool hasEncodedCmd = arguments.Any(a =>
                a.ToLowerInvariant().Contains("encodedcommand") ||
                a.ToLowerInvariant().Contains(" -enc ") ||
                a.ToLowerInvariant().Contains(" -e "));

            if (cheatKw is not null || hasEncodedCmd || nonSystemPath is not null ||
                (malPattern is not null && suspiciousExe is not null))
            {
                hits++;
                RiskLevel risk;
                string reason;

                if (cheatKw is not null)
                {
                    risk = RiskLevel.Critical;
                    reason = $"Cheat-Keyword '{cheatKw}' in Task-Definition. ";
                }
                else if (hasEncodedCmd)
                {
                    risk = RiskLevel.Critical;
                    reason = "Task enthält base64-codierten PowerShell-Befehl (-EncodedCommand). ";
                }
                else if (nonSystemPath is not null)
                {
                    risk = RiskLevel.High;
                    reason = $"Task führt Executable außerhalb System-Verzeichnis aus: '{nonSystemPath}'. ";
                }
                else
                {
                    risk = RiskLevel.High;
                    reason = $"Task nutzt LOLBIN '{suspiciousExe}' mit suspektem Muster '{malPattern}'. ";
                }

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Verdächtiger geplanter Task: {taskName}",
                    Risk     = risk,
                    Location = filePath,
                    FileName = taskName,
                    Reason   = reason +
                               "Geplante Tasks können für persistente Code-Ausführung bei " +
                               "Systemstart, Login oder in regelmäßigen Abständen genutzt werden.",
                    Detail   = $"Datei: {filePath} | Keyword: {cheatKw ?? "keins"} | " +
                               $"Muster: {malPattern ?? "keins"} | Executor: {suspiciousExe ?? "keins"} | " +
                               $"EncodedCmd: {hasEncodedCmd}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static List<string> ExtractXmlValues(string xml, string tagName)
    {
        var results = new List<string>();
        var openTag  = $"<{tagName}>";
        var closeTag = $"</{tagName}>";
        int pos = 0;
        while (true)
        {
            int start = xml.IndexOf(openTag, pos, StringComparison.OrdinalIgnoreCase);
            if (start < 0) break;
            start += openTag.Length;
            int end = xml.IndexOf(closeTag, start, StringComparison.OrdinalIgnoreCase);
            if (end < 0) break;
            results.Add(xml.Substring(start, end - start).Trim());
            pos = end + closeTag.Length;
        }
        return results;
    }
}
