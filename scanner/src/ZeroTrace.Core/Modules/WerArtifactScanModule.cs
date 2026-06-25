using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans Windows Error Reporting (WER) crash dump artifacts for cheat tool evidence.
///
/// When a process crashes, Windows Error Reporting writes artefacts to:
///   %LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive\   (archived reports)
///   %LOCALAPPDATA%\Microsoft\Windows\WER\ReportQueue\     (pending reports)
///   %ProgramData%\Microsoft\Windows\WER\ReportArchive\    (system-wide)
///   %ProgramData%\Microsoft\Windows\WER\ReportQueue\
///
/// Each crash report folder contains:
///   - Report.wer:   text file with ExeName, AppPath, FaultingModuleName
///   - *.hdmp:       heap dump (binary, contains process strings)
///   - *.mdmp:       mini-dump (binary)
///
/// Forensic value:
///   - Cheats that crashed leave WER entries revealing their path and module
///   - Anti-detection tools that inject into games may appear as faulting modules
///   - Report.wer files survive process/binary deletion
///   - FaultingModuleName reveals the exact DLL that caused the crash
///
/// Detection:
///   - Parse Report.wer for ExeName/ApplicationPath containing cheat keywords
///   - Check FaultingModuleName for injected cheat DLLs
///   - Flag crash reports from temp/appdata paths for unknown executables
/// </summary>
public sealed class WerArtifactScanModule : IScanModule
{
    public string Name => "WER-Absturzbericht-Artefakte";
    public double Weight => 0.6;
    public int ParallelGroup => 1;

    private static readonly string LocalApp = Environment.GetFolderPath(
        Environment.SpecialFolder.LocalApplicationData);
    private static readonly string ProgramData = Environment.GetFolderPath(
        Environment.SpecialFolder.CommonApplicationData);

    private static readonly string[] WerBaseDirs;

    static WerArtifactScanModule()
    {
        var dirs = new List<string>
        {
            Path.Combine(LocalApp, @"Microsoft\Windows\WER\ReportArchive"),
            Path.Combine(LocalApp, @"Microsoft\Windows\WER\ReportQueue"),
            Path.Combine(ProgramData, @"Microsoft\Windows\WER\ReportArchive"),
            Path.Combine(ProgramData, @"Microsoft\Windows\WER\ReportQueue"),
        };
        WerBaseDirs = dirs.Where(Directory.Exists).ToArray();
    }

    private static readonly string[] CheatKeywords =
    {
        "kiddion", "cherax", "2take1", "ozark", "aimware", "fecurity",
        "skeet", "fatality", "neverlose", "onetap", "interium", "nixware",
        "gamesense", "aimbot", "wallhack", "triggerbot", "bhop",
        "inject", "loader", "bypass", "spoofer", "hookdll",
        "xenos", "manualmap", "reclass", "memprocfs", "pcileech",
        "cheatengine", "processhacker", "extremeinjector",
        "menyoo", "modmenu", "scripthook",
    };

    private static readonly string[] SuspiciousPaths =
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\users\public\",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int reportsScanned = 0;
        int hits = 0;

        foreach (var baseDir in WerBaseDirs)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                foreach (var reportDir in Directory.EnumerateDirectories(baseDir))
                {
                    if (ct.IsCancellationRequested) break;
                    var werFile = Path.Combine(reportDir, "Report.wer");
                    if (!File.Exists(werFile)) continue;

                    reportsScanned++;
                    ctx.IncrementFiles();

                    try
                    {
                        var lines = File.ReadAllLines(werFile, System.Text.Encoding.Unicode);
                        if (lines.Length == 0)
                            lines = File.ReadAllLines(werFile, System.Text.Encoding.UTF8);

                        var report = ParseWerFile(lines);
                        if (CheckReport(report, reportDir, ctx, ct))
                            hits++;
                    }
                    catch { }
                }
            }
            catch { }
        }

        ctx.Report(1.0, Name, $"{reportsScanned} WER-Berichte geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static Dictionary<string, string> ParseWerFile(string[] lines)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines)
        {
            var eq = line.IndexOf('=');
            if (eq > 0)
            {
                var k = line[..eq].Trim();
                var v = line[(eq + 1)..].Trim();
                if (!string.IsNullOrEmpty(k))
                    result[k] = v;
            }
        }
        return result;
    }

    private static bool CheckReport(Dictionary<string, string> report, string reportDir,
        ScanContext ctx, CancellationToken ct)
    {
        // Fields of interest in Report.wer
        report.TryGetValue("AppName", out var appName);
        report.TryGetValue("AppPath", out var appPath);
        report.TryGetValue("FaultingModule", out var faultMod);
        report.TryGetValue("FaultingModulePath", out var faultPath);

        appName ??= "";
        appPath ??= "";
        faultMod ??= "";
        faultPath ??= "";

        var combined = $"{appName} {appPath} {faultMod} {faultPath}".ToLowerInvariant();

        var keyword = CheatKeywords.FirstOrDefault(k =>
            combined.Contains(k, StringComparison.OrdinalIgnoreCase));

        if (keyword is not null)
        {
            var title = !string.IsNullOrEmpty(appName) ? appName
                      : !string.IsNullOrEmpty(faultMod) ? faultMod
                      : Path.GetFileName(reportDir);

            ctx.AddFinding(new Finding
            {
                Module   = "WER-Absturzbericht-Artefakte",
                Title    = $"WER-Absturzbericht: Cheat-Tool: {title}",
                Risk     = RiskLevel.High,
                Location = reportDir,
                FileName = appName,
                Reason   = $"Windows-Absturzbericht enthält Cheat-Keyword '{keyword}' in: " +
                           $"AppName='{appName}', AppPath='{appPath}', " +
                           $"FaultingModule='{faultMod}'. " +
                           "WER-Artefakte bleiben nach Löschung des Cheat-Tools erhalten.",
                Detail   = $"Bericht: {reportDir} | Keyword: {keyword} | " +
                           $"AppPath: {appPath} | FaultMod: {faultPath}"
            });
            return true;
        }

        // Check if app crashed from a suspicious path
        var appPathLower = appPath.ToLowerInvariant();
        bool isSuspiciousPath = SuspiciousPaths.Any(p => appPathLower.Contains(p));
        if (isSuspiciousPath && !string.IsNullOrEmpty(appPath))
        {
            ctx.AddFinding(new Finding
            {
                Module   = "WER-Absturzbericht-Artefakte",
                Title    = $"WER: Absturz aus verdächtigem Pfad: {appName}",
                Risk     = RiskLevel.Medium,
                Location = reportDir,
                FileName = appName,
                Reason   = $"Programm '{appName}' ist aus einem user-beschreibbaren Pfad " +
                           $"abgestürzt: '{appPath}'. Cheats und Loader werden häufig aus " +
                           "Temp- oder Download-Ordnern ausgeführt.",
                Detail   = $"AppPath: {appPath} | FaultMod: {faultMod}"
            });
            return true;
        }

        return false;
    }
}
