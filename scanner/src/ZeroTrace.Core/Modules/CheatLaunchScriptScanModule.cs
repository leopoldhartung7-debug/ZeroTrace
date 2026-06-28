using System.IO;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects cheat launcher scripts in user-accessible directories: .bat/.cmd files with
/// injection/bypass commands, AutoHotKey scripts with PixelSearch/ImageSearch (triggerbot),
/// Python scripts with AI-aimbot imports (bettercam, ultralytics, dxcam), and VBS/JS
/// download-and-execute scripts. Ocean/detect.ac scan script directories as a standard
/// forensic source — launcher scripts often survive after the cheat binary is deleted.
/// </summary>
public sealed class CheatLaunchScriptScanModule : IScanModule
{
    public string Name => "CheatLaunchScript";
    public double Weight => 0.5;
    public int ParallelGroup => 4;

    private static readonly string[] CheatKeywordNames = {
        "aimbot", "wallhack", "esp", "bhop", "inject",
        "bypass", "triggerbot", "norecoil", "recoil", "spoofer",
        "hvh", "radar", "softaim", "silentaim", "silent_aim",
        "cheat", "hack", "loader", "autoclick"
    };

    // CMD/BAT script patterns
    private static readonly string[] BatchCheatPatterns = {
        "inject",
        "bypass",
        "aimbot",
        "wallhack",
        "sc stop vgc",
        "sc stop beservice",
        "sc stop easyanticheat",
        "sc config",
        "disable_antispyware",
        "disablerealtimemonitoring",
        "add mppreference",
        "bcdedit /set",
        "reg add.*disableantispyware",
        "start /high",
        "spoofer",
        "taskkill /f.*vgc",
        "taskkill /f.*beservice",
    };

    // AHK patterns — triggerbot/no-recoil/bhop scripts
    private static readonly string[] AhkCheatPatterns = {
        "pixelsearch",
        "imagesearch",
        "getcolor",
        "interception",
        "recoil",
        "norecoil",
        "triggerbot",
        "aimbot",
        "wallhack",
        "bhop",
        "bunnyhop",
        "rapidfire",
        "no_recoil",
        "antirecoil",
        "softaim",
    };

    // Python AI-aimbot + memory-cheat imports
    private static readonly string[] PythonCheatPatterns = {
        "bettercam",
        "dxcam",
        "ultralytics",
        "onnxruntime",
        "yolov",
        "triggerbot",
        "aimbot",
        "bhop",
        "readprocessmemory",
        "vmread",
        "pymem",
        "pyinjector",
        "openprocess",
        "recoil_control",
        "pynput",
        "vision_aim",
        "screen_detect",
        "mss.mss",       // mss screen capture for AI aimbot
    };

    // VBS/JS download-and-exec patterns
    private static readonly string[] VbsJsExecPatterns = {
        "downloadstring",
        "downloadfile",
        "winhttprequest",
        "shell.run",
        "wscript.shell",
        "createobject.*shell",
        "regwrite",
        "bypass",
        "inject",
        "aimbot",
        "wallhack",
        "invoke-expression",
        "iex ",
    };

    private static string[] BuildScanDirectories()
    {
        var profile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        return new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(profile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),    // Startup folder
            Path.Combine(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
            localApp,
            appData,
            Path.GetTempPath(),
            Path.Combine(profile, "Documents"),
        };
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var scanDirs = BuildScanDirectories();

        await Task.Run(() =>
        {
            ScanBatchFiles(ctx, scanDirs, ct);
            ScanAutoHotkeyScripts(ctx, scanDirs, ct);
            ScanPythonScripts(ctx, scanDirs, ct);
            ScanPowerShellScripts(ctx, scanDirs, ct);
            ScanVbsJsScripts(ctx, scanDirs, ct);
        }, ct);
    }

    // ─── Batch / CMD ─────────────────────────────────────────────────────────

    private static void ScanBatchFiles(ScanContext ctx, string[] scanDirs, CancellationToken ct)
    {
        foreach (var dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var ext in new[] { "*.bat", "*.cmd" })
                {
                    foreach (var file in Directory.GetFiles(dir, ext, SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles(1);

                        if (FileNameIsCheat(file))
                        {
                            ReportScriptByName(ctx, file, "Batch/CMD-Cheat-Launcher");
                            continue;
                        }

                        AnalyzeScriptContent(ctx, file, "CheatLaunchScript",
                            BatchCheatPatterns, "Batch/CMD-Cheat-Skript", RiskLevel.High, ct);
                    }
                }
            }
            catch { }
        }
    }

    // ─── AutoHotKey ──────────────────────────────────────────────────────────

    private static void ScanAutoHotkeyScripts(ScanContext ctx, string[] scanDirs, CancellationToken ct)
    {
        foreach (var dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(dir, "*.ahk", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles(1);

                    if (FileNameIsCheat(file))
                    {
                        ReportScriptByName(ctx, file, "AHK-Cheat-Skript",
                            "AutoHotKey-Skript mit Cheat-Keyword im Dateinamen. AHK wird fuer " +
                            "No-Recoil, Triggerbot und BunnyHop-Automation verwendet.",
                            RiskLevel.High);
                        continue;
                    }

                    AnalyzeScriptContent(ctx, file, "CheatLaunchScript",
                        AhkCheatPatterns, "AHK-Cheat-Automatisierungs-Skript", RiskLevel.High, ct);
                }
            }
            catch { }
        }
    }

    // ─── Python ──────────────────────────────────────────────────────────────

    private static void ScanPythonScripts(ScanContext ctx, string[] scanDirs, CancellationToken ct)
    {
        foreach (var dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(dir, "*.py", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles(1);

                    if (FileNameIsCheat(file))
                    {
                        ReportScriptByName(ctx, file, "Python-Cheat-Skript",
                            "Python-Skript mit Cheat-Keyword im Dateinamen. " +
                            "Haeufig bei AI-Aimbot (bettercam/ultralytics) oder memory-basierten Python-Cheats.",
                            RiskLevel.High);
                        continue;
                    }

                    AnalyzeScriptContent(ctx, file, "CheatLaunchScript",
                        PythonCheatPatterns, "Python-Cheat/AI-Aimbot-Skript", RiskLevel.High, ct);
                }
            }
            catch { }
        }
    }

    // ─── PowerShell ──────────────────────────────────────────────────────────

    private static void ScanPowerShellScripts(ScanContext ctx, string[] scanDirs, CancellationToken ct)
    {
        foreach (var dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var ext in new[] { "*.ps1", "*.psm1" })
                {
                    foreach (var file in Directory.GetFiles(dir, ext, SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles(1);

                        if (FileNameIsCheat(file))
                        {
                            ReportScriptByName(ctx, file, "PowerShell-Cheat-Skript",
                                "PowerShell-Skript mit Cheat-Keyword im Dateinamen.", RiskLevel.High);
                            continue;
                        }

                        // Reuse batch patterns — PowerShell uses same command names
                        AnalyzeScriptContent(ctx, file, "CheatLaunchScript",
                            BatchCheatPatterns, "PowerShell-Cheat-Launcher-Skript", RiskLevel.High, ct);
                    }
                }
            }
            catch { }
        }
    }

    // ─── VBScript / JScript / WSF ────────────────────────────────────────────

    private static void ScanVbsJsScripts(ScanContext ctx, string[] scanDirs, CancellationToken ct)
    {
        foreach (var dir in scanDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            try
            {
                foreach (var ext in new[] { "*.vbs", "*.vbe", "*.js", "*.jse", "*.wsf" })
                {
                    foreach (var file in Directory.GetFiles(dir, ext, SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles(1);

                        AnalyzeScriptContent(ctx, file, "CheatLaunchScript",
                            VbsJsExecPatterns, "VBScript/JScript Download-Execute-Skript", RiskLevel.High, ct);
                    }
                }
            }
            catch { }
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private static bool FileNameIsCheat(string filePath)
    {
        var name = Path.GetFileNameWithoutExtension(filePath).ToLowerInvariant();
        foreach (var kw in CheatKeywordNames)
            if (name.Contains(kw)) return true;
        return false;
    }

    private static void ReportScriptByName(
        ScanContext ctx, string file, string title,
        string reason = "", RiskLevel risk = RiskLevel.High)
    {
        if (string.IsNullOrEmpty(reason))
            reason = $"Skript-Datei mit Cheat-Keyword im Dateinamen gefunden: '{Path.GetFileName(file)}'.";

        ctx.AddFinding(new Finding
        {
            Module = "CheatLaunchScript",
            Title = $"{title}: {Path.GetFileName(file)}",
            Risk = risk,
            Location = file,
            FileName = Path.GetFileName(file),
            Reason = reason,
            Detail = $"File={file}"
        });
    }

    private static void AnalyzeScriptContent(
        ScanContext ctx,
        string filePath,
        string module,
        string[] patterns,
        string titlePrefix,
        RiskLevel baseRisk,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        string content;
        try
        {
            const int maxBytes = 512 * 1024;
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var buffer = new byte[(int)Math.Min(maxBytes, fs.Length)];
            var bytesRead = fs.Read(buffer, 0, buffer.Length);
            content = Encoding.UTF8.GetString(buffer, 0, bytesRead).ToLowerInvariant();
        }
        catch { return; }

        var matched = new List<string>();
        foreach (var pattern in patterns)
        {
            ct.ThrowIfCancellationRequested();
            if (content.Contains(pattern.ToLowerInvariant()))
            {
                matched.Add(pattern);
                if (matched.Count >= 4) break;
            }
        }

        if (matched.Count == 0) return;

        // Escalate to Critical when multiple cheat patterns co-occur
        var risk = matched.Count >= 2 ? RiskLevel.Critical : baseRisk;

        ctx.AddFinding(new Finding
        {
            Module = module,
            Title = $"{titlePrefix}: {Path.GetFileName(filePath)}",
            Risk = risk,
            Location = filePath,
            FileName = Path.GetFileName(filePath),
            Reason = $"Skript enthaelt {matched.Count} verdaechtige Pattern: {string.Join(", ", matched.Take(4))}.",
            Detail = $"File={filePath} Patterns={string.Join("|", matched)}"
        });
    }
}
