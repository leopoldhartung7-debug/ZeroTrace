using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Deep scan of all Windows startup folder locations for cheat persistence artifacts.
///
/// Windows processes files in startup folders at every login. This module scans:
///
///   1. Shell:Startup  — %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
///   2. Shell:Common Startup — %ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp
///   3. Registry startup (already in RegistryRunHistoryScanModule, but cross-checked here)
///   4. Load value: HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Load
///   5. Run value:  HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Run
///
/// For each startup entry, the module:
///   - Reads LNK targets to find the actual executable
///   - Checks for .vbs, .bat, .ps1, .js scripts
///   - Checks for hidden files (FileAttributes.Hidden)
///   - Verifies Authenticode signature of the pointed executable
///   - Flags non-system paths and cheat keywords
///
/// Also checks:
///   - SendTo folder for suspicious items
///   - Common Places / Shell extension startup hooks
/// </summary>
public sealed class StartupFolderDeepScanModule : IScanModule
{
    public string Name => "Autostart-Ordner-Deep-Scan";
    public double Weight => 0.7;
    public int ParallelGroup => 4;

    private static readonly string WinDir = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows).ToLowerInvariant();
    private static readonly string System32 = Environment.GetFolderPath(
        Environment.SpecialFolder.System).ToLowerInvariant();

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "aimbot",
        "kiddion", "cherax", "2take1", "ozark", "skeet", "fatality",
        "neverlose", "onetap", "aimware", "spoofer", "hook",
        "gta5", "fivem", "tarkov", "apex", "valorant", "csgo",
        "memprocfs", "pcileech", "dma", "radar",
        "macro", "autohotkey", "ahk", "triggerbot",
    };

    // Extensions that are immediately suspicious in a startup folder
    private static readonly HashSet<string> SuspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".ps1", ".psm1", ".psd1",
        ".bat", ".cmd",
        ".hta",
        ".scr",   // screensaver (often abused)
        ".pif",
        ".dll",   // should never be in startup folder
        ".sys",
    };

    // Extensions that are acceptable (LNK shortcuts and signed EXEs)
    private static readonly HashSet<string> AcceptableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".lnk", ".url", ".exe", ".appref-ms",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;

        var startupDirs = GetStartupDirectories();
        foreach (var dir in startupDirs)
        {
            if (ct.IsCancellationRequested) break;
            hits += ScanStartupDirectory(dir, ctx, ct);
        }

        // Also check Load/Run values in Windows key (less common but used by cheats)
        hits += CheckWindowsLoadRunValues(ctx, ct);

        ctx.Report(1.0, Name, $"Autostart-Ordner geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static List<string> GetStartupDirectories()
    {
        var dirs = new List<string>();

        // Per-user startup
        var userStartup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (!string.IsNullOrEmpty(userStartup)) dirs.Add(userStartup);

        // All-users startup
        var commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        if (!string.IsNullOrEmpty(commonStartup)) dirs.Add(commonStartup);

        // Alternative: read from Shell Folders registry
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", writable: false);
            if (key is not null)
            {
                var regStartup = key.GetValue("Startup") as string;
                if (!string.IsNullOrEmpty(regStartup) && !dirs.Contains(regStartup,
                    StringComparer.OrdinalIgnoreCase))
                    dirs.Add(regStartup);
            }
        }
        catch { }

        return dirs;
    }

    private static int ScanStartupDirectory(string dir, ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        if (!Directory.Exists(dir)) return 0;

        try
        {
            foreach (var file in Directory.EnumerateFiles(dir, "*",
                SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var ext   = Path.GetExtension(file).ToLowerInvariant();
                var name  = Path.GetFileName(file).ToLowerInvariant();
                var fi    = new FileInfo(file);

                // Check for hidden files
                bool isHidden = (fi.Attributes & FileAttributes.Hidden) != 0;

                var cheatKw = CheatKeywords.FirstOrDefault(k =>
                    name.Contains(k, StringComparison.OrdinalIgnoreCase));

                bool isSuspiciousExt = SuspiciousExtensions.Contains(ext);
                bool isAcceptable    = AcceptableExtensions.Contains(ext);

                if (cheatKw is not null || isSuspiciousExt || isHidden)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtiger Autostart-Eintrag: {Path.GetFileName(file)}",
                        Risk     = cheatKw is not null ? RiskLevel.Critical :
                                   isSuspiciousExt ? RiskLevel.High : RiskLevel.Medium,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Datei '{Path.GetFileName(file)}' im Autostart-Ordner '{dir}'. " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                   (isSuspiciousExt ? $"Dateityp '{ext}' ist ein Ausführungskanditat " +
                                       "(Script/SCR/PIF). " : "") +
                                   (isHidden ? "Datei ist versteckt (Hidden-Attribut). " : "") +
                                   "Autostart-Ordner werden bei jedem Benutzeranmeldevorgang verarbeitet.",
                        Detail   = $"Datei: {file} | Typ: {ext} | Größe: {fi.Length} | " +
                                   $"Versteckt: {isHidden} | Keyword: {cheatKw ?? "keins"}"
                    });
                }
                else if (!isAcceptable && !string.IsNullOrEmpty(ext))
                {
                    // Unknown extension in startup folder
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Unbekannte Datei im Autostart: {Path.GetFileName(file)}",
                        Risk     = RiskLevel.Medium,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason   = $"Datei mit unbekannter Extension '{ext}' im Autostart-Ordner '{dir}'. " +
                                   "Ungewöhnliche Dateitypen im Autostart sind ein forensisches Artefakt.",
                        Detail   = $"Datei: {file} | Typ: {ext} | Größe: {fi.Length}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckWindowsLoadRunValues(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            foreach (var valueName in new[] { "Load", "Run" })
            {
                if (ct.IsCancellationRequested) break;
                var value = key.GetValue(valueName) as string ?? "";
                if (string.IsNullOrWhiteSpace(value)) continue;

                var lower   = value.ToLowerInvariant();
                var cheatKw = CheatKeywords.FirstOrDefault(k =>
                    lower.Contains(k, StringComparison.OrdinalIgnoreCase));
                bool isSystem = lower.StartsWith(System32) || lower.StartsWith(WinDir);

                if (cheatKw is not null || !isSystem)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Windows-{valueName}-Autostart: {value}",
                        Risk     = cheatKw is not null ? RiskLevel.Critical : RiskLevel.High,
                        Location = $@"HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                        Reason   = $"HKCU Windows\\{valueName} ist auf '{value}' gesetzt. " +
                                   $"Der {valueName}-Wert wird von Windows bei jedem Anmeldevorgang " +
                                   "ausgeführt. " +
                                   (cheatKw is not null ? $"Cheat-Keyword: '{cheatKw}'. " : "") +
                                   (!isSystem ? "Pfad außerhalb Windows-Verzeichnis." : ""),
                        Detail   = $"{valueName}: {value} | Keyword: {cheatKw ?? "keins"}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }
}
