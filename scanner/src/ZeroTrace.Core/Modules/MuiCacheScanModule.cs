using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans the MuiCache registry hive for previously executed cheat tool binaries.
///
/// Windows maintains MuiCache (formerly known as the "Application Compatibility
/// Cache") under HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache.
/// Every time Windows displays a file's friendly name in Explorer or the taskbar
/// it looks up (and caches) the binary's FileDescription resource string. The
/// resulting entries survive even after the binary is deleted, making MuiCache
/// a reliable forensic artifact for "programs that ran on this machine."
///
/// Detection targets:
///   - Known cheat tool names in cached binary paths or description strings
///   - Paths inside temp/appdata/downloads for unknown executables
///   - Deleted cheats that left a MuiCache tombstone
///
/// References:
///   HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
///   Values: "C:\path\to\binary.exe.FriendlyAppName" = "Description string"
/// </summary>
public sealed class MuiCacheScanModule : IScanModule
{
    public string Name => "MuiCache-Ausführungshistorie";
    public double Weight => 0.6;
    public int ParallelGroup => 1;

    private const string MuiCacheKey =
        @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

    private static readonly string[] CheatToolKeywords =
    {
        // GTA V cheats
        "kiddion", "2take1", "cherax", "ozark", "midnight", "stand",
        "lunar", "aimware", "xigncode", "fecurity",
        // FPS cheats
        "skinport", "hwidspoofer", "spoofer", "loader", "injector",
        "skeet", "fatality", "gamesense", "neverlose", "onetap",
        "interium", "nixware", "hvh", "legit",
        "aimbot", "wallhack", "triggerbot", "bhop", "bunnyhop",
        // Tarkov
        "eft", "tarkov", "radar", "esp",
        // Tools
        "cheatengine", "cheat engine", "processhacker", "x64dbg", "ollydbg",
        "memprocfs", "dma", "pcileech", "arsenal", "extremeinjector",
        "xenos", "manualmap", "reclass",
        // Generic
        "hacktools", "cheat", "crack", "keygen", "bypass",
    };

    private static readonly string[] SuspiciousPaths =
    {
        @"\temp\", @"\tmp\", @"\downloads\",
        @"\appdata\local\temp\", @"\desktop\",
        @"\users\public\",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int checked_ = 0;
        int hits = 0;

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(MuiCacheKey, writable: false);
            if (key is null)
            {
                ctx.Report(1.0, Name, "MuiCache nicht gefunden");
                return Task.CompletedTask;
            }

            foreach (var valueName in key.GetValueNames())
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementRegistryKeys();
                checked_++;

                // Strip the ".FriendlyAppName" / ".ApplicationCompany" suffix
                var path = valueName;
                var dotIdx = valueName.LastIndexOf('.');
                if (dotIdx > 0 && !valueName[dotIdx..].Contains('\\'))
                    path = valueName[..dotIdx];

                var friendlyName = key.GetValue(valueName) as string ?? "";
                var pathLower = path.ToLowerInvariant();
                var nameLower = friendlyName.ToLowerInvariant();
                var combined = pathLower + " " + nameLower;

                // Check for cheat keywords
                var keyword = CheatToolKeywords.FirstOrDefault(k =>
                    combined.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (keyword is not null)
                {
                    hits++;
                    var fileName = Path.GetFileName(path);
                    bool fileExists = File.Exists(path);

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"MuiCache: Cheat-Tool ausgeführt: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKCU\{MuiCacheKey}",
                        FileName = fileName,
                        Reason   = $"MuiCache-Eintrag zeigt, dass '{fileName}' auf diesem PC ausgeführt wurde. " +
                                   $"Cheat-Keyword: '{keyword}'. " +
                                   (fileExists ? "Datei noch vorhanden." : "Datei wurde gelöscht, Ausführung jedoch nachgewiesen.") +
                                   " MuiCache persistiert auch nach Löschung der Datei.",
                        Detail   = $"Pfad: {path} | Beschreibung: {friendlyName} | Keyword: {keyword} | Datei existiert: {fileExists}"
                    });
                    continue;
                }

                // Check for executables in suspicious paths with unknown descriptions
                bool isSuspiciousPath = SuspiciousPaths.Any(p => pathLower.Contains(p));
                if (isSuspiciousPath && path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"MuiCache: Ausführung aus verdächtigem Pfad: {Path.GetFileName(path)}",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKCU\{MuiCacheKey}",
                        FileName = Path.GetFileName(path),
                        Reason   = $"Programm '{Path.GetFileName(path)}' wurde aus einem user-beschreibbaren " +
                                   $"Pfad ausgeführt: '{path}'. Cheats werden häufig aus Temp- oder " +
                                   "Download-Ordnern gestartet um Persistenz zu vermeiden.",
                        Detail   = $"Pfad: {path} | Beschreibung: {friendlyName}"
                    });
                }
            }
        }
        catch { }

        ctx.Report(1.0, Name, $"{checked_} MuiCache-Einträge geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }
}
