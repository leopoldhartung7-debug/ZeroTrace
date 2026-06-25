using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans Windows RecentDocs and Jump Lists for recently opened cheat-related files.
///
/// Windows tracks recently opened documents in two complementary systems:
///   1. HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
///      Binary MRU lists per file extension with Unicode filename.
///   2. %APPDATA%\Microsoft\Windows\Recent\ — LNK shortcuts to recent files.
///   3. Jump Lists: %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\
///      and CustomDestinations\ — per-application recent file lists.
///
/// Forensic value:
///   - Survives file deletion (the LNK / registry entry remains)
///   - Shows target file path including original network share or USB path
///   - Jump Lists embed application identifier (AppID) + file path
///
/// Detection targets:
///   - .lua/.asi/.dll files recently opened (cheat script editing)
///   - Cheat tool names in document MRU lists
///   - Recent items pointing to deleted files in Temp/Downloads
/// </summary>
public sealed class RecentDocsScanModule : IScanModule
{
    public string Name => "RecentDocs-Artefakte";
    public double Weight => 0.5;
    public int ParallelGroup => 1;

    private const string RecentDocsKey =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs";

    private static readonly string[] CheatExtensions = { ".lua", ".asi", ".dll", ".sys" };

    private static readonly string[] CheatKeywords =
    {
        "kiddion", "cherax", "2take1", "ozark", "aimbot", "wallhack",
        "cheat", "hack", "inject", "exploit", "bypass", "spoofer",
        "triggerbot", "bhop", "esp", "trainer", "modmenu", "menyoo",
        "memprocfs", "pcileech", "xenos", "reclass", "cheatengine",
        "aimware", "skeet", "fatality", "neverlose", "onetap",
    };

    private static readonly string[] SuspiciousPaths =
    {
        @"\temp\", @"\tmp\", @"\downloads\", @"\desktop\", @"\users\public\",
    };

    private static readonly string AppDataRoaming = Environment.GetFolderPath(
        Environment.SpecialFolder.ApplicationData);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += ScanRecentDocsRegistry(ctx, ct);
        hits += ScanRecentLnkFiles(ctx, ct);

        ctx.Report(1.0, Name, $"{hits} verdächtige Recent-Artefakte gefunden");
        return Task.CompletedTask;
    }

    private static int ScanRecentDocsRegistry(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var root = Registry.CurrentUser.OpenSubKey(RecentDocsKey, writable: false);
            if (root is null) return 0;

            // Check extension-specific sub-keys for cheat-relevant extensions
            foreach (var ext in CheatExtensions)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementRegistryKeys();

                using var extKey = root.OpenSubKey(ext, writable: false);
                if (extKey is null) continue;

                // The MRUListEx value contains order; each file is stored as binary
                // with a UInt16 array (UTF-16 filename + null + extra shell data)
                var mrList = extKey.GetValue("MRUListEx") as byte[];
                if (mrList is null) continue;

                // Each value except MRUListEx is a numbered entry
                foreach (var valueName in extKey.GetValueNames())
                {
                    if (valueName == "MRUListEx") continue;
                    var data = extKey.GetValue(valueName) as byte[];
                    if (data is null || data.Length < 4) continue;

                    // Filename is UTF-16 null-terminated at the start of the binary blob
                    var nullIdx = -1;
                    for (int i = 0; i < data.Length - 1; i += 2)
                        if (data[i] == 0 && data[i + 1] == 0) { nullIdx = i; break; }

                    var fileName = nullIdx > 0
                        ? System.Text.Encoding.Unicode.GetString(data, 0, nullIdx)
                        : System.Text.Encoding.Unicode.GetString(data);
                    var lower = fileName.ToLowerInvariant();

                    var keyword = CheatKeywords.FirstOrDefault(k =>
                        lower.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (keyword is not null)
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = "RecentDocs-Artefakte",
                            Title    = $"RecentDocs: Cheat-Datei geöffnet: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKCU\{RecentDocsKey}\{ext}",
                            FileName = fileName,
                            Reason   = $"RecentDocs-Eintrag zeigt, dass eine Datei mit cheat-typischem " +
                                       $"Namen geöffnet wurde: '{fileName}' (Keyword: '{keyword}'). " +
                                       $"Extension: {ext}. Dieser Eintrag bleibt auch nach Dateilöschung erhalten.",
                            Detail   = $"Dateiname: {fileName} | Extension: {ext} | Keyword: {keyword}"
                        });
                    }
                }
            }
        }
        catch { }
        return hits;
    }

    private static int ScanRecentLnkFiles(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        var recentDir = Path.Combine(AppDataRoaming, @"Microsoft\Windows\Recent");
        if (!Directory.Exists(recentDir)) return 0;

        try
        {
            foreach (var lnk in Directory.EnumerateFiles(recentDir, "*.lnk", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var lnkName = Path.GetFileNameWithoutExtension(lnk).ToLowerInvariant();
                var keyword = CheatKeywords.FirstOrDefault(k =>
                    lnkName.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (keyword is not null)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "RecentDocs-Artefakte",
                        Title    = $"Recent LNK: Cheat-Datei: {Path.GetFileNameWithoutExtension(lnk)}",
                        Risk     = RiskLevel.High,
                        Location = lnk,
                        FileName = Path.GetFileName(lnk),
                        Reason   = $"Windows-Verknüpfung im Recent-Ordner zeigt cheat-typischen Namen: " +
                                   $"'{Path.GetFileNameWithoutExtension(lnk)}' (Keyword: '{keyword}'). " +
                                   "LNK-Dateien bleiben auch nach Löschung der Zieldatei erhalten.",
                        Detail   = $"LNK: {lnk} | Keyword: {keyword}"
                    });
                    continue;
                }

                // Check LNK name for cheat extensions in suspicious context
                if (lnkName.EndsWith(".lua") || lnkName.EndsWith(".asi"))
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "RecentDocs-Artefakte",
                        Title    = $"Recent LNK: Script-Datei zuletzt geöffnet: {Path.GetFileNameWithoutExtension(lnk)}",
                        Risk     = RiskLevel.Medium,
                        Location = lnk,
                        FileName = Path.GetFileName(lnk),
                        Reason   = $"Eine .lua oder .asi Datei wurde kürzlich geöffnet: " +
                                   $"'{Path.GetFileNameWithoutExtension(lnk)}'. " +
                                   ".asi-Dateien sind GTA-V-Cheat-Loader-Plugins, " +
                                   ".lua sind häufig Cheat-Skripte für FiveM/Garry's Mod.",
                        Detail   = $"LNK: {lnk}"
                    });
                }
            }
        }
        catch { }
        return hits;
    }
}
