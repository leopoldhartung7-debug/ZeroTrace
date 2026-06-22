using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Reads Windows Prefetch file names from C:\Windows\Prefetch\*.pf.
/// Each .pf file name encodes the executable that was run, so this surfaces
/// cheat executables that have since been deleted. The file content is NOT
/// parsed — only the embedded executable name from the file name is used.
/// Format: EXECUTABLENAME-XXXXXXXX.pf  (8-char hex hash suffix)
/// </summary>
public sealed class PrefetchScanModule : IScanModule
{
    public string Name => "Prefetch";
    public double Weight => 0.4;

    private const string PrefetchDir = @"C:\Windows\Prefetch";

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        if (!Directory.Exists(PrefetchDir))
        {
            ctx.Report(1.0, "Prefetch", "Prefetch-Verzeichnis nicht vorhanden (deaktiviert oder kein Zugriff)");
            return Task.CompletedTask;
        }

        string[] files;
        try { files = Directory.GetFiles(PrefetchDir, "*.pf"); }
        catch { ctx.Report(1.0, "Prefetch", "Kein Zugriff auf Prefetch-Verzeichnis"); return Task.CompletedTask; }

        int total = 0, hits = 0;
        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) break;
            total++;
            var pfName = Path.GetFileNameWithoutExtension(file);
            // Strip the trailing -XXXXXXXX hash suffix to recover the exe name.
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            var hit = ctx.Matcher.MatchFileName(exeName + ".exe")
                      ?? ctx.Matcher.MatchFileNameKeyword(exeName)
                      ?? ctx.Matcher.MatchPathKeyword(exeName);
            if (hit is null) continue;

            hits++;
            var lastWrite = SafeWriteTime(file);
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Prefetch-Treffer: {exeName}.exe",
                Risk     = hit.Risk,
                Location = file,
                FileName = exeName + ".exe",
                Reason   = $"Prefetch-Datei deutet auf Ausfuehrung von '{exeName}.exe' hin " +
                           $"(Indikator: '{hit.Pattern}', Kategorie: {hit.Category}). " +
                           hit.Description,
                Detail   = lastWrite != default
                    ? $"Prefetch zuletzt aktualisiert: {lastWrite:yyyy-MM-dd HH:mm:ss}"
                    : null,
            });

            if (hits >= 40) break;
        }

        ctx.Report(1.0, "Prefetch", $"{total} Prefetch-Eintraege geprueft, {hits} Treffer");
        return Task.CompletedTask;
    }

    private static DateTime SafeWriteTime(string path)
    {
        try { return File.GetLastWriteTime(path); }
        catch { return default; }
    }
}
