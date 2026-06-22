using System.IO.Compression;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Focused pass over the user's Downloads folder, where cheat installers and
/// archives most often arrive. Executables/DLLs go through full file inspection.
/// Archives are not unpacked, but their NAME and PATH are now matched against
/// indicators (so an archive named like a known cheat package is still caught),
/// and recent archives are reported informationally with their internet origin
/// when known (Mark-of-the-Web).
/// </summary>
public sealed class DownloadsScanModule : IScanModule
{
    public string Name => "Downloads";
    public double Weight => 1.0;

    private static readonly string[] ArchiveExtensions =
        { ".zip", ".rar", ".7z", ".gz", ".cab", ".tar", ".iso" };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var downloads = KnownPaths.Downloads;
        if (!Directory.Exists(downloads))
        {
            ctx.Report(1.0, "Downloads", "Kein Downloads-Ordner gefunden");
            return Task.CompletedTask;
        }

        var files = SafeEnumerate(downloads, ct).ToList();
        int total = Math.Max(files.Count, 1);
        int i = 0;

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            i++;
            ctx.IncrementFiles();
            if (i % 20 == 0) ctx.Report((double)i / total, file, $"{i}/{files.Count} Downloads");

            var ext = Path.GetExtension(file);

            if (ArchiveExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase))
            {
                InspectArchive(ctx, file);
                continue;
            }

            // Check if file was downloaded from a known cheat-hosting domain.
            var urlFinding = CheckZoneIdentifierUrl(file);
            if (urlFinding is not null)
            {
                ctx.AddFinding(urlFinding);
                continue;
            }

            var finding = FileInspector.Inspect(file, ctx, Name);
            if (finding is not null)
            {
                finding.Reason = "[Downloads] " + finding.Reason;
                ctx.AddFinding(finding);
            }
        }

        ctx.Report(1.0, "Downloads", "Downloads-Pruefung abgeschlossen");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Archives are not unpacked. We still match name/path indicators against the
    /// archive itself and emit a low/informational note for recent archives.
    /// </summary>
    private void InspectArchive(ScanContext ctx, string file)
    {
        var fileName = Path.GetFileName(file);
        var motw = MarkOfWeb.Read(file);

        // Name / path indicator match on the archive itself.
        var nameHit = ctx.Matcher.MatchFileName(fileName)
                      ?? ctx.Matcher.MatchFileNameKeyword(fileName);
        var pathHit = nameHit is null ? ctx.Matcher.MatchPathKeyword(file) : null;
        var hit = nameHit ?? pathHit;

        if (hit is not null)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Archiv-Indikator-Treffer: {hit.Category}",
                Risk = hit.Risk,
                Location = file,
                FileName = fileName,
                Reason = $"[Downloads] Archivname/-pfad entspricht Indikator '{hit.Pattern}'. " +
                         hit.Description + " Inhalt wird nicht entpackt.",
                Detail = motw.FromInternet ? $"Herkunft: Internet{(motw.HostUrl is null ? "" : $" ({motw.HostUrl})")}" : null
            });
            return;
        }

        // ZIP only: read the ENTRY NAMES inside (no extraction of content) and
        // match them against the indicators. Catches an innocuously-named
        // archive that contains e.g. injector.dll / aimbot.lua.
        if (Path.GetExtension(file).Equals(".zip", StringComparison.OrdinalIgnoreCase))
        {
            var inner = PeekZipForIndicator(ctx, file);
            if (inner is not null)
            {
                var (ind, entry) = inner.Value;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Archiv-Inhalt-Treffer: {ind.Category}",
                    Risk = ind.Risk,
                    Location = file,
                    FileName = fileName,
                    Reason = $"[Downloads] Im Archiv enthaltene Datei '{entry}' entspricht Indikator " +
                             $"'{ind.Pattern}'. {ind.Description} (Nur Eintragsnamen gelesen, kein Entpacken.)",
                    Detail = motw.FromInternet ? $"Herkunft: Internet{(motw.HostUrl is null ? "" : $" ({motw.HostUrl})")}" : null
                });
                return;
            }
        }

        var age = DateTime.Now - SafeWriteTime(file);
        if (age <= TimeSpan.FromDays(30))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Kuerzlich heruntergeladenes Archiv",
                Risk = RiskLevel.Low,
                Location = file,
                FileName = fileName,
                Reason = "Archiv im Downloads-Ordner (innerhalb 30 Tagen). Inhalt wird nicht " +
                         "entpackt; bitte bei Bedarf manuell pruefen." +
                         (motw.FromInternet ? " Stammt aus dem Internet (Mark-of-the-Web)." : ""),
                Detail = $"Geaendert: {SafeWriteTime(file):yyyy-MM-dd}" +
                         (motw.HostUrl is null ? "" : $" \u00b7 Quelle: {motw.HostUrl}")
            });
        }
    }

    /// <summary>
    /// Opens a .zip read-only and matches each entry's NAME (not content)
    /// against the indicators. Bounded to a sane entry count; all failures
    /// (corrupt/encrypted/locked) degrade safely to null.
    /// </summary>
    private static (Indicator ind, string entry)? PeekZipForIndicator(ScanContext ctx, string file)
    {
        try
        {
            using var zip = ZipFile.OpenRead(file);
            int seen = 0;
            foreach (var e in zip.Entries)
            {
                if (++seen > 5000) break;            // bound very large archives
                if (string.IsNullOrEmpty(e.Name)) continue; // directory entry
                var ind = ctx.Matcher.MatchFileName(e.Name)
                          ?? ctx.Matcher.MatchFileNameKeyword(e.Name)
                          ?? ctx.Matcher.MatchPathKeyword(e.FullName);
                if (ind is not null) return (ind, e.FullName);
            }
        }
        catch { /* corrupt / encrypted / unsupported -> skip */ }
        return null;
    }

    private static IEnumerable<string> SafeEnumerate(string dir, CancellationToken ct)
    {
        var stack = new Stack<string>();
        stack.Push(dir);
        while (stack.Count > 0)
        {
            if (ct.IsCancellationRequested) yield break;
            var current = stack.Pop();

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(current); } catch { }
            foreach (var f in files) yield return f;

            string[] subs = Array.Empty<string>();
            try { subs = Directory.GetDirectories(current); } catch { continue; }
            foreach (var s in subs) stack.Push(s);
        }
    }

    private static DateTime SafeWriteTime(string path)
    {
        try { return File.GetLastWriteTime(path); }
        catch { return DateTime.MinValue; }
    }

    // Known cheat-hosting and reseller domain fragments.
    private static readonly string[] CheatDomainFragments =
    {
        "cheat", "hack", "aimbot", "esp-", "-esp.", "wallhack",
        "bypass", "spoofer", "undetected", "fivemcheat",
        "mod-menu", "modmenu", "cheathappens", "unknowncheats",
        "mpgh.net", "elitepvpers", "nulled.to", "cracked.io",
        "leakcheats", "freecheats", "bestcheats", "topcheat",
    };

    /// <summary>
    /// Reads the NTFS Zone.Identifier alternate data stream to extract the
    /// ReferrerUrl / HostUrl and checks it against known cheat-hosting domains.
    /// Returns a finding if a match is found, null otherwise.
    /// </summary>
    private static Finding? CheckZoneIdentifierUrl(string file)
    {
        // The ADS is named "file.ext:Zone.Identifier"
        var adsPath = file + ":Zone.Identifier";
        string content;
        try { content = File.ReadAllText(adsPath, System.Text.Encoding.UTF8); }
        catch { return null; }

        // Parse ReferrerUrl and HostUrl lines from the INI-style stream.
        string? url = null;
        foreach (var line in content.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("ReferrerUrl=", StringComparison.OrdinalIgnoreCase) ||
                trimmed.StartsWith("HostUrl=",     StringComparison.OrdinalIgnoreCase))
            {
                url = trimmed.Substring(trimmed.IndexOf('=') + 1).Trim();
                break;
            }
        }

        if (string.IsNullOrEmpty(url)) return null;

        foreach (var frag in CheatDomainFragments)
        {
            if (url.Contains(frag, StringComparison.OrdinalIgnoreCase))
            {
                return new Finding
                {
                    Module = "Downloads",
                    Title = $"Download von bekannter Cheat-Domain: {Path.GetFileName(file)}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = Path.GetFileName(file),
                    Reason = $"Die Datei wurde von einer als Cheat-Quelle bekannten Domain heruntergeladen. " +
                             $"Download-URL enthaelt verdaechtiges Muster '{frag}'.",
                    Detail = $"Quelle: {url}"
                };
            }
        }
        return null;
    }
}
