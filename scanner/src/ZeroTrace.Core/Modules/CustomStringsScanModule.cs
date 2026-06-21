using System.Diagnostics;
using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans for strings saved on the dashboard and bundled into the scanner ZIP as
/// a "zerotrace.strings" sidecar file (one pattern per line). Running process
/// images and targeted user-space directories are checked. Runs last so the
/// earlier modules' results are already visible. No network access is performed.
/// </summary>
public sealed class CustomStringsScanModule : IScanModule
{
    public string Name => "Benutzerdefinierte Strings";
    public double Weight => 1.0;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var indicators = CustomStringsReader.Read();
        if (indicators.Count == 0)
        {
            ctx.Report(1.0, "", "Keine benutzerdefinierten Strings konfiguriert");
            return Task.CompletedTask;
        }

        var matcher = new IndicatorMatcher(indicators);
        ctx.Report(0.05, "Scanning strings", $"{indicators.Count} Muster geladen");

        ScanProcessImages(ctx, matcher, ct);
        ctx.Report(0.55, "Scanning strings", "Prozessbilder geprueft");

        ScanDirectories(ctx, matcher, ct);
        ctx.Report(1.0, "Scanning strings", "Verzeichnisse geprueft");

        return Task.CompletedTask;
    }

    private static void ScanProcessImages(ScanContext ctx, IndicatorMatcher matcher, CancellationToken ct)
    {
        Process[] procs;
        try { procs = Process.GetProcesses(); }
        catch { return; }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var p in procs)
            {
                if (ct.IsCancellationRequested) break;
                string? path = null;
                try { path = p.MainModule?.FileName; } catch { }
                if (string.IsNullOrEmpty(path) || !seen.Add(path)) continue;

                var ind = ContentSignatureScanner.Scan(path, matcher);
                if (ind is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = "Benutzerdefinierte Strings",
                    Title = $"Benutzerdefinierter String in Prozess: {Path.GetFileName(path)}",
                    Risk = ind.Risk,
                    Location = path,
                    FileName = Path.GetFileName(path),
                    Reason = $"Der benutzerdefinierte String '{ind.Pattern}' wurde im Prozessabbild " +
                             $"'{Path.GetFileName(path)}' gefunden. {ind.Description}",
                });
            }
        }
        finally
        {
            foreach (var p in procs) try { p.Dispose(); } catch { }
        }
    }

    private static void ScanDirectories(ScanContext ctx, IndicatorMatcher matcher, CancellationToken ct)
    {
        var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".bin", ".dat", ".cfg", ".ini",
            ".lua", ".luac", ".asi", ".js", ".node",
            ".bat", ".cmd", ".ps1", ".vbs", ".wsf",
            ".json", ".xml", ".txt", ".log"
        };

        // Collect candidates sequentially first (keeps the seen-set simple).
        var allFiles = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var root in KnownPaths.TargetedScanRoots())
        {
            if (ct.IsCancellationRequested) break;
            CollectFiles(root, allFiles, extensions, seen, ct, depth: 0, maxCount: 5000);
        }

        // Process candidates in parallel — ContentSignatureScanner is stateless.
        var parallelOptions = new ParallelOptions
        {
            CancellationToken = ct,
            MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount)
        };

        Parallel.ForEach(allFiles, parallelOptions, f =>
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var ind = ContentSignatureScanner.Scan(f, matcher);
            if (ind is null) return;

            ctx.AddFinding(new Finding
            {
                Module = "Benutzerdefinierte Strings",
                Title = $"Benutzerdefinierter String in Datei: {Path.GetFileName(f)}",
                Risk = ind.Risk,
                Location = f,
                FileName = Path.GetFileName(f),
                Reason = $"Der benutzerdefinierte String '{ind.Pattern}' wurde in der Datei " +
                         $"'{Path.GetFileName(f)}' gefunden. {ind.Description}",
            });
        });
    }

    private static void CollectFiles(
        string dir,
        List<string> result,
        HashSet<string> extensions,
        HashSet<string> seen,
        CancellationToken ct,
        int depth,
        int maxCount)
    {
        if (depth > 6 || ct.IsCancellationRequested || result.Count >= maxCount) return;

        string[] files;
        try { files = Directory.GetFiles(dir); }
        catch { files = Array.Empty<string>(); }

        foreach (var f in files)
        {
            if (ct.IsCancellationRequested || result.Count >= maxCount) return;
            if (!extensions.Contains(Path.GetExtension(f))) continue;
            if (!seen.Add(f)) continue;
            result.Add(f);
        }

        string[] subdirs;
        try { subdirs = Directory.GetDirectories(dir); }
        catch { return; }

        foreach (var sub in subdirs)
        {
            if (ct.IsCancellationRequested || result.Count >= maxCount) break;
            CollectFiles(sub, result, extensions, seen, ct, depth + 1, maxCount);
        }
    }
}
