using System.Collections.Concurrent;
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

    // Scan directories for at most this many seconds before stopping.
    private const int DirScanBudgetSeconds = 30;

    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".bin", ".dat", ".cfg", ".ini",
        ".lua", ".luac", ".asi", ".js", ".node",
        ".bat", ".cmd", ".ps1", ".vbs", ".wsf",
        ".json", ".xml", ".txt", ".log",
        // additional formats common in FiveM mods and cheat configs
        ".config", ".html", ".htm", ".cs",
    };

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

        var seen = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var paths = procs
                .Select(p => { try { return p.MainModule?.FileName; } catch { return null; } })
                .Where(p => !string.IsNullOrEmpty(p))
                .Select(p => p!)
                .Where(p => seen.TryAdd(p, true))
                .ToList();

            Parallel.ForEach(paths, new ParallelOptions { CancellationToken = ct,
                MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount) }, path =>
            {
                var ind = ContentSignatureScanner.Scan(path, matcher);
                if (ind is null) return;
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
            });
        }
        finally
        {
            foreach (var p in procs) try { p.Dispose(); } catch { }
        }
    }

    private static void ScanDirectories(ScanContext ctx, IndicatorMatcher matcher, CancellationToken ct)
    {
        var seen = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        var sw   = Stopwatch.StartNew();

        // Collect candidate files across all roots up to depth 12.
        var candidates = new List<string>();
        foreach (var root in KnownPaths.TargetedScanRoots())
        {
            if (ct.IsCancellationRequested || sw.Elapsed.TotalSeconds > DirScanBudgetSeconds) break;
            CollectFiles(root, candidates, seen, ct, sw, depth: 0);
        }

        Parallel.ForEach(candidates, new ParallelOptions { CancellationToken = ct,
            MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount) }, f =>
        {
            if (sw.Elapsed.TotalSeconds > DirScanBudgetSeconds) return;
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
        string dir, List<string> results, ConcurrentDictionary<string, bool> seen,
        CancellationToken ct, Stopwatch sw, int depth)
    {
        if (depth > 12 || ct.IsCancellationRequested || sw.Elapsed.TotalSeconds > DirScanBudgetSeconds)
            return;

        string[] files;
        try { files = Directory.GetFiles(dir); }
        catch { files = Array.Empty<string>(); }

        foreach (var f in files)
        {
            if (!Extensions.Contains(Path.GetExtension(f))) continue;
            if (seen.TryAdd(f, true)) results.Add(f);
        }

        string[] subdirs;
        try { subdirs = Directory.GetDirectories(dir); }
        catch { return; }

        foreach (var sub in subdirs)
        {
            if (ct.IsCancellationRequested || sw.Elapsed.TotalSeconds > DirScanBudgetSeconds) break;
            CollectFiles(sub, results, seen, ct, sw, depth + 1);
        }
    }
}
