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
            // Script files that often carry custom strings in plain text
            ".bat", ".cmd", ".ps1", ".vbs", ".wsf"
        };

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int scanned = 0;

        foreach (var root in KnownPaths.TargetedScanRoots())
        {
            if (ct.IsCancellationRequested) break;
            ScanDirectory(root, ctx, matcher, extensions, seen, ref scanned, ct, depth: 0);
        }
    }

    private static void ScanDirectory(
        string dir,
        ScanContext ctx,
        IndicatorMatcher matcher,
        HashSet<string> extensions,
        HashSet<string> seen,
        ref int scanned,
        CancellationToken ct,
        int depth)
    {
        if (depth > 6 || ct.IsCancellationRequested || scanned > 5000) return;

        string[] files;
        try { files = Directory.GetFiles(dir); }
        catch { files = Array.Empty<string>(); }

        foreach (var f in files)
        {
            if (ct.IsCancellationRequested || scanned > 5000) return;
            if (!extensions.Contains(Path.GetExtension(f))) continue;
            if (!seen.Add(f)) continue;
            scanned++;
            ctx.IncrementFiles();

            var ind = ContentSignatureScanner.Scan(f, matcher);
            if (ind is null) continue;

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
        }

        string[] subdirs;
        try { subdirs = Directory.GetDirectories(dir); }
        catch { return; }

        foreach (var sub in subdirs)
        {
            if (ct.IsCancellationRequested || scanned > 5000) break;
            ScanDirectory(sub, ctx, matcher, extensions, seen, ref scanned, ct, depth + 1);
        }
    }
}
