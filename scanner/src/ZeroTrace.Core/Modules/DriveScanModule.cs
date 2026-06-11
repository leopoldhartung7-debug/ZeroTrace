using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Walks the filesystem looking for indicator/heuristic matches. By default it
/// scans only high-signal targeted roots (fast). With DeepDriveScan enabled it
/// walks whole drive roots for the configured extensions (slow). Enumeration is
/// defensive: reparse points and inaccessible directories are skipped silently.
/// </summary>
public sealed class DriveScanModule : IScanModule
{
    public string Name => "Laufwerke";
    public double Weight => 5.0;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var roots = ResolveRoots(ctx.Options);
        var extSet = new HashSet<string>(ctx.Options.RelevantExtensions, StringComparer.OrdinalIgnoreCase);
        var excluded = new HashSet<string>(ctx.Options.ExcludedDirectoryNames, StringComparer.OrdinalIgnoreCase);

        long processed = 0;
        int rootIndex = 0;

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();
            double rootBase = roots.Count == 0 ? 0 : (double)rootIndex / roots.Count;
            double rootSpan = roots.Count == 0 ? 1 : 1.0 / roots.Count;

            foreach (var file in EnumerateFiles(root, ctx.Options.MaxDepth, excluded, ct))
            {
                ct.ThrowIfCancellationRequested();

                if (extSet.Count > 0 && !extSet.Contains(Path.GetExtension(file)))
                    continue;

                ctx.IncrementFiles();
                processed++;

                var finding = FileInspector.Inspect(file, ctx, Name);
                if (finding is not null) ctx.AddFinding(finding);

                if (processed % 200 == 0)
                    ctx.Report(rootBase + rootSpan * 0.5, file, $"{processed} Dateien geprueft");
            }

            rootIndex++;
            ctx.Report(rootBase + rootSpan, root, $"Wurzel abgeschlossen: {root}");
        }

        return Task.CompletedTask;
    }

    private static List<string> ResolveRoots(ScanOptions options)
    {
        if (!options.DeepDriveScan)
            return KnownPaths.TargetedScanRoots().ToList();

        // Deep mode: whole fixed (and selected) drive roots.
        var letters = options.Drives;
        var drives = DriveInfo.GetDrives()
            .Where(d => d.IsReady &&
                        (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable))
            .ToList();

        var result = new List<string>();
        foreach (var d in drives)
        {
            var letter = d.Name.TrimEnd('\\', ':');
            if (letters.Count == 0 || letters.Any(l =>
                    string.Equals(l.TrimEnd('\\', ':'), letter, StringComparison.OrdinalIgnoreCase)))
            {
                result.Add(d.RootDirectory.FullName);
            }
        }
        return result;
    }

    /// <summary>
    /// Manual stack-based directory walk so we can cap depth, skip reparse points,
    /// and swallow access errors per directory rather than aborting the scan.
    /// </summary>
    private static IEnumerable<string> EnumerateFiles(
        string root, int maxDepth, HashSet<string> excludedNames, CancellationToken ct)
    {
        var stack = new Stack<(string dir, int depth)>();
        stack.Push((root, 0));

        while (stack.Count > 0)
        {
            if (ct.IsCancellationRequested) yield break;
            var (dir, depth) = stack.Pop();

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir); }
            catch { /* access denied / gone */ }

            foreach (var f in files) yield return f;

            if (depth >= maxDepth) continue;

            string[] subDirs = Array.Empty<string>();
            try { subDirs = Directory.GetDirectories(dir); }
            catch { continue; }

            foreach (var sub in subDirs)
            {
                var name = Path.GetFileName(sub);
                if (excludedNames.Contains(name)) continue;

                try
                {
                    var attr = File.GetAttributes(sub);
                    if (attr.HasFlag(FileAttributes.ReparsePoint)) continue; // avoid loops
                }
                catch { continue; }

                stack.Push((sub, depth + 1));
            }
        }
    }
}
