using ZeroTrace.Core.Detection;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Engine;

/// <summary>A scan module inspects one area of the system and emits findings.</summary>
public interface IScanModule
{
    /// <summary>Display name, also stored on each finding (e.g. "Drives").</summary>
    string Name { get; }

    /// <summary>Relative weight for the overall progress bar (sum need not be 1).</summary>
    double Weight { get; }

    Task RunAsync(ScanContext context, CancellationToken ct);
}

/// <summary>
/// Mutable state threaded through every module during a scan: shared counters,
/// the indicator matcher, progress reporting and the finding sink.
/// </summary>
public sealed class ScanContext
{
    private long _files;
    private long _processes;
    private long _registryKeys;
    private readonly object _findingsLock = new();
    // Collapses the same artifact (by file hash or file path) reported by several
    // modules into one finding, so a single cheat isn't listed five times.
    private readonly Dictionary<string, Finding> _dedup = new(StringComparer.OrdinalIgnoreCase);

    public ScanOptions Options { get; }
    public IndicatorMatcher Matcher { get; }
    public List<Finding> Findings { get; } = new();

    /// <summary>
    /// Shared host inventory the engine attaches to the report. Modules may
    /// append to its collections (e.g. <c>DiscordGuilds</c>) to surface
    /// per-account context that isn't a finding by itself.
    /// </summary>
    public HostInventory Inventory { get; set; } = new();

    private readonly IProgress<ScanProgress>? _progress;

    /// <summary>Raised on every added finding so the live view can stream results.</summary>
    public event Action<Finding>? FindingAdded;

    // Progress bookkeeping: each module reports its own 0-1 fraction; the engine
    // maps that onto the global bar using the module weights.
    internal double ModuleBaseline { get; set; }
    internal double ModuleSpan { get; set; } = 1;
    internal string CurrentModule { get; set; } = string.Empty;

    public long FilesScanned => Interlocked.Read(ref _files);
    public long ProcessesScanned => Interlocked.Read(ref _processes);
    public long RegistryKeysScanned => Interlocked.Read(ref _registryKeys);

    public ScanContext(ScanOptions options, IndicatorMatcher matcher, IProgress<ScanProgress>? progress)
    {
        Options = options;
        Matcher = matcher;
        _progress = progress;
    }

    public void IncrementFiles(long by = 1) => Interlocked.Add(ref _files, by);
    public void IncrementProcesses(long by = 1) => Interlocked.Add(ref _processes, by);
    public void IncrementRegistryKeys(long by = 1) => Interlocked.Add(ref _registryKeys, by);

    public void AddFinding(Finding f)
    {
        f.Module = string.IsNullOrEmpty(f.Module) ? CurrentModule : f.Module;
        f.Recommendation = RiskScorer.Recommend(f.Risk, f.Signed);

        var key = DedupKey(f);
        Finding? toStream = null;
        lock (_findingsLock)
        {
            if (key is not null && _dedup.TryGetValue(key, out var prev))
            {
                // Same artifact already reported by another module: keep the
                // strongest finding and note that another module also caught it.
                if (f.Risk > prev.Risk)
                {
                    AppendAlsoNote(f, prev.Module);
                    int idx = Findings.IndexOf(prev);
                    if (idx >= 0) Findings[idx] = f; else Findings.Add(f);
                    _dedup[key] = f;
                }
                else
                {
                    AppendAlsoNote(prev, f.Module);
                }
            }
            else
            {
                Findings.Add(f);
                if (key is not null) _dedup[key] = f;
                toStream = f;
            }
        }
        if (toStream is not null) FindingAdded?.Invoke(toStream);
    }

    /// <summary>Dedup key: file hash if present, else a real file path. Findings
    /// with a generic location (registry, logs, "Plattform") are never merged.</summary>
    private static string? DedupKey(Finding f)
    {
        if (!string.IsNullOrEmpty(f.Sha256)) return "h:" + f.Sha256;
        var loc = f.Location;
        if (!string.IsNullOrEmpty(f.FileName) && !string.IsNullOrEmpty(loc) &&
            (loc.Contains(":\\") || loc.Contains("\\\\") || loc.Contains('/')))
            return "p:" + loc!.ToLowerInvariant();
        return null;
    }

    private static void AppendAlsoNote(Finding f, string otherModule)
    {
        if (string.IsNullOrEmpty(otherModule) || otherModule == f.Module) return;
        var note = "auch erkannt von: " + otherModule;
        if (f.Detail is null) { f.Detail = note; return; }
        if (!f.Detail.Contains(otherModule, StringComparison.OrdinalIgnoreCase))
            f.Detail += " \u00b7 " + note;
    }

    /// <summary>Reports module-local progress (0-1) mapped onto the global bar.</summary>
    public void Report(double moduleFraction, string currentItem, string? message = null)
    {
        moduleFraction = Math.Clamp(moduleFraction, 0, 1);
        var percent = (ModuleBaseline + moduleFraction * ModuleSpan) * 100.0;
        _progress?.Report(new ScanProgress
        {
            Phase = ScanPhase.Running,
            Module = CurrentModule,
            CurrentItem = currentItem,
            Message = message ?? string.Empty,
            Percent = Math.Clamp(percent, 0, 100),
            FilesScanned = FilesScanned,
            ProcessesScanned = ProcessesScanned,
            RegistryKeysScanned = RegistryKeysScanned,
            FindingsCount = Findings.Count
        });
    }
}
