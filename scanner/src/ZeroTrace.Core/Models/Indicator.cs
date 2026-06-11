namespace ZeroTrace.Core.Models;

/// <summary>
/// A single detection rule held in the local database. Indicators are the
/// admin-maintained half of the engine; the other half is the built-in,
/// signature-free heuristics. Nothing here is downloaded automatically.
/// </summary>
public sealed class Indicator
{
    public long Id { get; set; }

    public IndicatorType Type { get; set; }

    /// <summary>
    /// The pattern to match. Meaning depends on <see cref="Type"/>:
    /// a hex hash, a file name, a keyword, a process name, etc.
    /// </summary>
    public string Pattern { get; set; } = string.Empty;

    public RiskLevel Risk { get; set; } = RiskLevel.Medium;

    /// <summary>Free-form grouping, e.g. "Injector", "Loader", "Memory tool".</summary>
    public string Category { get; set; } = "General";

    /// <summary>Human-readable explanation shown in findings as the reason.</summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>Where this indicator came from, e.g. "builtin-heuristic", "import:vendor".</summary>
    public string Source { get; set; } = "manual";

    public bool Enabled { get; set; } = true;

    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}
