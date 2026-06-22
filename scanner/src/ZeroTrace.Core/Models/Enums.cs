namespace ZeroTrace.Core.Models;

/// <summary>
/// Severity of a finding. Ordered so that higher value = higher severity.
/// Used directly for sorting and for deriving recommendations.
/// </summary>
public enum RiskLevel
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3
}

/// <summary>
/// The kind of pattern an indicator matches against. Indicators live in the
/// local SQLite database and are fully editable by the administrator.
/// </summary>
public enum IndicatorType
{
    /// <summary>Exact lower-case SHA-256 hex hash of a file.</summary>
    Sha256Hash = 0,

    /// <summary>Exact (case-insensitive) file name, e.g. "loader.exe".</summary>
    FileName = 1,

    /// <summary>Substring keyword tested against a file name (heuristic).</summary>
    FileNameKeyword = 2,

    /// <summary>Substring keyword tested against a full path (heuristic).</summary>
    FilePathKeyword = 3,

    /// <summary>Exact (case-insensitive) process name without extension.</summary>
    ProcessName = 4,

    /// <summary>Registry value content keyword (heuristic).</summary>
    RegistryValueKeyword = 5,

    /// <summary>
    /// Byte/string signature searched inside a file's raw content (ASCII and
    /// UTF-16LE). Catches characteristic cheat watermarks, menu strings and
    /// brand tokens embedded in a binary even when the file has been renamed.
    /// </summary>
    ContentString = 6,

    /// <summary>
    /// Substring keyword tested against the HOST of a visited URL in the local
    /// browser history (heuristic). Used to flag visits to known cheat or
    /// reseller domains. Only matching hosts are ever recorded; the rest of the
    /// browsing history is never stored or transmitted.
    /// </summary>
    UrlDomainKeyword = 7
}

/// <summary>
/// What the operator should do with a finding. Derived transparently from the
/// risk level plus context (e.g. valid signature) by <see cref="Engine.RiskScorer"/>.
/// </summary>
public enum Recommendation
{
    Ignore = 0,
    Review = 1,
    Remove = 2
}

/// <summary>High-level phase reported during a scan for the live UI.</summary>
public enum ScanPhase
{
    Initializing = 0,
    Running = 1,
    Finalizing = 2,
    Completed = 3,
    Cancelled = 4,
    Failed = 5
}

/// <summary>
/// How much of the result the scanned person sees. The organizer chooses the
/// depth, but the scanned person ALWAYS sees at least the yes/no summary
/// (see <see cref="DisplayLevel.YesNo"/>); it can never be set to show nothing.
/// </summary>
public enum DisplayLevel
{
    /// <summary>Only "Auffaelligkeiten gefunden: ja/nein" (guaranteed minimum).</summary>
    YesNo = 0,

    /// <summary>Yes/no plus risk counts and finding titles/categories (no paths).</summary>
    Categories = 1,

    /// <summary>The full finding list including locations and details.</summary>
    Full = 2
}

/// <summary>
/// Controls which modules are active and how deep the scan goes.
/// Quick = fast low-impact modules only.
/// Standard = the default balanced set.
/// Deep = everything including memory, deep drive scan, and extended timeouts.
/// </summary>
public enum ScanProfile
{
    Quick = 0,
    Standard = 1,
    Deep = 2
}
