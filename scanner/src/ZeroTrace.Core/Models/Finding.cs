namespace ZeroTrace.Core.Models;

/// <summary>
/// A single result produced by a scan module. Every finding is fully
/// self-describing: it always states WHY it was flagged so the operator can
/// judge it independently. Detection is never presented as proof of cheating.
/// </summary>
public sealed class Finding
{
    public long Id { get; set; }

    /// <summary>Foreign key to the owning scan.</summary>
    public long ScanId { get; set; }

    /// <summary>Which module produced this, e.g. "Drives", "Processes".</summary>
    public string Module { get; set; } = string.Empty;

    /// <summary>Short title shown in lists.</summary>
    public string Title { get; set; } = string.Empty;

    public RiskLevel Risk { get; set; }

    /// <summary>Where it was found: file path, registry key, process id, etc.</summary>
    public string Location { get; set; } = string.Empty;

    /// <summary>File name if applicable.</summary>
    public string? FileName { get; set; }

    /// <summary>Lower-case SHA-256 hex if a file was hashed.</summary>
    public string? Sha256 { get; set; }

    /// <summary>
    /// The explicit reason for the detection. This is mandatory and is what
    /// keeps the tool transparent.
    /// </summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>
    /// Authenticode signature status: true = signed, false = unsigned,
    /// null = not checked / not applicable. A heuristic input, not a verdict.
    /// </summary>
    public bool? Signed { get; set; }

    /// <summary>Optional extra detail (e.g. signer subject, parent process).</summary>
    public string? Detail { get; set; }

    public Recommendation Recommendation { get; set; } = Recommendation.Review;

    public DateTime DetectedUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Combined confidence 0-100 based on how many independent signals agreed.
    /// 0 means the field was not computed by this detection path.
    /// </summary>
    public int ConfidenceScore { get; set; }
}
