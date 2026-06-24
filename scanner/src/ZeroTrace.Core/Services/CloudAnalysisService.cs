using System.Net.Http.Json;
using System.Text.Json.Serialization;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Services;

/// <summary>
/// Client for the ZeroTrace cloud indicator database.
///
/// Submits batches of SHA-256 hashes found during the drive/process/driver
/// scan to the cloud API, which cross-references them against:
///   • The global cheat tool hash blocklist (updated hourly from analyst feeds)
///   • Community-reported hashes from other ZeroTrace scan submissions
///   • YARA-matched patterns (hash clusters of polymorphic packers)
///
/// Results are cached in memory for the session lifetime to avoid sending
/// the same hash twice on subsequent scans in the same session.
///
/// Privacy: only hex SHA-256 strings are sent — no file names, paths, or
/// any content that could identify the file owner.
/// </summary>
public sealed class CloudAnalysisService
{
    private readonly HttpClient _http;
    private readonly string     _endpoint;

    // Session-level in-memory cache: hash → result (null = clean)
    private readonly Dictionary<string, CloudFinding?> _cache =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _cacheLock = new(1, 1);

    private const int BatchSize = 500; // hashes per API call

    public CloudAnalysisService(HttpClient http, string endpoint)
    {
        _http     = http;
        _endpoint = endpoint.TrimEnd('/');
    }

    /// <summary>
    /// Looks up all provided SHA-256 hashes against the cloud database.
    /// Returns findings only for hashes flagged as malicious or suspicious.
    /// Unknown / clean hashes produce no entries.
    /// </summary>
    public async Task<List<CloudFinding>> LookupHashesAsync(
        IEnumerable<string> sha256Hashes,
        CancellationToken ct = default)
    {
        var results = new List<CloudFinding>();

        // Separate cached from uncached
        var toQuery = new List<string>();
        await _cacheLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            foreach (var h in sha256Hashes.Select(h => h.ToUpperInvariant()).Distinct())
            {
                if (_cache.TryGetValue(h, out var cached))
                {
                    if (cached is not null) results.Add(cached);
                }
                else
                {
                    toQuery.Add(h);
                }
            }
        }
        finally
        {
            _cacheLock.Release();
        }

        if (toQuery.Count == 0) return results;

        // Send in batches
        for (int offset = 0; offset < toQuery.Count; offset += BatchSize)
        {
            ct.ThrowIfCancellationRequested();
            var batch   = toQuery.Skip(offset).Take(BatchSize).ToList();
            var fetched = await QueryBatchAsync(batch, ct).ConfigureAwait(false);

            // Merge into cache
            await _cacheLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                // Mark all queried as seen; populate findings for flagged ones
                foreach (var h in batch) _cache.TryAdd(h, null);
                foreach (var f in fetched)
                {
                    _cache[f.Sha256.ToUpperInvariant()] = f;
                    results.Add(f);
                }
            }
            finally
            {
                _cacheLock.Release();
            }
        }

        return results;
    }

    // ── API call ──────────────────────────────────────────────────────────────

    private async Task<List<CloudFinding>> QueryBatchAsync(
        List<string> hashes,
        CancellationToken ct)
    {
        try
        {
            var request = new { Hashes = hashes };
            using var response = await _http.PostAsJsonAsync(
                _endpoint + "/api/indicators/lookup", request, ct)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode) return new();

            var dto = await response.Content
                .ReadFromJsonAsync<HashLookupResponse>(cancellationToken: ct)
                .ConfigureAwait(false);

            return dto?.Matches?.Select(m => new CloudFinding
            {
                Sha256        = m.Sha256,
                ThreatName    = m.ThreatName,
                Category      = m.Category,
                Description   = m.Description ?? string.Empty,
                RiskLevel     = ParseRisk(m.Risk),
                Source        = m.Source ?? "ZeroTrace Cloud",
                KnownFileName = m.KnownFileName,
                FirstSeen     = m.FirstSeen
            }).ToList() ?? new();
        }
        catch
        {
            return new();
        }
    }

    private static RiskLevel ParseRisk(string? risk) => risk?.ToLowerInvariant() switch
    {
        "critical" => RiskLevel.Critical,
        "high"     => RiskLevel.High,
        "medium"   => RiskLevel.Medium,
        _          => RiskLevel.Low
    };

    // ── DTOs ─────────────────────────────────────────────────────────────────

    private sealed class HashLookupResponse
    {
        [JsonPropertyName("matches")] public List<MatchDto>? Matches { get; set; }
    }

    private sealed class MatchDto
    {
        [JsonPropertyName("sha256")]        public string  Sha256        { get; set; } = "";
        [JsonPropertyName("threatName")]    public string  ThreatName    { get; set; } = "";
        [JsonPropertyName("category")]      public string  Category      { get; set; } = "";
        [JsonPropertyName("description")]   public string? Description   { get; set; }
        [JsonPropertyName("risk")]          public string? Risk          { get; set; }
        [JsonPropertyName("source")]        public string? Source        { get; set; }
        [JsonPropertyName("knownFileName")] public string? KnownFileName { get; set; }
        [JsonPropertyName("firstSeen")]     public DateTime FirstSeen    { get; set; }
    }
}

/// <summary>A threat-intelligence hit returned by the cloud for a specific hash.</summary>
public sealed class CloudFinding
{
    public string    Sha256        { get; set; } = "";
    public string    ThreatName    { get; set; } = "";
    public string    Category      { get; set; } = "";
    public string    Description   { get; set; } = "";
    public RiskLevel RiskLevel     { get; set; } = RiskLevel.Medium;
    public string    Source        { get; set; } = "";
    public string?   KnownFileName { get; set; }
    public DateTime  FirstSeen     { get; set; }
}
