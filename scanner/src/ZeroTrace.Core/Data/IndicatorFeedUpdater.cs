using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Data;

/// <summary>
/// Downloads an indicator feed from a remote URL, optionally verifies an
/// HMAC-SHA256 signature, and prepares the list for explicit user confirmation
/// before <see cref="Apply"/> is called.
///
/// Feed format (JSON):
/// <code>
/// {
///   "version": "1.0",
///   "publishedUtc": "2026-01-01T00:00:00Z",
///   "signature": "sha256=&lt;hex&gt;",   // optional HMAC-SHA256 over indicators array
///   "indicators": [ ... ]
/// }
/// </code>
/// A bare JSON array is also accepted when no envelope is needed.
/// Network access is intentional; the user must configure the URL and confirm
/// before any indicator is written to the database.
/// </summary>
public sealed class IndicatorFeedUpdater
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    public sealed record FeedResult(
        bool Ok,
        string? Error,
        List<Indicator> Indicators,
        int Count);

    public sealed class FeedEnvelope
    {
        public string Version { get; set; } = "1.0";
        public string? PublishedUtc { get; set; }
        public string? Signature { get; set; }
        public List<Indicator> Indicators { get; set; } = new();
    }

    /// <summary>
    /// Downloads the feed, optionally verifies its HMAC-SHA256 signature, and
    /// returns the parsed indicators. Does NOT write anything to the database.
    /// The caller must show the results to the user and call <see cref="Apply"/>
    /// on explicit confirmation.
    /// </summary>
    public static async Task<FeedResult> FetchAsync(
        string feedUrl, string? hmacKey = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(feedUrl))
            return new FeedResult(false, "Keine Feed-URL konfiguriert.", new(), 0);

        if (!Uri.TryCreate(feedUrl, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            return new FeedResult(false, "Ungueltige URL (nur http/https erlaubt).", new(), 0);

        string body;
        try
        {
            body = await Http.GetStringAsync(uri, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return new FeedResult(false, $"Download fehlgeschlagen: {ex.Message}", new(), 0);
        }

        var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

        // Try to parse as envelope.
        FeedEnvelope? envelope = null;
        try { envelope = JsonSerializer.Deserialize<FeedEnvelope>(body, opts); } catch { }

        var indicators = envelope?.Indicators is { Count: > 0 } ? envelope.Indicators
            : TryParseArray(body, opts);

        if (indicators is null)
            return new FeedResult(false, "Feed-Format konnte nicht gelesen werden (kein JSON-Array oder Envelope).", new(), 0);

        // HMAC verification when a key is configured.
        if (!string.IsNullOrEmpty(hmacKey))
        {
            if (string.IsNullOrEmpty(envelope?.Signature))
                return new FeedResult(false,
                    "Kein Signaturfeld im Feed (hmac_key ist konfiguriert, Signatur fehlt).", new(), 0);

            var indicatorsJson = JsonSerializer.Serialize(indicators, opts);
            var expected = ComputeHmac(indicatorsJson, hmacKey);
            var actual = envelope.Signature.StartsWith("sha256=", StringComparison.OrdinalIgnoreCase)
                ? envelope.Signature[7..] : envelope.Signature;

            if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
                return new FeedResult(false,
                    "HMAC-Signatur ungueltig – Feed koennte manipuliert worden sein.", new(), 0);
        }

        return new FeedResult(true, null, indicators, indicators.Count);
    }

    /// <summary>
    /// Upserts <paramref name="indicators"/> into the store (matched by type+pattern).
    /// Existing entries are updated; new ones are inserted.
    /// Returns the number of newly added indicators.
    /// </summary>
    public static int Apply(List<Indicator> indicators, IndicatorStore store, string source = "feed")
    {
        var existing = store.GetAll();
        var existingByKey = existing.ToDictionary(
            i => $"{(int)i.Type}:{i.Pattern.ToLowerInvariant()}");

        int added = 0;
        foreach (var ind in indicators)
        {
            if (string.IsNullOrWhiteSpace(ind.Pattern)) continue;
            ind.Source = source;
            var key = $"{(int)ind.Type}:{ind.Pattern.ToLowerInvariant()}";
            if (existingByKey.TryGetValue(key, out var prev))
            {
                ind.Id = prev.Id;
                store.Update(ind);
            }
            else
            {
                store.Add(ind);
                added++;
            }
        }
        return added;
    }

    private static List<Indicator>? TryParseArray(string json, JsonSerializerOptions opts)
    {
        try { return JsonSerializer.Deserialize<List<Indicator>>(json, opts); }
        catch { return null; }
    }

    private static string ComputeHmac(string payload, string key)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        using var hmac = new HMACSHA256(keyBytes);
        return Convert.ToHexString(hmac.ComputeHash(payloadBytes)).ToLowerInvariant();
    }
}
