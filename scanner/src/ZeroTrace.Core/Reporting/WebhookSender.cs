using System.Net.Http;
using System.Text;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Reporting;

/// <summary>
/// Sends a scan report as JSON to a user-supplied URL via HTTP POST.
///
/// This is the ONLY place the application can reach the network, and it never
/// runs on its own: the UI must obtain explicit, per-send confirmation from the
/// user (showing the exact target URL and the exact payload) before calling
/// <see cref="SendAsync"/>. Nothing is transmitted automatically or in the
/// background.
/// </summary>
public sealed class WebhookSender
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };

    public sealed record SendResult(bool Ok, int StatusCode, string Message);

    /// <summary>Builds the exact JSON body that will be sent (for preview + send).</summary>
    public static string BuildPayload(ScanReport report) => ReportExporter.ToJson(report);

    /// <summary>
    /// POSTs <paramref name="json"/> to <paramref name="url"/>. Validates the URL
    /// scheme (http/https only) and reports a clear result. Throws nothing on
    /// network failure - it is reported via the returned record.
    /// </summary>
    public static async Task<SendResult> SendAsync(string url, string json, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(url))
            return new SendResult(false, 0, "Keine Ziel-Adresse angegeben.");

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            return new SendResult(false, 0, "Adresse muss mit http:// oder https:// beginnen.");

        // Up to 3 attempts with exponential backoff. Networks at LAN parties /
        // tournaments are often flaky; Discord/Slack also rate-limit briefly.
        // We only retry on transient outcomes: network errors, timeouts, 429,
        // and 5xx. 4xx other than 429 means the payload is wrong, not the
        // transport, so we surface that immediately.
        const int MaxAttempts = 3;
        int code = 0;
        string lastMessage = string.Empty;
        for (int attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            try
            {
                using var content = new StringContent(json, Encoding.UTF8, "application/json");
                using var response = await Http.PostAsync(uri, content, ct);
                code = (int)response.StatusCode;
                if (response.IsSuccessStatusCode)
                    return new SendResult(true, code,
                        attempt == 1
                            ? $"Erfolgreich gesendet (HTTP {code})."
                            : $"Erfolgreich gesendet (HTTP {code}, Versuch {attempt}).");

                lastMessage = $"Server antwortete mit HTTP {code}.";
                bool retriable = code == 429 || code >= 500;
                if (!retriable || attempt == MaxAttempts)
                    return new SendResult(false, code, lastMessage);
            }
            catch (TaskCanceledException) when (!ct.IsCancellationRequested)
            {
                lastMessage = "Zeitueberschreitung - Adresse nicht erreichbar?";
                if (attempt == MaxAttempts)
                    return new SendResult(false, 0, lastMessage);
            }
            catch (TaskCanceledException)
            {
                return new SendResult(false, 0, "Vorgang abgebrochen.");
            }
            catch (Exception ex)
            {
                lastMessage = "Senden fehlgeschlagen: " + ex.Message;
                if (attempt == MaxAttempts)
                    return new SendResult(false, 0, lastMessage);
            }

            // 500ms, 1.5s — small enough that the user still sees a quick send
            // result, large enough to clear a transient 429 / brief 5xx.
            var delay = TimeSpan.FromMilliseconds(500 * Math.Pow(3, attempt - 1));
            try { await Task.Delay(delay, ct); }
            catch (TaskCanceledException) { return new SendResult(false, 0, "Vorgang abgebrochen."); }
        }
        return new SendResult(false, code, lastMessage);
    }
}
