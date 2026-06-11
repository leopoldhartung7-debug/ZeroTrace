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

        try
        {
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var response = await Http.PostAsync(uri, content, ct);
            var code = (int)response.StatusCode;
            return response.IsSuccessStatusCode
                ? new SendResult(true, code, $"Erfolgreich gesendet (HTTP {code}).")
                : new SendResult(false, code, $"Server antwortete mit HTTP {code}.");
        }
        catch (TaskCanceledException)
        {
            return new SendResult(false, 0, "Zeitüberschreitung - Adresse nicht erreichbar?");
        }
        catch (Exception ex)
        {
            return new SendResult(false, 0, "Senden fehlgeschlagen: " + ex.Message);
        }
    }
}
