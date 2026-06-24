using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ZeroTrace.Core.Services;

/// <summary>
/// Auto-update service: checks the ZeroTrace update endpoint for a newer
/// scanner version, downloads the update binary, verifies its SHA-256 hash,
/// and writes it to a staging path for the installer to apply.
///
/// Security properties:
///   • Version endpoint is served over HTTPS — man-in-the-middle would need
///     a valid cert for the configured host.
///   • Downloaded binary is verified against the SHA-256 published in the
///     version manifest before it is written to disk.
///   • The update is written to a TEMP path, not overwriting the running
///     binary; the installer (or a restart) performs the swap.
/// </summary>
public sealed class UpdateService
{
    private readonly HttpClient _http;
    private readonly string     _endpoint;

    public UpdateService(HttpClient http, string endpoint)
    {
        _http     = http;
        _endpoint = endpoint.TrimEnd('/');
    }

    /// <summary>
    /// Checks the version endpoint. Returns null if the current version is
    /// up-to-date or the check fails. Returns <see cref="UpdateInfo"/> if a
    /// newer version is available.
    /// </summary>
    public async Task<UpdateInfo?> CheckForUpdateAsync(
        string currentVersion,
        CancellationToken ct = default)
    {
        try
        {
            var manifest = await _http
                .GetFromJsonAsync<VersionManifest>(_endpoint + "/api/update/latest", ct)
                .ConfigureAwait(false);

            if (manifest is null) return null;

            var current = ParseVersion(currentVersion);
            var latest  = ParseVersion(manifest.Version);

            if (latest <= current) return null;

            return new UpdateInfo
            {
                LatestVersion = manifest.Version,
                DownloadUrl   = manifest.DownloadUrl,
                Sha256        = manifest.Sha256.ToUpperInvariant(),
                ReleaseNotes  = manifest.ReleaseNotes ?? string.Empty,
                PublishedUtc  = manifest.PublishedUtc
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Downloads the update from <paramref name="info"/>.DownloadUrl to
    /// <paramref name="stagingPath"/> and verifies its SHA-256 hash.
    /// Returns true on success.
    /// </summary>
    public async Task<bool> DownloadAndVerifyAsync(
        UpdateInfo info,
        string stagingPath,
        IProgress<double>? progress = null,
        CancellationToken ct = default)
    {
        try
        {
            using var response = await _http.GetAsync(
                info.DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);

            response.EnsureSuccessStatusCode();

            var totalBytes = response.Content.Headers.ContentLength ?? -1L;
            var tmpPath    = stagingPath + ".download";

            await using (var src  = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
            await using (var dest = File.Create(tmpPath))
            {
                var buffer    = new byte[81_920];
                long received = 0;
                int  read;
                while ((read = await src.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
                {
                    await dest.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                    received += read;
                    if (totalBytes > 0)
                        progress?.Report((double)received / totalBytes);
                }
            }

            // Verify SHA-256
            string actualHash = ComputeSha256(tmpPath);
            if (!string.Equals(actualHash, info.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                File.Delete(tmpPath);
                return false;
            }

            // Atomic move to staging path
            if (File.Exists(stagingPath)) File.Delete(stagingPath);
            File.Move(tmpPath, stagingPath);
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Version ParseVersion(string v)
    {
        return Version.TryParse(v, out var ver) ? ver : new Version(0, 0);
    }

    private static string ComputeSha256(string path)
    {
        using var sha = SHA256.Create();
        using var fs  = File.OpenRead(path);
        return Convert.ToHexString(sha.ComputeHash(fs));
    }

    // ── DTOs ─────────────────────────────────────────────────────────────────

    private sealed class VersionManifest
    {
        [JsonPropertyName("version")]    public string  Version      { get; set; } = "";
        [JsonPropertyName("downloadUrl")]public string  DownloadUrl  { get; set; } = "";
        [JsonPropertyName("sha256")]     public string  Sha256       { get; set; } = "";
        [JsonPropertyName("notes")]      public string? ReleaseNotes { get; set; }
        [JsonPropertyName("published")]  public DateTime PublishedUtc { get; set; }
    }
}

public sealed class UpdateInfo
{
    public string   LatestVersion { get; set; } = "";
    public string   DownloadUrl   { get; set; } = "";
    public string   Sha256        { get; set; } = "";
    public string   ReleaseNotes  { get; set; } = "";
    public DateTime PublishedUtc  { get; set; }
}
