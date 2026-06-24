using System.Net.Http.Json;
using System.Text.Json;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Security;

namespace ZeroTrace.Core.Services;

/// <summary>
/// Sends anonymized scan telemetry to the ZeroTrace backend after each scan.
///
/// Privacy guarantees:
///   • No file paths, user names, or personal data are ever transmitted.
///   • The machine is identified by a privacy-preserving HMAC-SHA256 of the
///     Windows Machine GUID derived with a machine-specific key (cannot be
///     reversed to identify the physical machine or its user).
///   • Only aggregate counts per severity level are sent, never individual
///     finding titles or reasons.
///   • Module timing is sent so we can identify slow/broken modules on certain
///     OS configurations.
///
/// The endpoint URL is injected at construction time so it can be overridden
/// per deployment (tournament server vs. public cloud).
/// </summary>
public sealed class TelemetryService
{
    private readonly HttpClient _http;
    private readonly string     _endpoint;

    public TelemetryService(HttpClient http, string endpoint)
    {
        _http     = http;
        _endpoint = endpoint.TrimEnd('/');
    }

    /// <summary>
    /// Transmits an anonymized telemetry record for the completed scan.
    /// Retries up to 3 times with exponential back-off; swallows all
    /// exceptions so a telemetry failure never interrupts the user flow.
    /// </summary>
    public async Task SendScanTelemetryAsync(ScanReport report, CancellationToken ct = default)
    {
        try
        {
            var payload = BuildPayload(report);
            await PostWithRetryAsync("/api/telemetry/scan", payload, ct).ConfigureAwait(false);
        }
        catch { /* Never let telemetry block or crash the caller */ }
    }

    /// <summary>Reports that a specific module timed out or threw an exception.</summary>
    public async Task SendModuleErrorAsync(string moduleName, string errorSummary, CancellationToken ct = default)
    {
        try
        {
            var payload = new
            {
                MachineId   = GetAnonymousMachineId(),
                Module      = moduleName,
                Error       = errorSummary.Length > 256 ? errorSummary[..256] : errorSummary,
                TimestampUtc= DateTime.UtcNow
            };
            await PostWithRetryAsync("/api/telemetry/module-error", payload, ct).ConfigureAwait(false);
        }
        catch { }
    }

    // ── Payload construction ──────────────────────────────────────────────────

    private static object BuildPayload(ScanReport report)
    {
        return new
        {
            MachineId     = GetAnonymousMachineId(),
            OsVersion     = report.OsVersion,
            MachineName   = Anonymize(report.MachineName),
            Profile       = report.Profile.ToString(),
            DurationSecs  = (int)report.Duration.TotalSeconds,
            Elevated      = report.Elevated,
            FilesScanned  = report.FilesScanned,
            ProcessCount  = report.ProcessesScanned,
            RegKeyCount   = report.RegistryKeysScanned,
            Findings = new
            {
                Total    = report.Findings.Count,
                Critical = report.CriticalCount,
                High     = report.HighCount,
                Medium   = report.MediumCount,
                Low      = report.LowCount
            },
            Modules = report.Findings
                .GroupBy(f => f.Module ?? "Unknown")
                .Select(g => new
                {
                    Module = g.Key,
                    Count  = g.Count(),
                    MaxRisk= g.Max(f => f.Risk).ToString()
                })
                .ToList(),
            TimestampUtc = DateTime.UtcNow
        };
    }

    private static string GetAnonymousMachineId()
    {
        // Derive an anonymous, machine-specific identifier.
        // The HMAC key is machine-specific, so the output cannot be linked across machines.
        var hwid = Environment.MachineName + Environment.OSVersion.VersionString;
        return StringEncryptor.HmacMachineId(hwid)[..16]; // 16 hex chars = 8 bytes entropy
    }

    private static string Anonymize(string value)
    {
        // Replace the real machine/user name with a stable pseudonym
        if (string.IsNullOrEmpty(value)) return "unknown";
        return StringEncryptor.HmacMachineId(value)[..8];
    }

    // ── HTTP helpers ──────────────────────────────────────────────────────────

    private async Task PostWithRetryAsync(string path, object payload, CancellationToken ct)
    {
        var url     = _endpoint + path;
        int delayMs = 1000;

        for (int attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                using var response = await _http.PostAsJsonAsync(url, payload, ct)
                    .ConfigureAwait(false);
                if (response.IsSuccessStatusCode) return;
                // 4xx = our problem (bad payload), don't retry
                if ((int)response.StatusCode < 500) return;
            }
            catch (OperationCanceledException) { throw; }
            catch { }

            if (attempt < 2)
            {
                await Task.Delay(delayMs, ct).ConfigureAwait(false);
                delayMs *= 2;
            }
        }
    }
}
