using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Services;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Collects all SHA-256 hashes found by earlier scan modules (drive scan,
/// process scan, driver scan) and submits them to the ZeroTrace cloud
/// indicator database for cross-reference against:
///
///   • Global cheat tool hash blocklist (updated daily from live samples)
///   • Community-reported cheat hashes
///   • YARA-matched suspicious patterns found in other scans
///
/// Only file hashes are transmitted — no file names, paths, or personal data.
/// The machine is identified by a privacy-preserving HMAC of its hardware ID;
/// this cannot be reversed to identify the user.
///
/// This module runs AFTER the drive scan so all hashes are already collected.
/// It is opt-in (disabled by default); enable via ScanOptions.ScanCloudAnalysis.
/// Requires outbound HTTPS connectivity to the configured endpoint.
/// </summary>
public sealed class CloudAnalysisScanModule : IScanModule
{
    public string Name => "Cloud-Analyse";
    public double Weight => 1.5;
    // Sequential (group 0) — must run after DriveScanModule has populated hashes
    public int ParallelGroup => 0;

    private readonly CloudAnalysisService _service;

    public CloudAnalysisScanModule(CloudAnalysisService service)
    {
        _service = service;
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0, Name, "Sammle Hashes aus vorherigen Modulen...");

        // Collect all SHA-256 hashes already reported by other modules
        List<string> hashes;
        lock (ctx.Findings)
        {
            hashes = ctx.Findings
                .Where(f => !string.IsNullOrEmpty(f.Sha256))
                .Select(f => f.Sha256!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        if (hashes.Count == 0)
        {
            ctx.Report(1.0, Name, "Keine Hashes zum Ueberpruefen");
            return;
        }

        ctx.Report(0.2, Name, $"Sende {hashes.Count} Hashes an Cloud-Datenbank...");

        List<CloudFinding>? cloudFindings;
        try
        {
            cloudFindings = await _service.LookupHashesAsync(hashes, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = "Cloud-Analyse nicht verfuegbar",
                Risk     = RiskLevel.Low,
                Location = "Cloud-API",
                Reason   = "Die Cloud-Analyse konnte nicht ausgefuehrt werden: " + ex.Message +
                           " Lokale Erkennung ist weiterhin aktiv."
            });
            ctx.Report(1.0, Name);
            return;
        }

        ctx.Report(0.8, Name, $"{cloudFindings?.Count ?? 0} Cloud-Treffer");

        foreach (var cf in cloudFindings ?? Enumerable.Empty<CloudFinding>())
        {
            ctx.AddFinding(new Finding
            {
                Module    = Name,
                Title     = $"Cloud-Datenbank-Treffer: {cf.ThreatName}",
                Risk      = cf.RiskLevel,
                Location  = cf.Sha256,
                Sha256    = cf.Sha256,
                FileName  = cf.KnownFileName ?? cf.Sha256,
                Reason    = $"Hash '{cf.Sha256}' ist in der globalen Cloud-Datenbank bekannt: " +
                            $"'{cf.ThreatName}'. Kategorie: {cf.Category}. " +
                            cf.Description,
                Detail    = $"Cloud-Quelle: {cf.Source} | Erstmals gesehen: {cf.FirstSeen:yyyy-MM-dd}"
            });
        }

        ctx.Report(1.0, Name, "Cloud-Analyse abgeschlossen");
    }
}
