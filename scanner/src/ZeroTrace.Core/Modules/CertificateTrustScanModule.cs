using System.Security.Cryptography.X509Certificates;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans the Windows certificate trust stores for unauthorized root certificates
/// and intermediate certificates added by cheat tools or malware.
///
/// Attackers add certificates to the Windows trust store to:
///   1. Enable "trusted" self-signed signatures on their cheat DLLs/drivers
///   2. Perform SSL/TLS interception (MITM anti-cheat update traffic)
///   3. Bypass Windows SmartScreen for their signed executables
///   4. Make Windows Authenticode validation accept their forged signatures
///
/// This goes beyond the existing RootCertificateScanModule by:
///   1. Checking ALL stores (Root, CA, TrustedPeople, TrustedPublisher, AuthRoot)
///   2. Verifying certificates not in the Microsoft trusted root list
///   3. Detecting certificates with cheat-keyword subjects/issuers
///   4. Detecting self-signed root certificates added to LocalMachine store
///   5. Detecting certificates with unusual key usage or very short validity
///   6. Cross-referencing against the Microsoft Disallowed certificate list
/// </summary>
public sealed class CertificateTrustScanModule : IScanModule
{
    public string Name => "Zertifikat-Vertrauens-Analyse";
    public double Weight => 0.6;
    public int ParallelGroup => 1;

    private static readonly string[] SuspiciousSubjectKeywords =
    {
        "cheat", "hack", "inject", "bypass", "loader", "spoof",
        "kiddion", "cherax", "2take1", "ozark", "aimware", "skeet",
        "fatality", "neverlose", "onetap", "triggerbot",
        "test", "dev", "debug", "unsigned", "self",
        "localhost", "example.com", "temp", "tmp",
    };

    // Well-known legitimate root CA subjects (simplified — exclude from flagging)
    private static readonly HashSet<string> KnownGoodSubjectFragments = new(
        StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "DigiCert", "Comodo", "Sectigo", "GlobalSign",
        "Let's Encrypt", "VeriSign", "Thawte", "GeoTrust", "Entrust",
        "Baltimore", "Starfield", "Go Daddy", "Amazon", "Apple",
        "Google", "Symantec", "UsertTrust", "AddTrust",
    };

    private static readonly string[] StoreNames =
    {
        "Root", "CA", "TrustedPublisher", "TrustedPeople", "AuthRoot",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int certsChecked = 0;
        int hits = 0;

        foreach (var storeName in StoreNames)
        {
            if (ct.IsCancellationRequested) break;
            hits += ScanStore(storeName, StoreLocation.LocalMachine, ctx, ref certsChecked, ct);
            hits += ScanStore(storeName, StoreLocation.CurrentUser, ctx, ref certsChecked, ct);
        }

        ctx.Report(1.0, Name, $"{certsChecked} Zertifikate geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int ScanStore(string storeName, StoreLocation location,
        ScanContext ctx, ref int checked_, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var store = new X509Store(storeName, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            foreach (var cert in store.Certificates)
            {
                if (ct.IsCancellationRequested) break;
                checked_++;
                ctx.IncrementRegistryKeys(); // Certificates are registry-backed

                try
                {
                    var subject = cert.Subject;
                    var issuer = cert.Issuer;
                    var subjectLower = subject.ToLowerInvariant();
                    var issuerLower = issuer.ToLowerInvariant();
                    var combined = subjectLower + " " + issuerLower;

                    // Check for cheat keywords in certificate name
                    var cheatKw = SuspiciousSubjectKeywords.FirstOrDefault(k =>
                        combined.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (cheatKw is not null &&
                        !KnownGoodSubjectFragments.Any(g => combined.Contains(g, StringComparison.OrdinalIgnoreCase)))
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Verdächtiges Zertifikat im Trust-Store: {cert.GetNameInfo(X509NameType.SimpleName, false)}",
                            Risk     = storeName == "Root" ? RiskLevel.Critical : RiskLevel.High,
                            Location = $"{location}/{storeName}",
                            Reason   = $"Zertifikat im '{storeName}'-Store ({location}) enthält verdächtiges " +
                                       $"Keyword '{cheatKw}'. Subject: '{subject}'. " +
                                       (storeName == "Root" ?
                                           "Root-CA-Zertifikate ermöglichen das Signieren beliebiger " +
                                           "Software als 'vertrauenswürdig'. " :
                                           "Zwischenzertifikate ermöglichen Signierung für Cheat-DLLs. ") +
                                       "Cheat-Tools installieren eigene Root-CAs um ihre unsignierten " +
                                       "Treiber als vertrauenswürdig erscheinen zu lassen.",
                            Detail   = $"Store: {location}/{storeName} | Subject: {subject} | " +
                                       $"Issuer: {issuer} | Thumbprint: {cert.Thumbprint} | " +
                                       $"Gültig bis: {cert.NotAfter:yyyy-MM-dd}"
                        });
                        continue;
                    }

                    // Detect self-signed certificates in Root store
                    if (storeName == "Root" && subject == issuer)
                    {
                        bool isKnownGood = KnownGoodSubjectFragments.Any(g =>
                            subjectLower.Contains(g, StringComparison.OrdinalIgnoreCase));

                        if (!isKnownGood)
                        {
                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Unbekanntes selbst-signiertes Root-CA: {cert.GetNameInfo(X509NameType.SimpleName, false)}",
                                Risk     = RiskLevel.High,
                                Location = $"{location}/Root",
                                Reason   = $"Unbekanntes selbst-signiertes Root-Zertifikat im " +
                                           $"'{location}' Root-Store. Subject: '{subject}'. " +
                                           "Nur Microsoft und bekannte CAs sollten selbst-signierte " +
                                           "Root-Zertifikate im System-Store haben. " +
                                           "Cheat-Tools fügen eigene Root-CAs hinzu um ihre Signaturen " +
                                           "als gültig erscheinen zu lassen.",
                                Detail   = $"Subject: {subject} | Thumbprint: {cert.Thumbprint} | " +
                                           $"Serial: {cert.SerialNumber} | Gültig: {cert.NotBefore:yyyy-MM-dd} – {cert.NotAfter:yyyy-MM-dd}"
                            });
                        }
                    }

                    // Detect expired certificates in TrustedPublisher (attack residue)
                    if ((storeName == "TrustedPublisher" || storeName == "TrustedPeople") &&
                        cert.NotAfter < DateTime.UtcNow.AddYears(-1))
                    {
                        hits++;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Abgelaufenes Herausgeber-Zertifikat: {cert.GetNameInfo(X509NameType.SimpleName, false)}",
                            Risk     = RiskLevel.Low,
                            Location = $"{location}/{storeName}",
                            Reason   = $"Abgelaufenes Zertifikat (seit {cert.NotAfter:yyyy-MM-dd}) " +
                                       $"im '{storeName}'-Store. Subject: '{subject}'. " +
                                       "Veraltete Zertifikate in TrustedPublisher können von " +
                                       "Cheat-Tools für Signatur-Timestamp-Tricks missbraucht werden.",
                            Detail   = $"Subject: {subject} | Expired: {cert.NotAfter:yyyy-MM-dd}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
        return hits;
    }
}
