using System.Security.Cryptography.X509Certificates;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Inspects the Windows certificate stores for anomalous root certificates:
///   - Any root CA installed in the CURRENT USER store (always unusual; legitimate
///     software installs to LOCAL MACHINE);
///   - Root CAs in the LOCAL MACHINE store with suspiciously recent validity start
///     dates (recently injected by software) or with cheat-related keywords in the
///     subject/issuer string.
/// Some cheat licensing systems and traffic-intercepting tools install their own
/// root CA to sign their own HTTPS connections. Read-only.
/// </summary>
public sealed class RootCertificateScanModule : IScanModule
{
    public string Name => "Zertifikatsspeicher";
    public double Weight => 0.3;

    private static readonly string[] CheatKeywords =
    {
        "cheat", "hack", "injector", "loader", "spoofer", "bypass",
        "fiddler", "proxyman", "mitmproxy", "charles", "burpsuite", "burp suite"
    };

    // Root CAs issued by well-known trusted roots are not flagged.
    // We only check for suspiciously recent (< 6 months old) HKLM additions
    // and anything in HKCU.
    private static readonly TimeSpan RecentThreshold = TimeSpan.FromDays(180);

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        CheckCurrentUserRootStore(ctx);
        ctx.Report(0.5, "HKCU-Root", "Benutzer-Stammzertifikate geprueft");

        CheckLocalMachineRootStore(ctx);
        ctx.Report(1.0, "HKLM-Root", "System-Stammzertifikate geprueft");

        return Task.CompletedTask;
    }

    private void CheckCurrentUserRootStore(ScanContext ctx)
    {
        // Any root cert in HKCU is suspicious: legitimate installers use HKLM.
        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            foreach (var cert in store.Certificates)
            {
                if (cert.Subject.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) ||
                    cert.Subject.Contains("Windows", StringComparison.OrdinalIgnoreCase))
                    continue; // built-in Windows certs that appear in both stores

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Stammzertifikat im Benutzer-Speicher (ungewoehnlich)",
                    Risk = RiskLevel.Medium,
                    Recommendation = Recommendation.Review,
                    Location = "HKCU\\SOFTWARE\\Microsoft\\SystemCertificates\\Root",
                    Reason = "Im persoenlichen Zertifikatsspeicher des Benutzers (HKCU) liegt ein " +
                             "Root-Zertifikat. Legitime Software installiert Root-CAs in den " +
                             "System-Speicher (HKLM), nicht in den Benutzer-Speicher. Manche " +
                             "Cheat-Lizenzierungs- oder Traffic-Abfangsysteme verwenden diese " +
                             "Technik um ihren HTTPS-Verkehr zu signieren.",
                    Detail = $"Betreff: {cert.Subject} · Aussteller: {cert.Issuer} " +
                             $"· Gueltig bis: {cert.NotAfter:yyyy-MM-dd}"
                });
            }
        }
        catch { }
    }

    private void CheckLocalMachineRootStore(ScanContext ctx)
    {
        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            var now = DateTime.UtcNow;

            foreach (var cert in store.Certificates)
            {
                var subject = cert.Subject.ToLowerInvariant();
                var issuer = cert.Issuer.ToLowerInvariant();
                var combined = subject + " " + issuer;

                bool hasCheatKw = CheatKeywords.Any(k =>
                    combined.Contains(k, StringComparison.OrdinalIgnoreCase));

                // Flag if cert has a suspicious keyword, OR if it became valid very
                // recently AND is NOT self-signed by a major known authority.
                bool recentlyAdded = (now - cert.NotBefore.ToUniversalTime()) < RecentThreshold;
                bool isMajorCa = combined.Contains("microsoft") ||
                                 combined.Contains("digicert") ||
                                 combined.Contains("globalsign") ||
                                 combined.Contains("comodo") ||
                                 combined.Contains("sectigo") ||
                                 combined.Contains("verisign") ||
                                 combined.Contains("thawte") ||
                                 combined.Contains("entrust") ||
                                 combined.Contains("geotrust") ||
                                 combined.Contains("usertrust") ||
                                 combined.Contains("identrust");

                if (!hasCheatKw && (isMajorCa || !recentlyAdded)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = hasCheatKw
                        ? "Verdaechtiges Stammzertifikat im System-Speicher"
                        : "Kuerzlich hinzugefuegtes Stammzertifikat im System-Speicher",
                    Risk = hasCheatKw ? RiskLevel.High : RiskLevel.Low,
                    Recommendation = Recommendation.Review,
                    Location = "HKLM\\SOFTWARE\\Microsoft\\SystemCertificates\\Root",
                    Reason = hasCheatKw
                        ? $"Das Root-Zertifikat '{cert.Subject}' enthaelt ein verdaechtiges " +
                          "Schluesselwort (Proxy, Cheat, Interceptor). Solche Zertifikate werden " +
                          "installiert um HTTPS-Verkehr zu entschluesseln (SSL-Inspection) oder " +
                          "Cheat-Lizenzen zu signieren."
                        : $"Das Root-Zertifikat '{cert.Subject}' wurde erst kuerzlich " +
                          $"(Gueltig ab: {cert.NotBefore:yyyy-MM-dd}) zum System hinzugefuegt und " +
                          "stammt nicht von einer bekannten CA. Koennte durch Software mit " +
                          "Netzwerk-Interception-Funktion installiert worden sein.",
                    Detail = $"Betreff: {cert.Subject} · Aussteller: {cert.Issuer} " +
                             $"· Gueltig: {cert.NotBefore:yyyy-MM-dd} – {cert.NotAfter:yyyy-MM-dd}"
                });
            }
        }
        catch { }
    }
}
