using Microsoft.Win32;
using System.Diagnostics;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) configuration changes used
/// by cheats to hide C2 communication from network monitoring tools.
///
/// Standard DNS queries are plaintext and visible to:
///   - Network monitoring (Wireshark, Fiddler)
///   - ISP/firewall logging
///   - Anti-cheat network analysis
///   - DNS-based domain blocking
///
/// Cheat C2 infrastructure hides behind DoH/DoT because:
///   1. DoH traffic looks identical to normal HTTPS to packet inspectors
///   2. DNS-based domain blocking (used by ACs) is bypassed
///   3. Even if the IP is blocked, SNI can be hidden via ECH/ESNI
///   4. DoH providers (Cloudflare, Google) don't log or share query data
///
/// Suspicious DoH configurations:
///   1. DoH explicitly configured system-wide (unusual for gaming PCs)
///   2. Custom DoH server pointing to non-major provider (private cheat C2 DoH)
///   3. DNS server changed to known DoH proxy addresses (1.1.1.1, 8.8.8.8 bypassed
///      by pointing to a local DoH-to-regular DNS proxy that bypasses corporate controls)
///   4. HOSTS file hijacking (covered separately, but DNS is related)
///   5. processes with direct port 853 (DoT) or port 443 DNS connections
///
/// Registry paths:
///   HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\
///     ServerAddresses — override DNS servers
///     DnsOverHttpsTemplates — DoH template URIs
///   HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\
///     (proxy settings — related)
/// </summary>
public sealed class DnsOverHttpsScanModule : IScanModule
{
    public string Name => "DNS-Konfiguration-Analyse";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    private const string DnsCacheKey =
        @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";

    // Known-legitimate DoH providers (major public DNS)
    private static readonly HashSet<string> LegitimateDoHProviders = new(StringComparer.OrdinalIgnoreCase)
    {
        "https://cloudflare-dns.com/dns-query",
        "https://dns.cloudflare.com/dns-query",
        "https://1.1.1.1/dns-query",
        "https://1.0.0.1/dns-query",
        "https://dns.google/dns-query",
        "https://8.8.8.8/dns-query",
        "https://8.8.4.4/dns-query",
        "https://dns.quad9.net/dns-query",
        "https://9.9.9.9/dns-query",
        "https://doh.opendns.com/dns-query",
        "https://doh.familyshield.opendns.com/dns-query",
    };

    // DNS server IPs that are suspicious (not major public resolvers)
    private static readonly HashSet<string> KnownGoodDnsServers = new()
    {
        "1.1.1.1", "1.0.0.1",         // Cloudflare
        "8.8.8.8", "8.8.4.4",         // Google
        "9.9.9.9", "149.112.112.112",  // Quad9
        "208.67.222.222", "208.67.220.220", // OpenDNS
        "64.6.64.6", "64.6.65.6",     // Verisign
        "::1", "127.0.0.1",           // Loopback (valid)
    };

    // Cheat-related keywords in DoH template URIs
    private static readonly string[] SuspiciousUriKeywords =
    {
        "cheat", "hack", "bypass", "priv", "private",
        "anon", "stealth", "vpn",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        hits += CheckDoHConfiguration(ctx, ct);
        hits += CheckDnsServerOverride(ctx, ct);
        hits += CheckHostsFile(ctx, ct);
        hits += CheckDnsClientPolicy(ctx, ct);

        ctx.Report(1.0, Name, $"DNS-Konfiguration geprüft, {hits} verdächtig");
        return Task.CompletedTask;
    }

    private static int CheckDoHConfiguration(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(DnsCacheKey, writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            // Check DoH template
            var dohTemplate = key.GetValue("DnsOverHttpsTemplates") as string ?? "";
            if (!string.IsNullOrEmpty(dohTemplate))
            {
                bool isLegit = LegitimateDoHProviders.Any(p =>
                    dohTemplate.Contains(p, StringComparison.OrdinalIgnoreCase));

                var kw = SuspiciousUriKeywords.FirstOrDefault(k =>
                    dohTemplate.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (!isLegit || kw is not null)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "DNS-Konfiguration-Analyse",
                        Title    = kw is not null
                            ? $"Verdächtiger DoH-Server: {dohTemplate[..Math.Min(60, dohTemplate.Length)]}"
                            : "Unbekannter DNS-over-HTTPS-Server konfiguriert",
                        Risk     = kw is not null ? RiskLevel.High : RiskLevel.Medium,
                        Location = $@"HKLM\{DnsCacheKey}",
                        Reason   = $"DoH-Template: '{dohTemplate}' — " +
                                   (kw is not null
                                       ? $"enthält Cheat-Keyword '{kw}'. "
                                       : "kein bekannter öffentlicher DoH-Anbieter. ") +
                                   "DNS-over-HTTPS verbirgt DNS-Anfragen vor Netzwerk-Monitoring. " +
                                   "Cheat-C2-Infrastruktur nutzt custom DoH-Server, " +
                                   "um Domain-Lookups vor Anti-Cheat-Netzwerkanalyse zu verstecken.",
                        Detail   = $"DnsOverHttpsTemplates: {dohTemplate}"
                    });
                }
            }

            // Check DoH exclusions (can be used to bypass corporate DoH enforcement)
            var dohExclusions = key.GetValue("DnsOverHttpsExclusionList") as string ?? "";
            if (!string.IsNullOrEmpty(dohExclusions))
            {
                // If AC/game domains are excluded from DoH, their traffic is plaintext
                // while cheat C2 uses DoH — selective evasion
                // This is low signal standalone, skip
            }
        }
        catch { }
        return hits;
    }

    private static int CheckDnsServerOverride(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check per-adapter DNS server overrides
            using var ifacesKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces", writable: false);
            if (ifacesKey is null) return 0;
            ctx.IncrementRegistryKeys();

            foreach (var ifGuid in ifacesKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) break;
                using var ifKey = ifacesKey.OpenSubKey(ifGuid, writable: false);
                if (ifKey is null) continue;

                var nameServer = ifKey.GetValue("NameServer") as string ?? "";
                if (string.IsNullOrEmpty(nameServer)) continue;

                var servers = nameServer.Split(new[] { ',', ';', ' ' },
                    StringSplitOptions.RemoveEmptyEntries);

                foreach (var server in servers)
                {
                    if (ct.IsCancellationRequested) break;
                    var ip = server.Trim();

                    if (!KnownGoodDnsServers.Contains(ip))
                    {
                        // Unknown DNS server — might be a cheat proxy
                        // Only flag if it's not a private/local IP
                        if (!IsPrivateIp(ip) && System.Net.IPAddress.TryParse(ip, out _))
                        {
                            hits++;
                            ctx.AddFinding(new Finding
                            {
                                Module   = "DNS-Konfiguration-Analyse",
                                Title    = $"Unbekannter DNS-Server konfiguriert: {ip}",
                                Risk     = RiskLevel.Medium,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{ifGuid}",
                                Reason   = $"DNS-Server '{ip}' auf Netzwerkadapter '{ifGuid}' " +
                                           "ist kein bekannter öffentlicher DNS-Resolver. " +
                                           "Cheat-Software kann eigene DNS-Server konfigurieren, " +
                                           "die Anfragen an bekannte Anti-Cheat-Domains unterdrücken " +
                                           "oder cheat-eigene Domains auflösen.",
                                Detail   = $"Adapter: {ifGuid} | DNS-Server: {nameServer}"
                            });
                        }
                    }
                }
            }
        }
        catch { }
        return hits;
    }

    private static int CheckHostsFile(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            var hostsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "drivers", "etc", "hosts");

            if (!File.Exists(hostsPath)) return 0;
            ctx.IncrementFiles();

            var lines = File.ReadAllLines(hostsPath);
            var antiCheatDomains = new[]
            {
                "easy.anticheat", "battleye", "vanguard", "faceit",
                "eac", "rockstargames", "valve", "steamcdn",
                "battlenet", "blizzard", "epicgames", "riot",
                "akamai", "cloudfront",
            };

            foreach (var line in lines)
            {
                if (ct.IsCancellationRequested) break;
                var trimmed = line.Trim();
                if (trimmed.StartsWith("#") || string.IsNullOrEmpty(trimmed)) continue;

                var blockedDomain = antiCheatDomains.FirstOrDefault(d =>
                    trimmed.Contains(d, StringComparison.OrdinalIgnoreCase));

                if (blockedDomain is not null && trimmed.StartsWith("0.0.0.0") ||
                    trimmed.StartsWith("127.0.0.1") && blockedDomain is not null)
                {
                    hits++;
                    ctx.AddFinding(new Finding
                    {
                        Module   = "DNS-Konfiguration-Analyse",
                        Title    = $"HOSTS-Datei blockiert Anti-Cheat-Domain: {blockedDomain}",
                        Risk     = RiskLevel.Critical,
                        Location = hostsPath,
                        Reason   = $"Die Windows HOSTS-Datei enthält einen Eintrag, der " +
                                   $"die Anti-Cheat/Spiel-Domain '{blockedDomain}' auf " +
                                   "127.0.0.1 oder 0.0.0.0 umleitet (blockiert). " +
                                   "Cheats blockieren Anti-Cheat-Server in der HOSTS-Datei, " +
                                   "um Telemetrie zu verhindern oder Update-Server zu blockieren.",
                        Detail   = $"HOSTS-Eintrag: {trimmed} | Domain-Pattern: {blockedDomain}"
                    });
                }
            }

            // Check for unusually large HOSTS file (many entries = spoofer tool)
            if (lines.Length > 500)
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "DNS-Konfiguration-Analyse",
                    Title    = $"HOSTS-Datei ungewöhnlich groß: {lines.Length} Einträge",
                    Risk     = RiskLevel.Medium,
                    Location = hostsPath,
                    Reason   = $"Die HOSTS-Datei enthält {lines.Length} Zeilen. " +
                               "Normal ist eine fast leere HOSTS-Datei (< 30 Einträge). " +
                               "Große HOSTS-Dateien werden oft von IP-Spoofern oder Tracking-Blockern " +
                               "installiert, können aber auch Anti-Cheat-Domains blockieren.",
                    Detail   = $"Einträge: {lines.Length}"
                });
            }
        }
        catch { }
        return hits;
    }

    private static int CheckDnsClientPolicy(ScanContext ctx, CancellationToken ct)
    {
        int hits = 0;
        try
        {
            // Check if DNS client service is disabled (blocks Windows DNS resolution)
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\Dnscache", writable: false);
            if (key is null) return 0;
            ctx.IncrementRegistryKeys();

            var startType = key.GetValue("Start") as int? ?? 2;
            if (startType == 4) // Disabled
            {
                hits++;
                ctx.AddFinding(new Finding
                {
                    Module   = "DNS-Konfiguration-Analyse",
                    Title    = "DNS-Client-Dienst deaktiviert",
                    Risk     = RiskLevel.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache",
                    Reason   = "Der DNS-Client-Dienst (dnscache) ist deaktiviert. " +
                               "Dieser Dienst cached DNS-Anfragen und ist Standardmäßig aktiv. " +
                               "Deaktiviert kann Cheat-Software direkte DNS-Anfragen stellen, " +
                               "die nicht durch Windows-DNS-Filtering gehen.",
                    Detail   = $"Dnscache Start: {startType} (4=Disabled)"
                });
            }
        }
        catch { }
        return hits;
    }

    private static bool IsPrivateIp(string ip)
    {
        try
        {
            if (!System.Net.IPAddress.TryParse(ip, out var addr)) return false;
            var bytes = addr.GetAddressBytes();
            if (bytes.Length == 4) // IPv4
            {
                return bytes[0] == 10 ||
                       (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                       (bytes[0] == 192 && bytes[1] == 168) ||
                       bytes[0] == 127;
            }
            return false;
        }
        catch { return false; }
    }
}
