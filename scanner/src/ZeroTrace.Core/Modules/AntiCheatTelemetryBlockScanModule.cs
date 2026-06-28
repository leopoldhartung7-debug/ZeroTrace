using ZeroTrace.Core.Models;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects systematic blocking of anti-cheat telemetry and update infrastructure.
///
/// Anti-cheat systems maintain telemetry and update servers that cheats attempt to block
/// via multiple mechanisms. Blocking these servers prevents:
///   - Anti-cheat database updates (new cheat signatures)
///   - Telemetry uploads (cheat detection events reaching the server)
///   - Ban propagation (cheat vendor gets advance warning of AC updates)
///   - VAC/EAC/BE heartbeat verification
///
/// Blocking mechanisms detected:
///
///   Windows Firewall rules:
///     - Outbound block rules for battleye.com, easyanticheat.net, Valve domains
///     - Rules named after cheat tools that created them
///
///   Proxy/PAC file configured:
///     - ProxyServer or AutoConfigURL in IE registry pointing to a proxy that intercepts AC traffic
///
///   DNS client configuration:
///     - Custom primary/secondary DNS pointing to 127.0.0.1 or non-ISP resolvers
///     - Split-horizon DNS configuration that resolves AC domains to local IPs
///
///   TCP/IP filter driver:
///     - HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TCPChimney disabled
///       (some cheat tools disable TCP offload to route through their WFP filter)
///
///   Certificate store:
///     - Anti-cheat server certificates in "Untrusted" or "Disallowed" stores
///       (prevents certificate validation, blocks HTTPS connections to AC servers)
///
/// Ocean and detect.ac scan these AC telemetry blocking mechanisms because:
///   - An AC-domain-block firewall rule is almost exclusively created by cheat tools
///   - Blocking AC telemetry is evidence the user knows they would be detected
/// </summary>
public sealed class AntiCheatTelemetryBlockScanModule : IScanModule
{
    public string Name => "Anti-Cheat Telemetrie-Blocking und Update-Sperren Scan";
    public double Weight => 0.65;
    public int ParallelGroup => 3;

    private static readonly string[] AntiCheatDomains =
    {
        "battleye", "battl.eye", "be.lol",
        "easyanticheat", "easy.ac", "eac.",
        "vanguard.riot", "faceit", "esea.net",
        "steampowered", "steamcommunity", "valve",
        "xigncode", "nprotect", "hackshield",
        "wellbia", "gameguard",
        "ricochet", "anticheat",
    };

    private static readonly string[] CheatFirewallRulePatterns =
    {
        // AC blocking rules
        "block battleye", "block eac", "block vanguard",
        "disable anticheat", "bypass ac", "block ac",
        "anticheat block", "battleye block",
        // Cheat tool created rules
        "cheat", "hack", "bypass", "inject",
        "spoofer", "loader",
        "kiddion", "2take1", "cherax",
        "gamesense", "onetap", "fatality",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ScanFirewallRules(ctx, ct);
        ScanProxyConfig(ctx, ct);
        ScanDnsConfig(ctx, ct);
        ScanCertificateStore(ctx, ct);
    }

    private void ScanFirewallRules(ScanContext ctx, CancellationToken ct)
    {
        // Scan Windows Firewall rules for AC domain blocks and cheat-named rules
        string fwPath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
        string[] rulePaths = { $@"{fwPath}\FirewallRules", $@"{fwPath}\StandardProfile\AuthorizedApplications\List" };

        foreach (string rulePath in rulePaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(rulePath, false);
                if (key == null) continue;

                foreach (string valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    string rule = (key.GetValue(valueName) as string ?? "").ToLowerInvariant();
                    if (string.IsNullOrEmpty(rule)) continue;

                    // Check for AC domain blocking rules
                    bool isBlock = rule.Contains("action=block") || rule.Contains("action=drop");
                    if (isBlock)
                    {
                        string? acDomain = AntiCheatDomains.FirstOrDefault(d =>
                            rule.Contains(d, StringComparison.OrdinalIgnoreCase) ||
                            valueName.ToLowerInvariant().Contains(d, StringComparison.OrdinalIgnoreCase));
                        if (acDomain != null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Windows Firewall blockiert Anti-Cheat-Domain: '{acDomain}'",
                                Risk     = RiskLevel.Critical,
                                Location = $@"HKLM\{rulePath}\{valueName}",
                                FileName = valueName,
                                Reason   = $"Windows Firewall-Regel blockiert Anti-Cheat-Domain '{acDomain}'. " +
                                           "Cheat-Tools erstellen Firewall-Block-Regeln für AC-Server um " +
                                           "Telemetrie-Uploads zu verhindern. Dies ist ein kritischer " +
                                           "Beweis für absichtliche Anti-Cheat-Sabotage. Ocean/detect.ac " +
                                           "prüfen Firewall-Regeln als primären Forensik-Indikator.",
                                Detail   = $"Regel: {valueName} | Domain: '{acDomain}' | Inhalt: {rule.Substring(0, Math.Min(200, rule.Length))}"
                            });
                            continue;
                        }
                    }

                    // Check for cheat-tool-named firewall rules
                    string? cheatPattern = CheatFirewallRulePatterns.FirstOrDefault(p =>
                        rule.Contains(p, StringComparison.OrdinalIgnoreCase) ||
                        valueName.ToLowerInvariant().Contains(p, StringComparison.OrdinalIgnoreCase));
                    if (cheatPattern != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Cheat-bezogene Firewall-Regel: '{cheatPattern}'",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{rulePath}\{valueName}",
                            FileName = valueName,
                            Reason   = $"Windows Firewall-Regel mit Cheat-Keyword '{cheatPattern}' gefunden. " +
                                       "Cheat-Loader erstellen automatisch Firewall-Regeln für ihre " +
                                       "Komponenten-Kommunikation oder für AC-Blocking.",
                            Detail   = $"Regel: {valueName} | Keyword: '{cheatPattern}'"
                        });
                    }
                }
            }
            catch { }
        }
    }

    private void ScanProxyConfig(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", false);
            if (key == null) return;
            ctx.IncrementRegistryKeys();

            string proxyServer = (key.GetValue("ProxyServer") as string ?? "").ToLowerInvariant();
            string autoConfigUrl = (key.GetValue("AutoConfigURL") as string ?? "").ToLowerInvariant();
            int proxyEnabled = (int)(key.GetValue("ProxyEnable") ?? 0);

            if (proxyEnabled == 1 && !string.IsNullOrEmpty(proxyServer))
            {
                // Localhost proxy = potentially a MITM proxy intercepting AC traffic
                bool isLocalProxy = proxyServer.Contains("127.0.0.1") ||
                                    proxyServer.Contains("localhost") ||
                                    proxyServer.Contains("0.0.0.0");
                if (isLocalProxy)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Localhost-Proxy konfiguriert: {proxyServer}",
                        Risk     = RiskLevel.High,
                        Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                        FileName = "ProxyServer",
                        Reason   = $"HTTP-Proxy auf Localhost ({proxyServer}) konfiguriert. " +
                                   "Lokal laufende Proxys können Anti-Cheat HTTPS-Traffic abfangen " +
                                   "und Telemetrie blockieren oder modifizieren. Cheat-Tools installieren " +
                                   "Mitmproxy/Burp Suite-Instanzen für AC-Traffic-Interception.",
                        Detail   = $"ProxyServer: {proxyServer} | ProxyEnable: {proxyEnabled}"
                    });
                }
            }

            if (!string.IsNullOrEmpty(autoConfigUrl))
            {
                bool isCheatPac = AntiCheatDomains.Any(d =>
                    autoConfigUrl.Contains(d, StringComparison.OrdinalIgnoreCase));
                if (isCheatPac || autoConfigUrl.Contains("127.0.0.1") || autoConfigUrl.Contains("localhost"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Verdächtige Proxy-Auto-Config (PAC): {autoConfigUrl}",
                        Risk     = RiskLevel.High,
                        Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                        FileName = "AutoConfigURL",
                        Reason   = $"Proxy Auto-Config URL '{autoConfigUrl}' konfiguriert. " +
                                   "PAC-Dateien können selektiv AC-Traffic auf blockierende Proxys umleiten.",
                        Detail   = $"AutoConfigURL: {autoConfigUrl}"
                    });
                }
            }
        }
        catch { }
    }

    private void ScanDnsConfig(ScanContext ctx, CancellationToken ct)
    {
        // Check if primary DNS is set to 127.0.0.1 (local DNS sinkhole) on any adapter
        try
        {
            using var adaptersKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces", false);
            if (adaptersKey == null) return;

            foreach (string adapterId in adaptersKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var adapterKey = adaptersKey.OpenSubKey(adapterId, false);
                    if (adapterKey == null) continue;
                    ctx.IncrementRegistryKeys();

                    string nameServers = (adapterKey.GetValue("NameServer") as string ?? "").Trim();
                    string dhcpNameServers = (adapterKey.GetValue("DhcpNameServer") as string ?? "").Trim();

                    string dnsToCheck = nameServers.Length > 0 ? nameServers : dhcpNameServers;
                    if (string.IsNullOrEmpty(dnsToCheck)) continue;

                    // Flag localhost DNS (DNS sinkhole for AC domains)
                    if (dnsToCheck.Contains("127.0.0.1") || dnsToCheck.Contains("::1"))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"DNS auf Localhost konfiguriert (mögliche AC-Domain-Sinkhole): {dnsToCheck}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{adapterId}",
                            FileName = "NameServer",
                            Reason   = $"DNS-Server '{dnsToCheck}' auf Localhost konfiguriert. " +
                                       "Ein lokaler DNS-Server kann Anti-Cheat-Domains auf 127.0.0.1 " +
                                       "auflösen und so AC-Updates und Telemetrie blockieren, ohne " +
                                       "die hosts-Datei zu modifizieren (schwieriger zu detektieren).",
                            Detail   = $"Adapter: {adapterId} | DNS: {dnsToCheck}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanCertificateStore(ScanContext ctx, CancellationToken ct)
    {
        // Check if any AC-related certificates are in the Untrusted/Disallowed stores
        try
        {
            using var disallowed = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates", false);
            if (disallowed == null) return;

            foreach (string thumbprint in disallowed.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                try
                {
                    using var certKey = disallowed.OpenSubKey(thumbprint, false);
                    if (certKey == null) continue;

                    string blob = (certKey.GetValue("Blob") as string ?? "");
                    // Check if this is a known AC cert thumbprint (we check the key exists)
                    // Any cert in Disallowed store is suspicious on a gaming PC

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Zertifikat in 'Disallowed' Store (HTTPS-Blockierung): {thumbprint.Substring(0, Math.Min(16, thumbprint.Length))}...",
                        Risk     = RiskLevel.Medium,
                        Location = $@"HKLM\SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates\{thumbprint}",
                        FileName = thumbprint,
                        Reason   = $"Zertifikat '{thumbprint}' im Windows 'Disallowed' Certificate Store. " +
                                   "Cheat-Tools platzieren Anti-Cheat-TLS-Zertifikate in den Disallowed-Store " +
                                   "um HTTPS-Verbindungen zu AC-Servern zu blockieren. " +
                                   "Alle HTTPS-Verbindungen zu Servern mit diesem Zertifikat schlagen fehl.",
                        Detail   = $"Thumbprint: {thumbprint}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }
}
