using ZeroTrace.Core.Models;
using System.Net.NetworkInformation;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects network-level cheat infrastructure: DMA radar protocol artifacts,
/// cheat license server connections, and suspicious network configuration.
///
/// Modern multi-PC cheat setups use network protocols to communicate between:
///   - A DMA card reading game memory on the gaming PC
///   - An external "radar PC" processing and displaying the data
///   - The gaming PC receiving aim coordinates via network
///
/// Network artifacts of cheat setups:
///
///   hosts file modifications:
///     - Anti-cheat update/license server domains blocked (battleye.com → 127.0.0.1)
///     - Cheat CDN domains added (cheat.gg → IP for offline license bypass)
///
///   TCP port patterns:
///     - Port 41337 (pcileech default), 31337 (l33t hacker default)
///     - Port 13337 (DMA radar default), 1234/1337 (cheat API commonly)
///     - Localhost servers on known cheat IPC ports
///
///   DNS configuration anomalies:
///     - Custom DNS server replacing ISP DNS (to resolve cheat license domains privately)
///     - DoH (DNS over HTTPS) to Cloudflare/AdGuard to hide cheat DNS queries
///
///   Network interface anomalies:
///     - Multiple simultaneous VPN connections (HWID bypassing via IP rotation)
///     - ZeroTier/Tailscale with default "zerotier" network name (DMA cheat LAN)
///
/// Ocean and detect.ac perform network protocol analysis because:
///   - Hosts file AC-blocking is a reliable signal
///   - DMA radar TCP connections to the gaming PC are detectable
///   - Cheat license server IPs appear in DNS cache and TCP connection table
/// </summary>
public sealed class CheatNetworkProtocolScanModule : IScanModule
{
    public string Name => "Cheat Netzwerk-Protokoll und Hosts-Datei Forensik Scan";
    public double Weight => 0.5;
    public int ParallelGroup => 3;

    // Anti-cheat domains that cheats block via hosts file
    private static readonly string[] AntiCheatDomains =
    {
        "battleye.com", "be.lol", "be.counter-strike.net",
        "easyanticheat.net", "easy.ac", "eac.battleye.com",
        "vanguard.riotgames.com", "faceit.com", "esea.net",
        "steampowered.com", "steamcommunity.com",
        "valve.net", "valvesoftware.com",
        "xigncode.com", "xhstt.com",
        "ricochet.gg",
    };

    // Cheat distribution/license domains that may be added to hosts
    private static readonly string[] CheatDomains =
    {
        "gamesense.pub", "onetap.com", "fatality.win", "aimware.net",
        "neverlose.cc", "skeet.cc", "ev0lve.xyz", "2take1.menu",
        "kiddion", "cherax", "engineowning.to", "iniuria.us",
        "vapeflux.net", "pcileech.com", "unknowncheats.me",
        "elitepvpers.com", "mpgh.net",
    };

    // Known cheat/DMA radar ports
    private static readonly int[] CheatPorts = { 41337, 31337, 13337, 1337, 4444, 6666, 9999, 12345, 54321 };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        ScanHostsFile(ctx, ct);
        ScanNetworkInterfaces(ctx, ct);
        ScanListeningPorts(ctx, ct);
    }

    private void ScanHostsFile(ScanContext ctx, CancellationToken ct)
    {
        string hostsPath = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "drivers", "etc", "hosts");

        if (!System.IO.File.Exists(hostsPath)) return;

        try
        {
            ctx.IncrementFiles();
            string[] lines = System.IO.File.ReadAllLines(hostsPath);
            var blockedAcDomains = new List<string>();
            var addedCheatDomains = new List<string>();

            foreach (string line in lines)
            {
                ct.ThrowIfCancellationRequested();
                string trimmed = line.Trim();
                if (trimmed.StartsWith('#') || string.IsNullOrEmpty(trimmed)) continue;

                string lineLower = trimmed.ToLowerInvariant();

                // Check for blocked AC domains (pointing to 127.0.0.1 or 0.0.0.0)
                bool isBlock = lineLower.StartsWith("127.0.0.1") || lineLower.StartsWith("0.0.0.0");
                if (isBlock)
                {
                    string? blockedDomain = AntiCheatDomains.FirstOrDefault(d =>
                        lineLower.Contains(d, StringComparison.OrdinalIgnoreCase));
                    if (blockedDomain != null)
                        blockedAcDomains.Add($"{blockedDomain} → {trimmed}");
                }

                // Check for cheat domains added (pointing to real IPs)
                string? cheatDomain = CheatDomains.FirstOrDefault(d =>
                    lineLower.Contains(d, StringComparison.OrdinalIgnoreCase));
                if (cheatDomain != null)
                    addedCheatDomains.Add($"{cheatDomain} → {trimmed}");
            }

            if (blockedAcDomains.Count > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Anti-Cheat-Domains in hosts-Datei blockiert ({blockedAcDomains.Count} Einträge)",
                    Risk     = RiskLevel.Critical,
                    Location = hostsPath,
                    FileName = "hosts",
                    Reason   = $"hosts-Datei blockiert {blockedAcDomains.Count} Anti-Cheat-Domain(s) via " +
                               "127.0.0.1/0.0.0.0. Dies verhindert, dass Anti-Cheat-Software ihre " +
                               "Server für Updates, Bans und Lizenzprüfungen erreicht. Klassische " +
                               "Cheat-Setup-Methode für VAC/EAC/BE-Bypass. Ocean/detect.ac prüfen hosts-Datei.",
                    Detail   = $"Blockiert: {string.Join("; ", blockedAcDomains.Take(5))}"
                });
            }

            if (addedCheatDomains.Count > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Cheat-Domains in hosts-Datei: {addedCheatDomains.Count} Einträge",
                    Risk     = RiskLevel.High,
                    Location = hostsPath,
                    FileName = "hosts",
                    Reason   = $"hosts-Datei enthält Cheat-Domains: {string.Join(", ", addedCheatDomains.Take(3))}. " +
                               "Cheat-Loader modifizieren hosts um Lizenzserver-IPs direkt einzutragen " +
                               "und so offline-Lizenzprüfungen zu ermöglichen.",
                    Detail   = $"Cheat-Domains: {string.Join("; ", addedCheatDomains)}"
                });
            }
        }
        catch { }
    }

    private void ScanNetworkInterfaces(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();
            int vpnCount = 0;
            var vpnNames = new List<string>();

            foreach (var nic in interfaces)
            {
                ct.ThrowIfCancellationRequested();

                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                string name = nic.Name.ToLowerInvariant();
                string desc = nic.Description.ToLowerInvariant();

                bool isVpn = name.Contains("vpn") || desc.Contains("vpn") ||
                             name.Contains("tunnel") || desc.Contains("tunnel") ||
                             desc.Contains("tap-") || desc.Contains("tun") ||
                             name.Contains("wireguard") || desc.Contains("wireguard") ||
                             name.Contains("openvpn") || desc.Contains("openvpn") ||
                             desc.Contains("nordvpn") || desc.Contains("expressvpn");

                if (isVpn)
                {
                    vpnCount++;
                    vpnNames.Add(nic.Name);
                }

                // Check for ZeroTier (DMA cheat LAN)
                if (name.Contains("zerotier") || desc.Contains("zerotier"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"ZeroTier-Netzwerk aktiv: {nic.Name}",
                        Risk     = RiskLevel.High,
                        Location = $"Netzwerk-Interface: {nic.Name}",
                        FileName = nic.Name,
                        Reason   = $"ZeroTier VPN-Adapter '{nic.Name}' ist aktiv. ZeroTier wird für " +
                                   "DMA-Cheat-LANs verwendet um DMA-PC und Radar-PC zu verbinden. " +
                                   "Ocean/detect.ac flaggen ZeroTier auf Gaming-PCs als Cheat-Indikator.",
                        Detail   = $"Interface: {nic.Name} | Description: {nic.Description} | MAC: {nic.GetPhysicalAddress()}"
                    });
                }

                // Check for Tailscale (used for multi-PC cheat setup)
                if (name.Contains("tailscale") || desc.Contains("tailscale"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Tailscale-Netzwerk aktiv: {nic.Name}",
                        Risk     = RiskLevel.High,
                        Location = $"Netzwerk-Interface: {nic.Name}",
                        FileName = nic.Name,
                        Reason   = $"Tailscale VPN-Adapter '{nic.Name}' ist aktiv. Tailscale wird " +
                                   "ähnlich wie ZeroTier für DMA-Cheat Multi-PC-Setups genutzt. " +
                                   "Ermöglicht sichere Kommunikation zwischen Gaming-PC und externem Radar-PC.",
                        Detail   = $"Interface: {nic.Name} | Description: {nic.Description}"
                    });
                }
            }

            if (vpnCount >= 2)
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Mehrere VPN-Adapter aktiv ({vpnCount}) — möglicher HWID-Bypass",
                    Risk     = RiskLevel.Medium,
                    Location = "Netzwerk-Interfaces",
                    FileName = "VPN Adapters",
                    Reason   = $"{vpnCount} aktive VPN-Adapter: {string.Join(", ", vpnNames.Take(5))}. " +
                               "Mehrere gleichzeitige VPNs auf einem Gaming-PC können für IP-Rotation " +
                               "zur HWID-Ban-Umgehung genutzt werden. Ocean/detect.ac flaggen multi-VPN-Setups.",
                    Detail   = $"VPN-Adapter: {string.Join(", ", vpnNames)}"
                });
            }
        }
        catch { }
    }

    private void ScanListeningPorts(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var ipGlobalProps = IPGlobalProperties.GetIPGlobalProperties();

            // Check TCP listeners
            var tcpListeners = ipGlobalProps.GetActiveTcpListeners();
            foreach (var endpoint in tcpListeners)
            {
                ct.ThrowIfCancellationRequested();
                if (!CheatPorts.Contains(endpoint.Port)) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Bekannter Cheat-IPC Port offen (TCP): {endpoint.Port}",
                    Risk     = RiskLevel.High,
                    Location = $"TCP Listener: {endpoint}",
                    FileName = $"Port {endpoint.Port}",
                    Reason   = $"TCP Port {endpoint.Port} ist als Listener geöffnet. " +
                               "Port 41337=PCILeech/DMA, 31337=klassischer Cheat-Port, " +
                               "13337=DMA Radar, 1337=Cheat-API. Diese Ports werden für " +
                               "Cheat-IPC zwischen DMA-PC und Radar-PC verwendet.",
                    Detail   = $"Endpoint: {endpoint} | Port: {endpoint.Port}"
                });
            }

            // Check UDP sockets
            var udpListeners = ipGlobalProps.GetActiveUdpListeners();
            foreach (var endpoint in udpListeners)
            {
                ct.ThrowIfCancellationRequested();
                if (!CheatPorts.Contains(endpoint.Port)) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Bekannter Cheat-Port auf UDP: {endpoint.Port}",
                    Risk     = RiskLevel.High,
                    Location = $"UDP Listener: {endpoint}",
                    FileName = $"Port {endpoint.Port}",
                    Reason   = $"UDP Port {endpoint.Port} ist aktiv — bekannter Cheat-Kommunikations-Port. " +
                               "DMA-Radar-Software sendet Game-State-Pakete per UDP.",
                    Detail   = $"Endpoint: {endpoint} | Port: {endpoint.Port}"
                });
            }
        }
        catch { }
    }
}
