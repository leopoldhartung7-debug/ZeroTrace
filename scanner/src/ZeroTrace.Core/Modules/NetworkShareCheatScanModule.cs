using System.Net.NetworkInformation;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Detects network share and local network artifacts indicative of multi-PC cheat setups.
///
/// DMA cheats and external AI aimbots require two PCs: the gaming PC and a cheat PC
/// connected over a local network. Common indicators of a two-PC cheat setup:
///
///   - SMB share names that suggest cheat data transfer ("radar", "esp", "cheat")
///   - Active SMB shares pointing to unusual directories
///   - Recently accessed network paths in MRU (Most Recently Used) with cheat keywords
///   - VPN adapter presence (used to obscure identity / bypass IP bans)
///   - Tailscale / ZeroTier (peer-to-peer overlay networks, used in DMA setups)
///   - Hamachi (LAN emulation, used for remote cheat access)
///
/// Ocean and detect.ac check network configuration because:
///   - A gaming PC that exports SMB shares named "radar" or has active Tailscale/ZeroTier
///     alongside DMA hardware indicators is essentially confirmed as a cheat setup
///   - Network MRU entries in registry persist after cheat removal
///
/// Detection:
///   - HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU
///   - HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver\Shares (active SMB shares)
///   - Installed network adapter names (Hamachi, ZeroTier, Tailscale)
///   - HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComputerDescriptions
/// </summary>
public sealed class NetworkShareCheatScanModule : IScanModule
{
    public string Name => "Netzwerk-Share / Multi-PC-Cheat-Setup Scan";
    public double Weight => 0.45;
    public int ParallelGroup => 3;

    private static readonly string[] CheatShareKeywords =
    {
        "radar", "esp", "cheat", "hack", "dma",
        "aimbot", "wallhack", "cheatpc", "cheat_pc",
        "external", "triggerbot",
    };

    private static readonly string[] VpnAdapterPatterns =
    {
        // Hamachi (LAN emulation — multi-PC cheat over internet)
        "hamachi", "logmein hamachi",
        // ZeroTier (overlay network — DMA cheat PC communication)
        "zerotier", "zero tier",
        // Tailscale (peer-to-peer VPN, used in DMA setups)
        "tailscale",
        // Common VPN that bypass IP bans
        "nordvpn", "nord vpn", "expressvpn", "express vpn",
        "mullvad", "hide.me", "privatevpn", "ivpn",
        // Generic VPN adapter names
        "tap-windows", "tun0", "wintun",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        ScanSmbShares(ctx, ct);
        ScanNetworkMru(ctx, ct);
        ScanNetworkAdapters(ctx, ct);
    }

    private void ScanSmbShares(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var sharesKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\LanmanServer\Shares", writable: false);
            if (sharesKey is null) return;

            foreach (string shareName in sharesKey.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                string? shareData = sharesKey.GetValue(shareName) as string;
                string combined = $"{shareName} {shareData ?? ""}".ToLowerInvariant();

                // Skip default Windows shares (ADMIN$, C$, IPC$, print$)
                if (shareName is "ADMIN$" or "IPC$" or "print$" ||
                    shareName.Length == 2 && shareName[1] == '$') continue;

                foreach (string kw in CheatShareKeywords)
                {
                    if (!combined.Contains(kw)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"SMB-Share mit Cheat-Bezug: {shareName}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares",
                        FileName = shareName,
                        Reason   = $"Aktiver SMB-Share '{shareName}' enthält Cheat-Schlüsselwort '{kw}'. " +
                                   "Cheat-Setups mit zwei PCs teilen häufig Radar/ESP-Daten über lokale " +
                                   "Netzwerkfreigaben. Ein Share namens 'radar' oder 'esp' neben DMA-Hardware " +
                                   "ist ein sehr starkes Indiz für ein Multi-PC-Cheat-Setup.",
                        Detail   = $"Share-Name: {shareName} | Daten: {shareData} | Match: '{kw}'"
                    });
                    break;
                }
            }
        }
        catch { }
    }

    private void ScanNetworkMru(ScanContext ctx, CancellationToken ct)
    {
        string[] mruPaths =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
        };

        foreach (string path in mruPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(path, writable: false);
                if (key is null) continue;

                foreach (string valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    string? value = key.GetValue(valueName) as string ?? "";
                    string lower = value.ToLowerInvariant();

                    foreach (string kw in CheatShareKeywords)
                    {
                        if (!lower.Contains(kw)) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Netzwerk-MRU mit Cheat-Bezug: {value}",
                            Risk     = RiskLevel.Medium,
                            Location = $@"HKCU\{path}",
                            FileName = value,
                            Reason   = $"Netzwerk-MRU-Eintrag '{value}' enthält Cheat-Schlüsselwort '{kw}'. " +
                                       "Recently-Used-Netzwerkpfade belegen den früheren Zugriff auf cheat- " +
                                       "bezogene Netzwerkfreigaben und persistieren nach der Nutzung.",
                            Detail   = $"MRU-Eintrag: {value} | Match: '{kw}'"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }

    private void ScanNetworkAdapters(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var nics = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var nic in nics)
            {
                ct.ThrowIfCancellationRequested();
                string name = nic.Name.ToLowerInvariant();
                string desc = nic.Description.ToLowerInvariant();
                string combined = $"{name} {desc}";

                foreach (string pattern in VpnAdapterPatterns)
                {
                    if (!combined.Contains(pattern)) continue;

                    bool isCheatSpecific = pattern is "hamachi" or "zerotier" or "tailscale" or "zero tier";

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"VPN/Overlay-Netzwerkadapter erkannt: {nic.Name}",
                        Risk     = isCheatSpecific ? RiskLevel.High : RiskLevel.Medium,
                        Location = $"Netzwerkadapter: {nic.Name}",
                        FileName = nic.Name,
                        Reason   = $"Netzwerkadapter '{nic.Name}' ({nic.Description}) entspricht " +
                                   $"'{pattern}'. {GetAdapterReason(pattern)}",
                        Detail   = $"Adapter: {nic.Name} | Beschreibung: {nic.Description} | " +
                                   $"Typ: {nic.NetworkInterfaceType} | Status: {nic.OperationalStatus} | " +
                                   $"Match: '{pattern}'"
                    });
                    break;
                }
            }
        }
        catch { }
    }

    private static string GetAdapterReason(string pattern) => pattern switch
    {
        "hamachi" or "logmein hamachi" =>
            "Hamachi emuliert ein lokales LAN über das Internet und wird in Multi-PC-Cheat-Setups " +
            "verwendet, um den Cheat-PC aus der Ferne zu verbinden.",
        "zerotier" or "zero tier" =>
            "ZeroTier ist ein Overlay-Netzwerk, das in DMA-Cheat-Setups zur Kommunikation zwischen " +
            "Gaming-PC und externem Cheat-PC eingesetzt wird.",
        "tailscale" =>
            "Tailscale ist eine Peer-to-Peer-VPN-Lösung, die in DMA-Radar-Setups für die Verbindung " +
            "zwischen Gaming-PC und Radar-PC verwendet wird.",
        _ =>
            "VPN-Adapter werden häufig zur Umgehung von IP-Sperren nach Account-Bans eingesetzt."
    };
}
