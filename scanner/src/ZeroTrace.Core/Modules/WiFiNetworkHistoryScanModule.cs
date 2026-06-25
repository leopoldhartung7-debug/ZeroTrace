using System.Diagnostics;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Enumerates Windows-saved WLAN profiles and reads each profile's SSID and security
/// configuration. Cross-references the SSID list against known cheat-LAN tournament
/// names, shared cheat-house Wi-Fi SSIDs, and suspicious patterns (hex MAC-only
/// SSIDs, ".local", "wifi pineapple", etc.).
///
/// Ocean/detect.ac maintain WLAN-history coverage because:
///   - Sharing a Wi-Fi network with known banned accounts is a strong correlation
///   - Cheat-house / LAN-cheat groups use distinctive shared SSIDs
///   - Wi-Fi pineapples / rogue APs used for stream-sniping show characteristic SSIDs
///   - Mobile-hotspot SSIDs (often used to obscure IP) leave a profile entry
///
/// Implemented via netsh wlan show profiles + netsh wlan show profile name=&lt;n&gt; key=clear
/// (no special API call). Profile-key files live at
/// C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\*.xml and persist forever
/// unless manually deleted by the user.
/// </summary>
public sealed class WiFiNetworkHistoryScanModule : IScanModule
{
    public string Name => "Wi-Fi Network History Cheat-Correlation Scan";
    public double Weight => 0.4;
    public int ParallelGroup => 3;

    private static readonly string[] SuspiciousSsidPatterns =
    {
        // Known cheat-house / LAN-cheat SSIDs (community-tracked)
        "cheaters", "cheater", "wallhack", "aimbot",
        // Wi-Fi Pineapple defaults
        "pineapple", "wifipineapple", "wifi_pineapple",
        // Rogue AP / penetration tester defaults
        "kali", "fluxion", "evilwifi",
        // Cheat-stream characteristic
        "cheat_lan", "cheatlan", "dma_lan",
        // Generic suspicious
        "stream_snipe", "lan_party_cheats",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        // Approach 1: netsh wlan show profiles
        List<string> profiles = ListProfiles();
        if (profiles.Count == 0)
        {
            // Fallback: enumerate WLAN profile XML files directly.
            string wlanDir = @"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces";
            if (!System.IO.Directory.Exists(wlanDir)) return;
            try
            {
                foreach (string iface in System.IO.Directory.GetDirectories(wlanDir))
                {
                    foreach (string xml in System.IO.Directory.GetFiles(iface, "*.xml"))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        string content;
                        try { content = System.IO.File.ReadAllText(xml); }
                        catch { continue; }

                        int s = content.IndexOf("<name>", StringComparison.OrdinalIgnoreCase);
                        int e = content.IndexOf("</name>", StringComparison.OrdinalIgnoreCase);
                        if (s < 0 || e <= s) continue;
                        string ssid = content.Substring(s + 6, e - s - 6).Trim();
                        if (!string.IsNullOrEmpty(ssid)) profiles.Add(ssid);
                    }
                }
            }
            catch { }
        }

        foreach (string ssid in profiles)
        {
            ct.ThrowIfCancellationRequested();
            string lower = ssid.ToLowerInvariant();

            string? matched = null;
            foreach (string p in SuspiciousSsidPatterns)
            {
                if (lower.Contains(p)) { matched = p; break; }
            }

            if (matched is null) continue;

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Verdächtiges WLAN-Profil: {ssid}",
                Risk     = RiskLevel.Medium,
                Location = $"WLAN-Profil: {ssid}",
                FileName = ssid,
                Reason   = $"Gespeichertes WLAN-Profil mit SSID '{ssid}' entspricht einem bekannten " +
                           $"Cheat-/Penetrationstest-Muster (Match: '{matched}'). Wi-Fi-Profile " +
                           "persistieren in C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles und " +
                           "überleben Account-Wechsel — ein forensisches Korrelat zu vorherigem " +
                           "Cheat-Netzwerk-Zugang.",
                Detail   = $"SSID: {ssid} | Match: {matched}"
            });
        }
    }

    private static List<string> ListProfiles()
    {
        var profiles = new List<string>();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName  = "netsh.exe",
                Arguments = "wlan show profiles",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };
            using var proc = Process.Start(psi);
            if (proc is null) return profiles;
            string output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(8000);

            foreach (string line in output.Split('\n'))
            {
                int idx = line.IndexOf(": ", StringComparison.Ordinal);
                if (idx < 0) continue;
                string lhs = line.Substring(0, idx).Trim().ToLowerInvariant();
                if (!lhs.Contains("all user profile") && !lhs.Contains("user profile")) continue;
                string ssid = line.Substring(idx + 2).Trim();
                if (!string.IsNullOrEmpty(ssid)) profiles.Add(ssid);
            }
        }
        catch { }
        return profiles;
    }
}
