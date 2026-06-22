namespace ZeroTrace.Core.Models;

/// <summary>
/// Read-only "PC information" snapshot shown on the organizer dashboard. All
/// values are non-sensitive host facts relevant to anti-cheat identification.
/// The HWID is a one-way hash (no raw serials are transmitted). Public IP and
/// real geo-country are intentionally NOT fetched here (no outbound calls) —
/// the dashboard should derive them from the incoming connection instead.
/// </summary>
public sealed class SystemSnapshot
{
    public string System { get; set; } = "Unknown";
    public List<string> IpAddresses { get; set; } = new();   // local IPv4 only
    public string Hwid { get; set; } = "";                   // SHA-256 hex, opaque
    public string? BootTime { get; set; }                    // local time
    public string Vpn { get; set; } = "Nicht erkannt";       // heuristic
    public string? InstallDate { get; set; }                 // OS install date
    public string Country { get; set; } = "Unbekannt";       // system region (approx)
    public string Game { get; set; } = "Unbekannt";          // detected MP framework(s)
    public string HardwareStats { get; set; } = "Not available"; // CPU / GPU / RAM

    // Mainboard / BIOS facts for the dashboard "Boot sequence" panel. Read from
    // WMI (same sources already used for the HWID hash); non-sensitive.
    public string? BiosVendor { get; set; }
    public string? BiosVersion { get; set; }
    public string? BoardManufacturer { get; set; }
    public string? BoardProduct { get; set; }
    public string? BoardVersion { get; set; }

    public string IpNote { get; set; } =
        "Oeffentliche IP und Land am besten serverseitig aus der Verbindung erfassen (kein Outbound-Call im Scanner).";
}
