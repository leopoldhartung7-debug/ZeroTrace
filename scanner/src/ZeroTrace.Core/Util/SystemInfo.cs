namespace ZeroTrace.Core.Util;

/// <summary>Lightweight, read-only system facts shown on the dashboard.</summary>
public static class SystemInfo
{
    public static string MachineName => Environment.MachineName;
    public static string UserName => Environment.UserName;
    public static string OsVersion => Environment.OSVersion.VersionString;
    public static int ProcessorCount => Environment.ProcessorCount;
    public static bool Is64BitOs => Environment.Is64BitOperatingSystem;
    public static bool FiveMInstalled => KnownPaths.FindFiveMDirectory() is not null;
    public static string? FiveMPath => KnownPaths.FindFiveMDirectory();

    /// <summary>Human-readable list of all detected GTA-MP frameworks.</summary>
    public static string MpFrameworksSummary
    {
        get
        {
            var found = KnownPaths.FindMpFrameworks().ToList();
            return found.Count == 0
                ? "Keine Installation gefunden"
                : string.Join(", ", found.Select(f => $"{f.Name} ({f.Root})"));
        }
    }

    private static readonly string[] VpnHints =
    {
        "vpn", "tap-windows", "tap adapter", "tun", "wintun", "wireguard", "openvpn",
        "nordlynx", "proton", "mullvad", "pangp", "anyconnect", "zerotier", "softether",
        "expressvpn", "surfshark", "hide.me", "windscribe"
    };

    /// <summary>
    /// Collects a read-only PC-info snapshot for the dashboard. Never makes an
    /// outbound network call; the HWID is hashed; only non-sensitive host facts
    /// are gathered.
    /// </summary>
    public static Models.SystemSnapshot Capture()
    {
        var s = new Models.SystemSnapshot
        {
            System = BuildSystemString(),
            IpAddresses = LocalIpv4(),
            Hwid = ComputeHwid(),
            BootTime = WmiDate("Win32_OperatingSystem", "LastBootUpTime")?.ToLocalTime().ToString("yyyy-MM-dd HH:mm"),
            InstallDate = WmiDate("Win32_OperatingSystem", "InstallDate")?.ToLocalTime().ToString("yyyy-MM-dd"),
            Vpn = DetectVpn(),
            Country = SystemRegion(),
            Game = DetectGame(),
            HardwareStats = BuildHardwareStats()
        };
        return s;
    }

    private static string BuildSystemString()
    {
        var caption = Wmi("Win32_OperatingSystem", "Caption");
        var build = Wmi("Win32_OperatingSystem", "BuildNumber");
        var arch = Is64BitOs ? "64-bit" : "32-bit";
        if (string.IsNullOrWhiteSpace(caption)) return $"{OsVersion} ({arch})";
        return $"{caption?.Trim()}{(build is null ? "" : $" Build {build}")} \u00b7 {arch}";
    }

    private static List<string> LocalIpv4()
    {
        var list = new List<string>();
        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    {
                        var ip = ua.Address.ToString();
                        if (!list.Contains(ip)) list.Add(ip);
                    }
                }
            }
        }
        catch { }
        return list;
    }

    private static string ComputeHwid()
    {
        // Stable, opaque hardware fingerprint: machine GUID + board/BIOS/CPU IDs,
        // one-way hashed so no raw serials ever leave the machine.
        var parts = new[]
        {
            ReadMachineGuid(),
            Wmi("Win32_BaseBoard", "SerialNumber"),
            Wmi("Win32_BIOS", "SerialNumber"),
            Wmi("Win32_Processor", "ProcessorId"),
            Wmi("Win32_ComputerSystemProduct", "UUID")
        };
        var seed = string.Join("|", parts.Where(p => !string.IsNullOrWhiteSpace(p)));
        if (seed.Length == 0) seed = MachineName + "|" + Environment.UserName;
        using var sha = System.Security.Cryptography.SHA256.Create();
        var hash = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(seed));
        return Convert.ToHexString(hash);
    }

    private static string? ReadMachineGuid()
    {
        try
        {
            using var k = Microsoft.Win32.RegistryKey
                .OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64)
                .OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            return k?.GetValue("MachineGuid")?.ToString();
        }
        catch { return null; }
    }

    private static string DetectVpn()
    {
        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                var hay = (ni.Name + " " + ni.Description).ToLowerInvariant();
                var hit = VpnHints.FirstOrDefault(h => hay.Contains(h));
                if (hit is not null)
                    return $"Aktiv (Heuristik): {ni.Description}";
            }
        }
        catch { }
        return "Nicht erkannt (Heuristik)";
    }

    private static string SystemRegion()
    {
        try
        {
            var r = System.Globalization.RegionInfo.CurrentRegion;
            return $"{r.EnglishName} ({r.TwoLetterISORegionName}) \u00b7 System-Region, kein Geo-IP";
        }
        catch { return "Unbekannt"; }
    }

    private static string DetectGame()
    {
        var names = KnownPaths.FindMpFrameworks().Select(f => f.Name).ToList();
        return names.Count == 0 ? "Unbekannt" : string.Join(", ", names);
    }

    private static string BuildHardwareStats()
    {
        var cpu = Wmi("Win32_Processor", "Name")?.Trim();
        var gpu = Wmi("Win32_VideoController", "Name")?.Trim();
        string? ram = null;
        var totalRaw = Wmi("Win32_ComputerSystem", "TotalPhysicalMemory");
        if (long.TryParse(totalRaw, out var bytes) && bytes > 0)
            ram = $"{Math.Round(bytes / 1024d / 1024d / 1024d)} GB";

        var parts = new List<string>();
        if (cpu is not null) parts.Add($"CPU: {cpu}");
        if (gpu is not null) parts.Add($"GPU: {gpu}");
        if (ram is not null) parts.Add($"RAM: {ram}");
        return parts.Count == 0 ? "Not available" : string.Join(" \u00b7 ", parts);
    }

    // --- tiny WMI helpers ------------------------------------------------------

    private static string? Wmi(string cls, string prop)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher($"SELECT {prop} FROM {cls}");
            foreach (System.Management.ManagementObject mo in searcher.Get())
            {
                var v = mo[prop]?.ToString();
                if (!string.IsNullOrWhiteSpace(v)) return v;
            }
        }
        catch { }
        return null;
    }

    private static DateTime? WmiDate(string cls, string prop)
    {
        var raw = Wmi(cls, prop);
        if (string.IsNullOrWhiteSpace(raw)) return null;
        try { return System.Management.ManagementDateTimeConverter.ToDateTime(raw); }
        catch { return null; }
    }
}
