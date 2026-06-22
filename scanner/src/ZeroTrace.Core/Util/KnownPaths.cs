using Microsoft.Win32;

namespace ZeroTrace.Core.Util;

/// <summary>Central place for well-known filesystem locations used by the scanner.</summary>
public static class KnownPaths
{
    public static string LocalAppData =>
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    public static string RoamingAppData =>
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    public static string UserProfile =>
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    public static string Temp => Path.GetTempPath();

    public static string Downloads => Path.Combine(UserProfile, "Downloads");

    public static string StartupUser =>
        Environment.GetFolderPath(Environment.SpecialFolder.Startup);

    public static string StartupCommon =>
        Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);

    /// <summary>Folder the application stores its database and exports in.</summary>
    public static string AppDataDir
    {
        get
        {
            var dir = Path.Combine(LocalAppData, "ZeroTrace");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    public static string DatabasePath => Path.Combine(AppDataDir, "zerotrace.db");

    public static string ReportsDir
    {
        get
        {
            var dir = Path.Combine(AppDataDir, "Reports");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    /// <summary>
    /// Returns the FiveM application directory if it exists, otherwise null.
    /// FiveM installs per-user under %LocalAppData%\FiveM by default.
    /// </summary>
    public static string? FindFiveMDirectory()
    {
        var candidates = new[]
        {
            Path.Combine(LocalAppData, "FiveM"),
            Path.Combine(LocalAppData, "FiveM", "FiveM.app")
        };
        return candidates.FirstOrDefault(Directory.Exists);
    }

    /// <summary>
    /// Returns the RAGE Multiplayer (RageMP) directory if found. RageMP has no
    /// single fixed location, so several common install/data paths are probed.
    /// </summary>
    public static string? FindRageMpDirectory()
    {
        var candidates = new[]
        {
            Path.Combine(RoamingAppData, "RAGE Multiplayer"),
            Path.Combine(LocalAppData, "RAGE Multiplayer"),
            Path.Combine(UserProfile, "Documents", "RAGEMP"),
            @"C:\RAGEMP",
            @"C:\Program Files\RAGE Multiplayer",
            @"C:\Program Files (x86)\RAGE Multiplayer"
        };
        return candidates.FirstOrDefault(Directory.Exists);
    }

    /// <summary>
    /// Returns the alt:V directory if found. The alt:V launcher/client commonly
    /// lives under %LocalAppData%\altv; a few alternates are probed too.
    /// </summary>
    public static string? FindAltVDirectory()
    {
        var candidates = new[]
        {
            Path.Combine(LocalAppData, "altv"),
            Path.Combine(LocalAppData, "altv-launcher"),
            Path.Combine(RoamingAppData, "altv"),
            Path.Combine(UserProfile, "Documents", "altv"),
            @"C:\altv",
            @"C:\altv-launcher"
        };
        return candidates.FirstOrDefault(Directory.Exists);
    }

    /// <summary>
    /// Enumerates the installed GTA-V multiplayer frameworks (FiveM, RageMP,
    /// alt:V) that were found on this machine, as (name, root) pairs. The
    /// dedicated framework scan iterates over all of them.
    /// </summary>
    public static IEnumerable<(string Name, string Root)> FindMpFrameworks()
    {
        var fivem = FindFiveMDirectory();
        if (fivem is not null) yield return ("FiveM", fivem);

        var rage = FindRageMpDirectory();
        if (rage is not null) yield return ("RageMP", rage);

        var altv = FindAltVDirectory();
        if (altv is not null) yield return ("alt:V", altv);
    }

    /// <summary>
    /// Returns the GTA-MP framework ("FiveM"/"RageMP"/"alt:V") a process belongs
    /// to — by process name or by its image living under a framework directory —
    /// otherwise null. Used to escalate DLLs injected into a framework process.
    /// </summary>
    public static string? MpFrameworkForProcess(string processName, string? imagePath)
    {
        var n = processName;
        if (n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) n = n[..^4];

        if (n.Equals("FiveM", StringComparison.OrdinalIgnoreCase) ||
            n.StartsWith("FiveM_", StringComparison.OrdinalIgnoreCase) ||
            n.Equals("CitizenFX", StringComparison.OrdinalIgnoreCase))
            return "FiveM";

        if (n.Equals("ragemp_v", StringComparison.OrdinalIgnoreCase) ||
            n.Equals("ragemp", StringComparison.OrdinalIgnoreCase) ||
            n.Equals("updater", StringComparison.OrdinalIgnoreCase) && IsUnderAny(imagePath, FindRageMpDirectory()))
            return "RageMP";

        if (n.Equals("altv", StringComparison.OrdinalIgnoreCase) ||
            n.Equals("altv-client", StringComparison.OrdinalIgnoreCase) ||
            n.Equals("altv-crash-handler", StringComparison.OrdinalIgnoreCase))
            return "alt:V";

        foreach (var (name, root) in FindMpFrameworks())
            if (IsUnderAny(imagePath, root)) return name;

        return null;
    }

    private static bool IsUnderAny(string? path, string? root)
    {
        if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(root)) return false;
        try
        {
            return Path.GetFullPath(path)
                .StartsWith(Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }

    /// <summary>
    /// Returns the set of high-signal directories scanned in the default
    /// (non-deep) drive scan: the locations cheats most commonly land in.
    /// </summary>
    public static IEnumerable<string> TargetedScanRoots()
    {
        var roots = new List<string>
        {
            Downloads,
            Temp,
            Path.Combine(LocalAppData, "Temp"),
            // System temp — written by SYSTEM-level processes and loaders
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            Path.Combine(UserProfile, "Desktop"),
            Path.Combine(UserProfile, "Documents"),
            Path.Combine(RoamingAppData),
            Path.Combine(LocalAppData)
        };

        // C:\Users\Public — accessible to all users, occasionally used for multi-user cheat drops
        var pub = Environment.GetEnvironmentVariable("PUBLIC");
        if (!string.IsNullOrEmpty(pub)) roots.Add(pub);

        // ProgramData — many cheats/spoofers install services or configs here
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (!string.IsNullOrEmpty(programData)) roots.Add(programData);

        // VirtualStore — UAC-virtualized writes from apps without proper write permissions
        roots.Add(Path.Combine(LocalAppData, "VirtualStore"));

        // User-installed programs (winget, MSIX sideload, some cheat loaders use this path)
        roots.Add(Path.Combine(LocalAppData, "Programs"));

        // Steam install directory (covers steamapps\workshop and game-level cheat drops)
        var steam = FindSteamDirectory();
        if (steam is not null) roots.Add(steam);

        var fivem = FindFiveMDirectory();
        if (fivem is not null) roots.Add(fivem);

        foreach (var (_, root) in FindMpFrameworks())
            roots.Add(root);

        return roots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Returns the Steam installation directory by reading its registry key,
    /// or null if Steam is not installed or the registry is inaccessible.
    /// Covers both per-user (HKCU) and machine-wide (HKLM) installs.
    /// </summary>
    public static string? FindSteamDirectory()
    {
        try
        {
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                using var key = hive.OpenSubKey(@"SOFTWARE\Valve\Steam", writable: false)
                             ?? hive.OpenSubKey(@"SOFTWARE\WOW6432Node\Valve\Steam", writable: false);
                var path = key?.GetValue("SteamPath")?.ToString()
                        ?? key?.GetValue("InstallPath")?.ToString();
                if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                    return path;
            }
        }
        catch { }
        return null;
    }
}
