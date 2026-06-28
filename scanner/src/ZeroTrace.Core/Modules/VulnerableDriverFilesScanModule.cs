using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Scans the filesystem for known vulnerable BYOVD (Bring Your Own Vulnerable Driver) .sys files.
///
/// BYOVD attacks load a legitimate but vulnerable signed driver to gain kernel code execution.
/// The vulnerable driver is typically dropped to disk, loaded via sc.exe/NtLoadDriver, exploited
/// for kernel R/W (IOCTL), then optionally deleted. However:
///   - Cheats often keep the driver on disk (especially in Temp/AppData) for quick re-load
///   - Some cheat loaders drop it to a predictable location and never clean up
///   - The driver file may remain after a service deletion if cleanup failed
///
/// Known BYOVD drivers targeted by cheat tools:
///   mhyprot2.sys  — Genshin Impact anti-cheat (most common BYOVD for AC bypass)
///   RTCore64.sys  — MSI Afterburner (used by multiple cheat tools)
///   WinRing0x64.sys — OpenHardwareMonitor (ring-0 R/W capability)
///   gdrv.sys      — Gigabyte driver (used for BYOVD since 2019)
///   dbutil_2_3.sys — Dell firmware update (used for privilege escalation)
///   AsIO3.sys     — ASUS hardware monitoring
///   cpuz143.sys   — CPU-Z (IOCTL exposes kernel R/W)
///   ALCPU64.sys   — Core Temp
///   nvoclock.sys  — nVidia overclock tool
///   HookLib.sys   — HookKit
///   HackerShield.sys — HackerShield
///
/// Ocean and detect.ac scan common paths (System32\drivers, Temp, AppData, Downloads, game dirs)
/// for these driver files because their presence off-path is highly suspicious.
/// </summary>
public sealed class VulnerableDriverFilesScanModule : IScanModule
{
    public string Name => "Bekannte BYOVD Vulnerable Driver Dateien Scan";
    public double Weight => 0.7;
    public int ParallelGroup => 3;

    private static readonly (string FileName, string Description)[] KnownVulnDrivers =
    {
        // === Tier 1: Most commonly used by cheat tools ===
        ("mhyprot2.sys",    "Genshin Impact Anti-Cheat BYOVD (Ring-0 R/W, häufigster Cheat-BYOVD)"),
        ("mhyprot3.sys",    "Genshin Impact Anti-Cheat v3 BYOVD"),
        ("RTCore64.sys",    "MSI Afterburner / Riva Tuner BYOVD (Ring-0 R/W via IOCTL)"),
        ("RTCore32.sys",    "MSI Afterburner 32-bit BYOVD"),
        ("WinRing0x64.sys", "OpenHardwareMonitor BYOVD (Ring-0 R/W, weitverbreitet)"),
        ("WinRing0.sys",    "OpenHardwareMonitor 32-bit BYOVD"),
        ("gdrv.sys",        "Gigabyte BYOVD Treiber (Ring-0 via physischem Speicher-IOCTL)"),
        ("gdrv2.sys",       "Gigabyte BYOVD v2"),
        ("dbutil_2_3.sys",  "Dell Firmware Update BYOVD (Privilege Escalation)"),
        // === Tier 2: Used in documented cheat/exploit campaigns ===
        ("AsIO3.sys",       "ASUS BIOS/HW Monitor BYOVD"),
        ("AsIO2.sys",       "ASUS System Info BYOVD"),
        ("cpuz145.sys",     "CPU-Z v1.45 BYOVD (kernel R/W IOCTL)"),
        ("cpuz143.sys",     "CPU-Z v1.43 BYOVD"),
        ("cpuz141.sys",     "CPU-Z v1.41 BYOVD"),
        ("cpuz136.sys",     "CPU-Z v1.36 BYOVD"),
        ("ALCPU64.sys",     "Core Temp BYOVD (IOCTL kernel R/W)"),
        ("ALCpu.sys",       "Core Temp 32-bit BYOVD"),
        ("nvoclock.sys",    "nVidia OC BYOVD"),
        ("nicm.sys",        "Novatel Wireless BYOVD"),
        ("hetzbga.sys",     "HetzbgA rootkit helper"),
        ("phymem64.sys",    "Physical Memory driver BYOVD"),
        ("procexp.sys",     "Process Explorer signed driver (abused for PID spoofing/token steal)"),
        ("procexp152.sys",  "Process Explorer 15.2 driver"),
        ("kprocesshacker.sys", "Process Hacker ring-0 driver"),
        ("nkvirtmem.sys",   "NVRAM virtual memory driver BYOVD"),
        ("iobitunlocker.sys", "IObit Unlocker driver (weak IOCTL)"),
        ("ene.sys",         "ENE Tech BYOVD"),
        ("EneTechIo64.sys", "ENE Tech IO64 BYOVD"),
        // === Tier 3: BYOVD drivers for cheat persistence ===
        ("HookLib.sys",     "HookKit driver (unsigned hook helper)"),
        ("Dbk64.sys",       "Cheat Engine kernel driver"),
        ("Dbk32.sys",       "Cheat Engine 32-bit kernel driver"),
        ("HackerShield.sys","HackerShield ring-0 driver"),
        ("viragt64.sys",    "Vir.IT anti-rootkit driver (abused)"),
        ("msio64.sys",      "MSI Dragon Center driver (BYOVD)"),
        ("msio32.sys",      "MSI Dragon Center 32-bit driver"),
        ("dellbios.sys",    "Dell BIOS driver BYOVD"),
        ("bs_i2cIo.sys",    "BS I2C BYOVD"),
        ("EneIo64.sys",     "ENE IO64 driver"),
        ("iqvw64e.sys",     "Intel Network Adapter Diagnostics BYOVD"),
        ("iqvw32e.sys",     "Intel Network Adapter 32-bit BYOVD"),
    };

    // Paths to search for vulnerable driver files
    private static readonly string[] SearchSubdirs =
    {
        // System driver directory (legitimate location — check if unexpected ones present)
        // We flag ALL known vuln drivers even in System32\drivers since they may be planted
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string appData     = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localApp    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string sysRoot     = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string sysTemp     = System.IO.Path.GetTempPath();

        var searchRoots = new List<string>
        {
            sysTemp,
            System.IO.Path.Combine(userProfile, "Downloads"),
            System.IO.Path.Combine(userProfile, "Desktop"),
            System.IO.Path.Combine(userProfile, "Documents"),
            appData,
            localApp,
            System.IO.Path.Combine(sysRoot, "System32", "drivers"),
            // Also search Steam game directories for BYOVD drivers dropped next to games
            System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Steam", "steamapps", "common"),
        };

        // Add alt Steam roots
        foreach (char drive in "DEFG")
        {
            string alt = $@"{drive}:\SteamLibrary\steamapps\common";
            if (System.IO.Directory.Exists(alt)) searchRoots.Add(alt);
        }

        // Build lookup set for O(1) matching
        var driverLookup = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (fileName, description) in KnownVulnDrivers)
            driverLookup[fileName] = description;

        foreach (string root in searchRoots)
        {
            ct.ThrowIfCancellationRequested();
            if (!System.IO.Directory.Exists(root)) continue;
            ScanDirectory(ctx, root, driverLookup, root, ct);
        }
    }

    private void ScanDirectory(ScanContext ctx, string dir, Dictionary<string, string> lookup,
        string searchRoot, CancellationToken ct, int depth = 0)
    {
        if (depth > 5) return;
        ct.ThrowIfCancellationRequested();

        try
        {
            foreach (string file in System.IO.Directory.EnumerateFiles(dir, "*.sys",
                         System.IO.SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                string fileName = System.IO.Path.GetFileName(file);

                if (!lookup.TryGetValue(fileName, out string? description)) continue;

                // Determine risk: in System32\drivers may be a legitimate install;
                // everywhere else is highly suspicious
                bool inSystem32 = dir.Contains("System32", StringComparison.OrdinalIgnoreCase) &&
                                  dir.Contains("drivers", StringComparison.OrdinalIgnoreCase);
                var risk = inSystem32 ? RiskLevel.High : RiskLevel.Critical;

                long fileSize = 0;
                try { fileSize = new System.IO.FileInfo(file).Length; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Bekannter BYOVD Treiber auf Disk: {fileName}",
                    Risk     = risk,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"Datei '{fileName}' ist ein dokumentierter BYOVD-Treiber: {description}. " +
                               "BYOVD-Treiber werden von Cheats genutzt, um Ring-0-Zugriff zu erlangen, " +
                               "Anti-Cheat-Prozesse zu beenden, und Kernel-Speicher zu lesen/schreiben. " +
                               "Ocean/detect.ac scannen bekannte BYOVD-Dateien in allen User-Verzeichnissen.",
                    Detail   = $"Datei: {file} | Größe: {fileSize} Bytes | In System32: {inSystem32}"
                });
            }

            // Recurse
            try
            {
                foreach (string subDir in System.IO.Directory.GetDirectories(dir))
                {
                    ct.ThrowIfCancellationRequested();
                    string subName = System.IO.Path.GetFileName(subDir);
                    // Skip known-safe subdirs
                    if (subName is "node_modules" or ".git" or "WinSxS" or "en-US") continue;
                    ScanDirectory(ctx, subDir, lookup, searchRoot, ct, depth + 1);
                }
            }
            catch { }
        }
        catch { }
    }
}
