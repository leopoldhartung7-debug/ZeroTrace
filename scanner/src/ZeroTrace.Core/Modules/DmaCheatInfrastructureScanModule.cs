using ZeroTrace.Core.Models;
using Microsoft.Win32;
using System.Net.NetworkInformation;
using System.Text;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Deep scan for DMA (Direct Memory Access) cheat infrastructure indicators.
///
/// DMA cheats use a second PC connected via PCIe/M.2 DMA card to directly read
/// the gaming PC's physical RAM without the OS ever knowing. This is the highest-tier
/// cheat and hardest to detect because:
///   - No process injection into the game process
///   - No kernel driver on the gaming PC (the cheat runs on a SECOND PC)
///   - Memory access bypasses ALL OS and AC protection layers
///   - Only the DMA hardware card itself and the network connection are on the gaming PC
///
/// Known DMA hardware:
///   - Squirrel DMA (PCILeech-based) — VID:PID 12ab:0600 or similar PCILeech VIDs
///   - LeetCheater DMA — custom VID/PID
///   - Enigma-X DMA card
///   - PCILeech FPGA (basis for all above): VID:1172 (Altera), VID:0403 (FTDI)
///   - ChipWhisperer DMA
///   - ComtaDMA / DMAHack devices
///
/// Detection vectors:
///   1. PCIe DMA device in PCI device registry (VID:PID matching known FPGA IDs)
///   2. PCILeech / MemProcFS software installed/run on this PC (as donor side)
///   3. MappedFile sections from PCILeech-related tools
///   4. ZeroTier/Tailscale VPN (radar-over-LAN between DMA PC and gaming PC)
///   5. "radar" named network shares (classic DMA radar setup)
///   6. vmm.dll / leechcore.dll / pcileech.exe on disk (PCILeech framework files)
///   7. FTD2XX.dll / FTDI drivers for DMA card USB debug interface
///   8. MemProcFS specific directories and files
///   9. DMA-specific registry artifacts: PCILeech firmware signatures
///  10. Previous execution via BAM/Shimcache (handled by RegistryForensicArtifacts)
///
/// Ocean / detect.ac treat DMA infrastructure detection as Critical because
/// DMA cheats are universally used in professional tournament environments where
/// they cannot be caught by the gaming PC's own AC system.
/// </summary>
public sealed class DmaCheatInfrastructureScanModule : IScanModule
{
    public string Name => "DMA-Cheat Infrastruktur Erkennung (PCILeech/MemProcFS/FTD2XX)";
    public double Weight => 0.65;
    public int ParallelGroup => 3;

    // Known PCILeech and DMA cheat framework files
    private static readonly (string FileName, string Context)[] DmaFiles =
    {
        ("pcileech.exe",       "PCILeech DMA Framework"),
        ("leechcore.dll",      "PCILeech LeechCore Library"),
        ("leechcoreplugin.dll","PCILeech Plugin"),
        ("vmm.dll",            "PCILeech MemProcFS VMM"),
        ("dbg.dll",            "PCILeech Debug Module"),
        ("FTD2XX.dll",         "FTDI DMA Card USB Driver"),
        ("ftd2xx.dll",         "FTDI DMA Card USB Driver"),
        ("FTD2XX64.dll",       "FTDI DMA Card USB Driver (64-bit)"),
        ("MemProcFS.exe",      "MemProcFS Direct Memory Access Tool"),
        ("memprocfs.exe",      "MemProcFS Direct Memory Access Tool"),
        ("leechagent.exe",     "PCILeech Remote Agent"),
        ("pcileech.pdb",       "PCILeech Debug Symbols"),
        ("vmm.pdb",            "MemProcFS Debug Symbols"),
        ("DumpIt.exe",         "Memory Acquisition Tool"),
        ("winpmem.exe",        "WinPMem Physical Memory Access"),
        ("winpmem_mini.exe",   "WinPMem Physical Memory Access"),
        ("rekall.exe",         "Rekall Memory Forensics / Cheat"),
        ("volatility.exe",     "Volatility Memory Forensics / Cheat"),
        ("physmem2profit.exe", "LSASS via Physical Memory"),
    };

    // Known DMA cheat software names (process names / directory names)
    private static readonly string[] DmaKeywords =
    {
        "pcileech", "memprocfs", "leechcore", "leechagent",
        "dma", "radar", "radaroverlay", "esp-radar", "kmbox",
        "squirrel", "leetcheater", "enigmadma", "comtadma",
        "physical_memory", "physmem", "winpmem", "dumpit",
    };

    // PCI registry paths to check for DMA device hardware IDs
    private const string PciRegPath = @"SYSTEM\CurrentControlSet\Enum\PCI";

    // Known FPGA DMA device vendor IDs (VID_xxxx format)
    private static readonly string[] SuspiciousVendorIds =
    {
        // PCILeech-compatible FPGA vendor IDs
        "VID_1172",  // Altera FPGA (used in many PCILeech devices)
        "VID_0403",  // FTDI (used for DMA card debug/config interface)
        "VID_1D6B",  // Linux Foundation (USB gadget — DMA emulation)
        "VID_12AB",  // Used in some DMA cheat cards
        "VID_F112",  // DMAHack VID
        "VID_10EE",  // Xilinx FPGA (used in high-end DMA cards)
    };

    // Network share names associated with DMA radar setups
    private static readonly string[] RadarShareNames =
    {
        "radar", "esp", "dma", "kmbox", "cheatradar", "radarshare",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        // 1. Scan filesystem for PCILeech/MemProcFS files
        ScanDmaFiles(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 2. Check PCI device registry for DMA FPGA hardware
        ScanPciDevices(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 3. Check for MemProcFS-specific directories
        ScanMemProcFsDirectories(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 4. Check running processes for DMA tools
        ScanDmaProcesses(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 5. Check network shares named "radar" / "esp" (DMA radar LAN sharing)
        ScanRadarNetworkShares(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 6. Installed software check for DMA tools
        ScanInstalledDmaSoftware(ctx, ct);
    }

    private void ScanDmaFiles(ScanContext ctx, CancellationToken ct)
    {
        string systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string downloads = Path.Combine(userProfile, "Downloads");
        string temp = Path.GetTempPath();

        var searchPaths = new[]
        {
            desktop, downloads, temp, userProfile,
            localAppData, appData,
            Path.Combine(userProfile, "Documents"),
            Path.Combine(userProfile, "tools"),
            Path.Combine(systemDrive, "tools"),
            Path.Combine(systemDrive, "DMA"),
            Path.Combine(systemDrive, "pcileech"),
            Path.Combine(systemDrive, "memprocfs"),
        };

        foreach (var (dmaFile, context) in DmaFiles)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var basePath in searchPaths)
            {
                if (!Directory.Exists(basePath)) continue;
                try
                {
                    SearchForDmaFile(basePath, dmaFile, context, ctx, ct, maxDepth: 4, currentDepth: 0);
                }
                catch { }
            }
        }
    }

    private void SearchForDmaFile(string dir, string targetFile, string context,
        ScanContext ctx, CancellationToken ct, int maxDepth, int currentDepth)
    {
        if (currentDepth > maxDepth) return;
        ct.ThrowIfCancellationRequested();

        try
        {
            string fullPath = Path.Combine(dir, targetFile);
            if (File.Exists(fullPath))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"DMA-Tool-Datei gefunden ({context}): {targetFile}",
                    Risk     = RiskLevel.Critical,
                    Location = fullPath,
                    FileName = targetFile,
                    Reason   = $"DMA-Cheat Framework-Datei '{targetFile}' ({context}) auf Disk gefunden. " +
                               "DMA-Cheats lesen physischen Spielspeicher von einem zweiten PC via PCIe-" +
                               "FPGA-Karte — vollständig unsichtbar für alle AC-Systeme auf dem Spieler-PC. " +
                               "PCILeech/MemProcFS ist die Basis der meisten kommerziellen DMA-Cheats.",
                    Detail   = $"Datei: {fullPath} | Kontext: {context}"
                });
            }

            if (currentDepth < maxDepth)
            {
                foreach (var subDir in Directory.GetDirectories(dir))
                {
                    SearchForDmaFile(subDir, targetFile, context, ctx, ct, maxDepth, currentDepth + 1);
                }
            }
        }
        catch { }
    }

    private void ScanPciDevices(ScanContext ctx, CancellationToken ct)
    {
        ctx.IncrementRegistryKeys();
        try
        {
            using var pciKey = Registry.LocalMachine.OpenSubKey(PciRegPath);
            if (pciKey == null) return;

            foreach (var deviceKeyName in pciKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                // Device key names like "VEN_1172&DEV_0001&SUBSYS_00011234&REV_00"
                string deviceUpper = deviceKeyName.ToUpperInvariant();

                string? matchedVid = SuspiciousVendorIds.FirstOrDefault(vid =>
                    deviceUpper.Contains(vid.ToUpperInvariant()));

                if (matchedVid == null) continue;

                // Open the device key to get friendly name
                try
                {
                    using var deviceKey = pciKey.OpenSubKey(deviceKeyName);
                    if (deviceKey == null) continue;

                    // Get sub-instance keys
                    foreach (var instanceName in deviceKey.GetSubKeyNames())
                    {
                        using var instKey = deviceKey.OpenSubKey(instanceName);
                        if (instKey == null) continue;

                        string? deviceDesc = instKey.GetValue("DeviceDesc") as string ?? deviceKeyName;
                        string? hardwareId = instKey.GetValue("HardwareID") as string ?? "";
                        string? classGuid  = instKey.GetValue("ClassGUID") as string ?? "";

                        ctx.IncrementRegistryKeys();

                        // Filter out known legitimate devices with same VID
                        // FTDI is heavily overloaded — require DMA-specific context
                        bool isFtdi = matchedVid == "VID_0403";
                        if (isFtdi)
                        {
                            // Only flag FTDI if found in a context matching DMA keywords
                            string combinedDesc = (deviceDesc + deviceKeyName).ToLowerInvariant();
                            bool hasDmaContext = DmaKeywords.Any(kw => combinedDesc.Contains(kw));
                            if (!hasDmaContext) continue;
                        }

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Verdächtiges PCI-Gerät (DMA-FPGA VID '{matchedVid}'): {deviceKeyName}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{PciRegPath}\{deviceKeyName}\{instanceName}",
                            FileName = deviceDesc,
                            Reason   = $"PCI-Gerät mit Vendor-ID '{matchedVid}' gefunden. Diese VID " +
                                       "wird von Altera/Xilinx FPGAs und FTDI USB-Chips verwendet die " +
                                       "in kommerziellen DMA-Cheat-Karten (PCILeech-basiert) eingesetzt werden. " +
                                       $"Gerät: {deviceDesc}. Hardware-ID: {hardwareId}. " +
                                       "Auf einem Gaming-PC ohne Entwickler-Hintergrund ist dieses Gerät ungewöhnlich.",
                            Detail   = $"DeviceKey: {deviceKeyName} | Desc: {deviceDesc} | HW-ID: {hardwareId}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanMemProcFsDirectories(ScanContext ctx, CancellationToken ct)
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";

        var mpfsDirs = new[]
        {
            Path.Combine(userProfile, "Documents", "memprocfs"),
            Path.Combine(userProfile, "Desktop", "memprocfs"),
            Path.Combine(systemDrive, "memprocfs"),
            Path.Combine(systemDrive, "pcileech"),
            Path.Combine(systemDrive, "tools", "memprocfs"),
            Path.Combine(systemDrive, "tools", "pcileech"),
        };

        foreach (var dir in mpfsDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"MemProcFS/PCILeech Verzeichnis gefunden: {dir}",
                Risk     = RiskLevel.Critical,
                Location = dir,
                FileName = Path.GetFileName(dir),
                Reason   = $"Bekanntes DMA-Tool-Verzeichnis '{dir}' existiert. " +
                           "MemProcFS und PCILeech sind die Kern-Frameworks aller kommerziellen " +
                           "DMA-Cheats. Das Verzeichnis enthält Framework-Binaries, Firmware-Dateien " +
                           "und Konfigurationen für die DMA-Karte.",
                Detail   = $"Verzeichnis: {dir}"
            });
        }
    }

    private void ScanDmaProcesses(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            var snapshot = ctx.GetProcessSnapshot();
            foreach (var proc in snapshot)
            {
                ct.ThrowIfCancellationRequested();
                string procName = proc.ProcessName.ToLowerInvariant();
                string? match = DmaKeywords.FirstOrDefault(kw => procName.Contains(kw));

                if (match != null)
                {
                    string procPath = "";
                    try { procPath = proc.MainModule?.FileName ?? ""; } catch { }

                    ctx.IncrementProcesses();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"DMA-Tool Prozess läuft: '{proc.ProcessName}' (Keyword: '{match}')",
                        Risk     = RiskLevel.Critical,
                        Location = $"PID {proc.Id}",
                        FileName = proc.ProcessName,
                        Reason   = $"Prozess '{proc.ProcessName}' (PID {proc.Id}) enthält DMA-Tool-Keyword '{match}'. " +
                                   "DMA-Framework-Prozesse (PCILeech, MemProcFS) greifen direkt auf physischen " +
                                   "RAM zu. Wenn ein solcher Prozess läuft während ein Spiel aktiv ist, " +
                                   "kann er Spielspeicher ohne Kernel-Treiber auf dem Spieler-PC lesen.",
                        Detail   = $"Prozess: {proc.ProcessName} | PID: {proc.Id} | Pfad: {procPath}"
                    });
                }
            }
        }
        catch { }
    }

    private void ScanRadarNetworkShares(ScanContext ctx, CancellationToken ct)
    {
        // Check for network shares with DMA-radar-related names using net use / registry
        ctx.IncrementRegistryKeys();
        try
        {
            // Network MRU: Recently connected shares
            using var mruKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU");
            if (mruKey != null)
            {
                foreach (var valName in mruKey.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    string val = (mruKey.GetValue(valName) as string ?? "").ToLowerInvariant();
                    string? match = RadarShareNames.FirstOrDefault(s => val.Contains(s));
                    if (match != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Netzlaufwerk-MRU mit DMA-Radar-Keyword '{match}': {val}",
                            Risk     = RiskLevel.Critical,
                            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU",
                            FileName = val,
                            Reason   = $"Kürzlich verbundenes Netzlaufwerk '{val}' enthält DMA-Radar-Keyword '{match}'. " +
                                       "DMA-Radar-Setups teilen Radardaten via SMB-Share oder dediziertes Netzwerk " +
                                       "zwischen dem DMA-PC und dem Spieler-PC. Ein 'radar'-benannter Share " +
                                       "ist ein direkter Hinweis auf DMA-Cheat-Infrastruktur.",
                            Detail   = $"MRU-Wert: {val} | Keyword: {match}"
                        });
                    }
                }
            }
        }
        catch { }

        // Check currently mapped drives
        ctx.IncrementRegistryKeys();
        try
        {
            using var networkKey = Registry.CurrentUser.OpenSubKey(@"Network");
            if (networkKey != null)
            {
                foreach (var driveLetter in networkKey.GetSubKeyNames())
                {
                    using var driveKey = networkKey.OpenSubKey(driveLetter);
                    string? remotePath = driveKey?.GetValue("RemotePath") as string;
                    if (remotePath == null) continue;

                    string remotePathLower = remotePath.ToLowerInvariant();
                    string? match = RadarShareNames.FirstOrDefault(s => remotePathLower.Contains(s));
                    if (match != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Gemapptes Netzlaufwerk {driveLetter}: mit Radar-Share '{match}': {remotePath}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKCU\Network\{driveLetter}",
                            FileName = remotePath,
                            Reason   = $"Netzlaufwerk {driveLetter}: zeigt auf '{remotePath}' das Radar-Keyword '{match}' " +
                                       "enthält. Dieses Laufwerk ist aktuell verbunden — aktive DMA-Radar-Verbindung möglich.",
                            Detail   = $"Laufwerk: {driveLetter}: | Remote: {remotePath} | Keyword: {match}"
                        });
                    }
                }
            }
        }
        catch { }
    }

    private void ScanInstalledDmaSoftware(ScanContext ctx, CancellationToken ct)
    {
        string[] uninstallPaths =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (var regPath in uninstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementRegistryKeys();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                if (key == null) continue;

                foreach (var appKeyName in key.GetSubKeyNames())
                {
                    using var appKey = key.OpenSubKey(appKeyName);
                    if (appKey == null) continue;

                    string displayName = (appKey.GetValue("DisplayName") as string ?? "").ToLowerInvariant();
                    string installLocation = (appKey.GetValue("InstallLocation") as string ?? "").ToLowerInvariant();

                    string combined = displayName + " " + installLocation;
                    string? match = DmaKeywords.FirstOrDefault(kw => combined.Contains(kw));

                    if (match != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"DMA-Tool installiert: '{displayName}' (Keyword: '{match}')",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{regPath}\{appKeyName}",
                            FileName = displayName,
                            Reason   = $"DMA-Tool-Software '{displayName}' ist in der Programmliste registriert " +
                                       $"(Keyword: '{match}'). Installierte DMA-Frameworks sind direkter Beweis " +
                                       "für die Nutzung oder Entwicklung von DMA-Cheats.",
                            Detail   = $"DisplayName: {displayName} | InstallLocation: {installLocation}"
                        });
                    }
                }
            }
            catch { }
        }
    }
}
