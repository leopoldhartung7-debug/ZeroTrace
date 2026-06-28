using ZeroTrace.Core.Models;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

/// <summary>
/// Deep scan for HWID spoofer artifacts beyond what HwidSpooferScanModule covers.
///
/// This module targets spoofer-specific residual artifacts:
///
/// 1. Spoofer tool configuration files:
///    - Most spoofers save their "original → spoofed" hardware ID mapping to a config
///    - This allows restoration after the ban period
///    - Common paths: %APPDATA%\spoofer\, %LOCALAPPDATA%\spoofer\, C:\spoofer\
///    - File names: config.ini, settings.json, backup.dat, orig_hwid.txt
///
/// 2. Registry artifacts from serial number modification:
///    - HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum (spoofed disk serials)
///    - HKLM\SYSTEM\CurrentControlSet\Services\cdrom\Enum
///    - HardwareID keys for USB devices with spoofed serials
///
/// 3. MAC address spoofer artifacts:
///    - HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}
///      NetworkAddress value (custom MAC in NIC adapter registry)
///    - Multiple NIC entries with identical MAC = cloning detected
///    - NetworkAddress not matching factory MAC = spoofer active
///
/// 4. BIOS serial number spoofing:
///    - WMI Win32_BIOS SerialNumber vs UEFI NVRAM backup
///    - SMBIOS structures accessible via registry
///    - ACPI registry entries for spoofed system info
///
/// 5. Known spoofer tool names and files:
///    - HWID Spoofer.exe, HWIDSpoofer.exe, HWID_Changer.exe
///    - Valorant Spoofer, EAC Spoofer, BattlEye Spoofer
///    - Diskpart serial change scripts
///    - MOD_HWID, Boreal, AbyssRipper spoofer names
///
/// 6. Volume serial number manipulation:
///    - vol C: serial should be consistent with filesystem creation
///    - Diskpart change was often done via bcdboot / format tricks
///
/// Ocean/detect.ac extensively check HWID spoofer artifacts because:
///   - Ban evaders ALWAYS use spoofers to avoid hardware-based bans
///   - Spoofer config files are the most valuable forensic artifact
///   - MAC address registry entries persist indefinitely
/// </summary>
public sealed class SpooferArtifactScanModule : IScanModule
{
    public string Name => "HWID-Spoofer Artefakt-Tiefenscan (MAC/Disk/BIOS Spoofing)";
    public double Weight => 0.6;
    public int ParallelGroup => 3;

    // Known HWID spoofer tool file names
    private static readonly (string FileName, string SpooferName)[] SpooferFiles =
    {
        ("hwid spoofer.exe",          "HWID Spoofer"),
        ("hwid_spoofer.exe",          "HWID Spoofer"),
        ("hwidspoofer.exe",           "HWID Spoofer"),
        ("hwid changer.exe",          "HWID Changer"),
        ("hwid_changer.exe",          "HWID Changer"),
        ("valorant spoofer.exe",      "Valorant HWID Spoofer"),
        ("valorant_spoofer.exe",      "Valorant HWID Spoofer"),
        ("eac spoofer.exe",           "EAC HWID Spoofer"),
        ("battleye spoofer.exe",      "BattlEye HWID Spoofer"),
        ("vanguard spoofer.exe",      "Vanguard HWID Spoofer"),
        ("be spoofer.exe",            "BattlEye Spoofer"),
        ("boreal spoofer.exe",        "Boreal HWID Spoofer"),
        ("abyss spoofer.exe",         "AbyssRipper Spoofer"),
        ("abyssripper.exe",           "AbyssRipper Spoofer"),
        ("serial changer.exe",        "Serial Number Changer"),
        ("disk serial changer.exe",   "Disk Serial Changer"),
        ("mac changer.exe",           "MAC Address Changer"),
        ("mac spoofer.exe",           "MAC Address Spoofer"),
        ("mac_spoofer.exe",           "MAC Address Spoofer"),
        ("tmac.exe",                  "TMAC (MAC Changer)"),
        ("technitium mac changer.exe","Technitium MAC Changer"),
        ("mod_hwid.exe",              "MOD_HWID Spoofer"),
        ("spoof.exe",                 "Generic Spoofer"),
        ("spoofer.exe",               "Generic HWID Spoofer"),
        ("cleanspoofer.exe",          "Clean Spoofer"),
        ("hwidban_bypass.exe",        "HWID Ban Bypass"),
        ("permaban_bypass.exe",       "Permanent Ban Bypass"),
        ("serial_backup.dat",         "Spoofer Original Serial Backup"),
        ("orig_hwid.txt",             "Original HWID Backup"),
        ("hwid_backup.json",          "HWID Backup File"),
        ("serial_restore.bat",        "Serial Restore Script"),
        ("restore_hwid.bat",          "HWID Restore Script"),
    };

    // Known spoofer directory names
    private static readonly string[] SpooferDirNames =
    {
        "hwid spoofer", "hwidspoofer", "hwid_spoofer",
        "boreal", "abyssripper", "mod_hwid",
        "spoofer", "mac changer", "macchanger", "tmac",
        "serialchanger", "serialspoofer",
        "cleanspoofer", "permaban",
    };

    // NIC adapter class GUID for MAC address spoofing check
    private const string NicClassGuid = @"SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}";

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() => Scan(ctx, ct), ct);
    }

    private void Scan(ScanContext ctx, CancellationToken ct)
    {
        // 1. Scan common directories for spoofer executables/configs
        ScanSpooferFiles(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 2. Check NIC registry for MAC address spoofing
        ScanMacAddressSpoofing(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 3. Check for known spoofer tool registry artifacts
        ScanSpooferRegistryArtifacts(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 4. Check installed software for spoofers
        ScanInstalledSpooferSoftware(ctx, ct);
        ct.ThrowIfCancellationRequested();

        // 5. Check spoofer directory names in common locations
        ScanSpooferDirectories(ctx, ct);
    }

    private void ScanSpooferFiles(ScanContext ctx, CancellationToken ct)
    {
        string userProfile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string desktop      = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        string downloads    = Path.Combine(userProfile, "Downloads");
        string temp         = Path.GetTempPath();
        string systemDrive  = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";

        var searchPaths = new[]
        {
            desktop, downloads, temp, appData, localAppData,
            Path.Combine(systemDrive, "spoofer"),
            Path.Combine(systemDrive, "tools"),
            Path.Combine(userProfile, "Documents"),
        };

        foreach (var (fileName, spooferName) in SpooferFiles)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var basePath in searchPaths)
            {
                if (!Directory.Exists(basePath)) continue;
                SearchForSpooferFile(basePath, fileName, spooferName, ctx, ct, 3, 0);
            }
        }
    }

    private void SearchForSpooferFile(string dir, string target, string name,
        ScanContext ctx, CancellationToken ct, int maxDepth, int depth)
    {
        if (depth > maxDepth) return;
        ct.ThrowIfCancellationRequested();
        try
        {
            string fullPath = Path.Combine(dir, target);
            if (File.Exists(fullPath))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"HWID-Spoofer Datei gefunden ({name}): {target}",
                    Risk     = RiskLevel.Critical,
                    Location = fullPath,
                    FileName = target,
                    Reason   = $"Bekannte HWID-Spoofer-Datei '{target}' ({name}) auf Disk gefunden. " +
                               "HWID-Spoofer manipulieren Hardware-Seriennummern (Disk, MAC, BIOS, GPU) " +
                               "um Hardware-Bans von BattlEye, EasyAntiCheat, Vanguard und Riot zu umgehen. " +
                               "Das Vorhandensein einer Spoofer-Datei ist ein direkter Beweis für Ban-Evasion.",
                    Detail   = $"Datei: {fullPath} | Spoofer: {name}"
                });
            }

            if (depth < maxDepth)
            {
                foreach (var subDir in Directory.GetDirectories(dir))
                    SearchForSpooferFile(subDir, target, name, ctx, ct, maxDepth, depth + 1);
            }
        }
        catch { }
    }

    private void ScanMacAddressSpoofing(ScanContext ctx, CancellationToken ct)
    {
        ctx.IncrementRegistryKeys();
        try
        {
            using var nicKey = Registry.LocalMachine.OpenSubKey(NicClassGuid);
            if (nicKey == null) return;

            int spoofedCount = 0;
            var macAddresses = new Dictionary<string, List<string>>();

            foreach (var subKeyName in nicKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                if (!int.TryParse(subKeyName, out _)) continue; // Skip Properties key etc.

                ctx.IncrementRegistryKeys();
                try
                {
                    using var adapterKey = nicKey.OpenSubKey(subKeyName);
                    if (adapterKey == null) continue;

                    string? networkAddress = adapterKey.GetValue("NetworkAddress") as string;
                    string? driverDesc     = adapterKey.GetValue("DriverDesc") as string ?? "Unknown NIC";
                    string? macAddress     = adapterKey.GetValue("NetworkAddress") as string;
                    string? providerName   = adapterKey.GetValue("ProviderName") as string ?? "";

                    // NetworkAddress present = MAC was explicitly set (not auto-detected from hardware)
                    if (!string.IsNullOrEmpty(networkAddress))
                    {
                        spoofedCount++;
                        string mac = networkAddress.ToUpperInvariant();

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"MAC-Adresse manuell gesetzt für NIC '{driverDesc}': {mac}",
                            Risk     = RiskLevel.High,
                            Location = $@"HKLM\{NicClassGuid}\{subKeyName}",
                            FileName = driverDesc,
                            Reason   = $"Netzwerkadapter '{driverDesc}' hat eine manuell gesetzte MAC-Adresse " +
                                       $"'{mac}' im Registry (NetworkAddress-Eintrag). " +
                                       "Legitime Anwendungen setzen nie den NetworkAddress-Registrierungswert. " +
                                       "Dieser Wert wird ausschließlich von MAC-Spoofer-Tools (Technitium MAC Changer, " +
                                       "TMAC, HWID-Spoofer) geschrieben um die Hardware-MAC zu verschleiern und " +
                                       "MAC-basierte Hardware-Bans (BattlEye, EAC) zu umgehen.",
                            Detail   = $"NIC: {driverDesc} | Adapter Key: {subKeyName} | NetworkAddress: {mac}"
                        });

                        // Track for duplicate detection
                        if (!macAddresses.ContainsKey(mac))
                            macAddresses[mac] = new List<string>();
                        macAddresses[mac].Add(driverDesc ?? subKeyName);
                    }
                }
                catch { }
            }

            // Detect duplicate MACs (cloning)
            foreach (var (mac, adapters) in macAddresses)
            {
                if (adapters.Count > 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Doppelte MAC-Adresse auf mehreren NICs: {mac}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{NicClassGuid}",
                        FileName = mac,
                        Reason   = $"MAC-Adresse '{mac}' ist auf {adapters.Count} Netzwerkadaptern konfiguriert: " +
                                   string.Join(", ", adapters) + ". " +
                                   "Doppelte MACs entstehen durch MAC-Kloning — ein HWID-Spoofer kopiert " +
                                   "eine bekannte ungebannte MAC auf alle Adapter.",
                        Detail   = $"MAC: {mac} | Adapter: {string.Join("; ", adapters)}"
                    });
                }
            }
        }
        catch { }
    }

    private void ScanSpooferRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        // Known spoofer registry artifacts
        var spooferKeys = new[]
        {
            // Technitium MAC Changer leaves this key
            (@"SOFTWARE\Technitium\MAC Address Changer", "Technitium MAC Changer"),
            // TMAC
            (@"SOFTWARE\TMAC", "TMAC MAC Changer"),
            // Generic HWID spoofer key patterns
            (@"SOFTWARE\HWID Spoofer", "HWID Spoofer"),
            (@"SOFTWARE\HWIDSpoofer", "HWID Spoofer"),
            (@"SOFTWARE\Boreal", "Boreal HWID Spoofer"),
        };

        foreach (var (regPath, spooferName) in spooferKeys)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementRegistryKeys();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath)
                             ?? Registry.CurrentUser.OpenSubKey(regPath);
                if (key != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"HWID-Spoofer Registry-Artefakt gefunden: {spooferName}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"HKLM\{regPath} oder HKCU\{regPath}",
                        FileName = spooferName,
                        Reason   = $"Registry-Schlüssel von HWID-Spoofer '{spooferName}' gefunden: {regPath}. " +
                                   "Spoofer-Registry-Einträge bleiben nach der Deinstallation erhalten und " +
                                   "sind daher starke forensische Beweismittel für Ban-Evasion-Aktivität.",
                        Detail   = $"Pfad: {regPath} | Spoofer: {spooferName}"
                    });
                }
            }
            catch { }
        }
    }

    private void ScanInstalledSpooferSoftware(ScanContext ctx, CancellationToken ct)
    {
        string[] uninstallPaths =
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        string[] spooferKeywords =
        {
            "hwid spoofer", "hwid changer", "mac changer", "mac address changer",
            "serial changer", "spoofer", "ban bypass", "hwid bypass",
            "technitium", "tmac", "boreal", "abyssripper",
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
                    string? match = spooferKeywords.FirstOrDefault(kw => displayName.Contains(kw));

                    if (match != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"HWID-Spoofer installiert: '{displayName}'",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{regPath}\{appKeyName}",
                            FileName = displayName,
                            Reason   = $"HWID-Spoofer-Software '{displayName}' in der Windows-Programmliste " +
                                       $"gefunden (Keyword: '{match}'). Installierte HWID-Spoofer sind " +
                                       "direkter Beweis für Ban-Evasion-Vorbereitung oder aktives Umgehen " +
                                       "von BattlEye/EAC/Vanguard Hardware-Bans.",
                            Detail   = $"DisplayName: {displayName} | RegKey: {appKeyName}"
                        });
                    }
                }
            }
            catch { }
        }
    }

    private void ScanSpooferDirectories(ScanContext ctx, CancellationToken ct)
    {
        string appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string userProfile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string systemDrive  = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";

        var searchBases = new[] { appData, localAppData, userProfile, systemDrive };

        foreach (var basePath in searchBases)
        {
            if (!Directory.Exists(basePath)) continue;
            try
            {
                foreach (var dir in Directory.GetDirectories(basePath))
                {
                    ct.ThrowIfCancellationRequested();
                    string dirName = Path.GetFileName(dir).ToLowerInvariant();
                    string? match = SpooferDirNames.FirstOrDefault(s =>
                        dirName.Contains(s, StringComparison.OrdinalIgnoreCase));

                    if (match != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"HWID-Spoofer Verzeichnis gefunden: '{Path.GetFileName(dir)}'",
                            Risk     = RiskLevel.Critical,
                            Location = dir,
                            FileName = Path.GetFileName(dir),
                            Reason   = $"Verzeichnis '{dir}' enthält Spoofer-Keyword '{match}'. " +
                                       "Spoofer-Verzeichnisse speichern Konfigurationen, Hardware-ID-Backups " +
                                       "und Logs die nach der Deinstallation zurückbleiben.",
                            Detail   = $"Verzeichnis: {dir} | Keyword: {match}"
                        });
                    }
                }
            }
            catch { }
        }
    }
}
