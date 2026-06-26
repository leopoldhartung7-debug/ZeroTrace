using Microsoft.Win32;
using System.Text;
using System.Text.RegularExpressions;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class RageMPAntibanForensicScanModule : IScanModule
{
    public string Name => "RageMP-AntiBan";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    private static readonly string[] KnownBanEvasionExecutables =
    {
        "RageMPCleaner.exe", "HWIDSpoofer.exe", "UnbanTool.exe",
        "FingerprintCleaner.exe", "MACSpoofer.exe", "BanBypass.exe",
        "ragemp_cleaner.exe", "hwid_spoofer.exe", "unban_tool.exe",
        "fingerprint_cleaner.exe", "mac_spoofer.exe", "ban_bypass.exe",
        "ragemp_unban.exe", "ragemp_unban_tool.exe",
        "serial_spoofer.exe", "SerialSpoofer.exe",
        "disk_spoofer.exe", "DiskSpoofer.exe",
        "BanEvade.exe", "ban_evade.exe",
        "RageMPBypass.exe", "ragemp_bypass.exe",
        "FPCleaner.exe", "fp_cleaner.exe",
        "HardwareSpoofer.exe", "hardware_spoofer.exe",
        "UUIDSpoofer.exe", "uuid_spoofer.exe",
        "VolumeSpoofer.exe", "volume_spoofer.exe",
        "MACChanger.exe", "mac_changer.exe",
        "NICSpoofer.exe", "nic_spoofer.exe",
        "CPUSpoofer.exe", "cpu_spoofer.exe",
        "GPUSpoofer.exe", "gpu_spoofer.exe",
        "BIOSSpoofer.exe", "bios_spoofer.exe",
        "DriveSpoofer.exe", "drive_spoofer.exe",
    };

    private static readonly string[] BanEvasionFileWildcardPrefixes =
    {
        "hwid_spoofer", "ragemp_cleaner", "ban_evade", "mac_spoof",
        "fp_clean", "ragemp_unban", "serial_spoof", "disk_spoof",
        "hwid-spoofer", "ragemp-cleaner", "ban-evade", "mac-spoof",
        "fp-clean", "ragemp-unban", "serial-spoof", "disk-spoof",
        "banbypass", "ban_bypass", "hwidspoof", "ragecleaner",
        "serialchanger", "uuidspoof", "fpwipe", "hardwarespoof",
    };

    private static readonly string[] BanEvasionLogKeywords =
    {
        "ban evade", "hwid spoof", "serial changed", "ragemp unban",
        "mac spoof", "fingerprint wipe", "ban bypass", "hwid changed",
        "serial spoof", "ragemp ban bypass", "unban ragemp", "hwid cleaned",
        "disk serial changed", "mac address spoofed", "fingerprint cleaned",
        "hardware id changed", "volume serial changed", "bios serial spoofed",
        "gpu serial spoof", "cpu serial spoof", "ragemp cleaner",
        "ban evasion", "hwid regenerate", "new hwid applied",
    };

    private static readonly string[] DiscordBanEvasionKeywords =
    {
        "hwid spoof ragemp", "ragemp ban bypass", "unban ragemp",
        "serial spoof", "ragemp unban", "mac spoof ragemp",
        "ragemp hwid", "fingerprint wipe ragemp", "ban evade ragemp",
        "ragemp cleaner", "ragemp spoofer", "rage mp unban",
        "rage mp spoofer", "ragemp ban evade", "hwid bypass ragemp",
        "ragemp hardware spoof", "ragemp serial change",
        "disk spoofer ragemp", "ragemp fp cleaner",
    };

    private static readonly string[] SuspiciousRegistryValueNames =
    {
        "HardwareSerial", "DiskSerial", "BIOSSerial", "MachineGuid",
        "SpoofedSerial", "OriginalSerial", "SpoofActive", "SpoofVersion",
        "HWIDBackup", "OriginalHWID", "SpoofedHWID", "LastSpoof",
        "SpoofTimestamp", "BanBypassVersion", "CleanerVersion",
    };

    private static readonly string[] SpooferRegistryPaths =
    {
        @"SYSTEM\CurrentControlSet\Control\HardwareSerial",
        @"SOFTWARE\HWID Spoofer",
        @"SOFTWARE\HWIDSpoofer",
        @"SOFTWARE\RageMP Cleaner",
        @"SOFTWARE\RageMPCleaner",
        @"SOFTWARE\Ban Evade",
        @"SOFTWARE\BanEvade",
        @"SOFTWARE\BanBypass",
        @"SOFTWARE\Ban Bypass",
        @"SOFTWARE\SerialSpoofer",
        @"SOFTWARE\Serial Spoofer",
        @"SOFTWARE\MACSpoofer",
        @"SOFTWARE\MAC Spoofer",
        @"SOFTWARE\FingerprintCleaner",
        @"SOFTWARE\Fingerprint Cleaner",
        @"SOFTWARE\UnbanTool",
        @"SOFTWARE\Unban Tool",
        @"SOFTWARE\DiskSpoofer",
        @"SOFTWARE\Disk Spoofer",
        @"SOFTWARE\HardwareSpoofer",
        @"SOFTWARE\Hardware Spoofer",
        @"SOFTWARE\RageMP\Spoofer",
        @"SOFTWARE\RageMP\BanBypass",
        @"SOFTWARE\RageMP\Cleaner",
        @"SOFTWARE\RageMP\Unban",
        @"SOFTWARE\UUIDSpoofer",
        @"SOFTWARE\UUID Spoofer",
        @"SOFTWARE\VolumeSpoofer",
        @"SOFTWARE\Volume Spoofer",
    };

    private static readonly string[] TempFileUuidPatterns =
    {
        "spoof_", "hwid_", "serial_", "backup_hwid", "original_hwid",
        "spoofer_", "ban_evade_", "ragemp_clean", "fp_wipe_",
        "mac_backup_", "disk_serial_", "volume_serial_",
        "uuid_backup", "bios_backup", "hwid_backup",
    };

    private static readonly Regex UuidLikePattern = new(
        @"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex SerialLikePattern = new(
        @"[0-9A-Fa-f]{16,32}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly string[] SuspiciousPsScriptKeywords =
    {
        "Set-ItemProperty.*SerialNumber", "reg add.*HardwareSerial",
        "wmic diskdrive set serial", "bcdedit.*spoofed",
        "Set-WmiInstance.*SerialNumber", "hwid.*spoof",
        "serial.*replace", "volume serial", "VolumeSerialNumber",
        "mac.*changer", "netsh interface set", "MACAddress.*set",
        "reg add.*MachineGuid", "New-Guid.*MachineGuid",
        "ragemp.*clean", "ban.*bypass.*reg", "hwid.*clean",
        "diskpart.*uniqueid", "UNIQUEID DISK ID=",
        "fsutil volume.*set", "serial.*wipe",
    };

    private static readonly string[] SuspiciousBatchScriptKeywords =
    {
        "reg add.*HardwareSerial", "wmic diskdrive", "diskpart",
        "netsh interface set interface", "UNIQUEID DISK ID=",
        "bcdedit /set", "reg delete.*MachineGuid",
        "reg add.*MachineGuid", "mac changer", "spoofer",
        "hwid clean", "ragemp unban", "serial replace",
        "volume serial", "mac spoof", "ban bypass",
        "fingerprint wipe", "reg add.*CurrentControlSet",
    };

    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting RageMP anti-ban/ban-evasion artifact scan...");

        await Task.WhenAll(
            CheckBanEvasionFilesOnDisk(ctx, ct),
            CheckRegistryArtifacts(ctx, ct),
            CheckLogFilesForBanEvasionKeywords(ctx, ct),
            CheckKnownBanEvasionTools(ctx, ct),
            CheckTempFolderSpooferArtifacts(ctx, ct),
            CheckPrefetchForSpooferExes(ctx, ct),
            CheckUserAssistForBanEvasionTools(ctx, ct),
            CheckDiscordCacheForBanEvasionKeywords(ctx, ct),
            CheckSuspiciousPowerShellScripts(ctx, ct),
            CheckSuspiciousBatchScripts(ctx, ct),
            CheckHardwareSerialRegistryAnomalies(ctx, ct)
        );

        ctx.Report(1.0, Name, "RageMP anti-ban forensic scan complete.");
    }

    private Task CheckBanEvasionFilesOnDisk(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var searchDirs = new List<string>
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RageMP"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RageMP"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RAGE Multiplayer"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "RAGE Multiplayer"),
        };

        string? programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string? programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if (!string.IsNullOrEmpty(programFiles)) searchDirs.Add(programFiles);
        if (!string.IsNullOrEmpty(programFilesX86)) searchDirs.Add(programFilesX86);

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                bool isKnownTool = KnownBanEvasionExecutables.Any(e =>
                    fileName.Equals(e, StringComparison.OrdinalIgnoreCase));

                bool isWildcard = BanEvasionFileWildcardPrefixes.Any(p =>
                    fileName.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                if (!isKnownTool && !isWildcard) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RageMP ban-evasion tool file: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Known RageMP ban-evasion tool file '{fileName}' found at '{file}'. " +
                             "This is a forensic artifact from an HWID spoofer, MAC spoofer, " +
                             "fingerprint cleaner, or serial manipulator targeting RageMP bans.",
                    Detail = $"Match type: {(isKnownTool ? "exact filename" : "wildcard prefix")} | Dir: {dir}"
                });
            }

            IEnumerable<string> subDirs;
            try
            {
                subDirs = Directory.EnumerateDirectories(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var subDir in subDirs)
            {
                if (ct.IsCancellationRequested) return;
                var dirName = Path.GetFileName(subDir);

                bool isDirSuspicious = BanEvasionFileWildcardPrefixes.Any(p =>
                    dirName.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                if (!isDirSuspicious)
                {
                    isDirSuspicious = KnownBanEvasionExecutables.Any(e =>
                        dirName.Equals(Path.GetFileNameWithoutExtension(e), StringComparison.OrdinalIgnoreCase));
                }

                if (isDirSuspicious)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP ban-evasion tool directory: {dirName}",
                        Risk = RiskLevel.High,
                        Location = subDir,
                        FileName = dirName,
                        Reason = $"Directory '{dirName}' at '{subDir}' matches RageMP ban-evasion tool naming patterns. " +
                                 "These directories are typically created by HWID spoofers or serial changers.",
                        Detail = $"Parent: {dir}"
                    });
                }

                IEnumerable<string> subFiles;
                try
                {
                    subFiles = Directory.EnumerateFiles(subDir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var subFile in subFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var subFileName = Path.GetFileName(subFile);

                    bool isSubKnown = KnownBanEvasionExecutables.Any(e =>
                        subFileName.Equals(e, StringComparison.OrdinalIgnoreCase));
                    bool isSubWildcard = BanEvasionFileWildcardPrefixes.Any(p =>
                        subFileName.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                    if (!isSubKnown && !isSubWildcard) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP ban-evasion file in subdir: {subFileName}",
                        Risk = RiskLevel.High,
                        Location = subFile,
                        FileName = subFileName,
                        Reason = $"RageMP ban-evasion tool file '{subFileName}' found in '{subDir}'. " +
                                 "This file is a forensic artifact from an HWID/serial spoofer or fingerprint cleaner.",
                        Detail = $"Subdir: {subDir} | Parent: {dir}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var hkuPaths = SpooferRegistryPaths;
        var hklmPaths = SpooferRegistryPaths;

        foreach (var regPath in hkuPaths)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"HWID spoofer registry key (HKCU): {Path.GetFileName(regPath)}",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{regPath}",
                    Reason = $"Registry key 'HKCU\\{regPath}' is associated with a known RageMP ban-evasion tool. " +
                             "This key is a remnant from an HWID spoofer or fingerprint cleaner installation.",
                    Detail = $"Full path: HKCU\\{regPath} | Value count: {key.ValueCount}"
                });
            }
            catch { }
        }

        foreach (var regPath in hklmPaths)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"HWID spoofer registry key (HKLM): {Path.GetFileName(regPath)}",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{regPath}",
                    Reason = $"Registry key 'HKLM\\{regPath}' is associated with a known RageMP ban-evasion tool. " +
                             "System-level spoofer keys indicate kernel-mode or installer-level HWID manipulation.",
                    Detail = $"Full path: HKLM\\{regPath} | Value count: {key.ValueCount}"
                });
            }
            catch { }
        }

        var hkuSoftwarePaths = new[]
        {
            @"SOFTWARE\HWID",
            @"SOFTWARE\Spoofer",
            @"SOFTWARE\BanEvade",
            @"SOFTWARE\RageUnban",
            @"SOFTWARE\RageMP",
        };

        foreach (var softPath in hkuSoftwarePaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.CurrentUser.OpenSubKey(softPath, writable: false);
                if (key is null) continue;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    bool isSuspicious = BanEvasionFileWildcardPrefixes.Any(p =>
                        subKeyName.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (!isSuspicious) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious HWID-related registry subkey: {subKeyName}",
                        Risk = RiskLevel.Medium,
                        Location = $@"HKCU\{softPath}\{subKeyName}",
                        Reason = $"Registry subkey 'HKCU\\{softPath}\\{subKeyName}' contains patterns associated " +
                                 "with HWID/serial spoofer tools targeting RageMP bans.",
                        Detail = $"Subkey: {subKeyName} | Parent: HKCU\\{softPath}"
                    });
                }
            }
            catch { }
        }

        var muiCachePath = @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
        try
        {
            ctx.IncrementRegistryKeys();
            using var muiKey = Registry.CurrentUser.OpenSubKey(muiCachePath, writable: false);
            if (muiKey is not null)
            {
                foreach (var valueName in muiKey.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    bool isBanEvasion = KnownBanEvasionExecutables.Any(e =>
                        valueName.Contains(e, StringComparison.OrdinalIgnoreCase));

                    if (!isBanEvasion)
                    {
                        isBanEvasion = BanEvasionFileWildcardPrefixes.Any(p =>
                            valueName.Contains(p, StringComparison.OrdinalIgnoreCase));
                    }

                    if (!isBanEvasion) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"MuiCache: Ban-evasion tool execution trace: {Path.GetFileName(valueName)}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{muiCachePath}",
                        FileName = Path.GetFileName(valueName),
                        Reason = $"MuiCache entry '{valueName}' indicates execution of a RageMP ban-evasion tool. " +
                                 "MuiCache entries persist after the executable is deleted.",
                        Detail = $"MuiCache value: {valueName}"
                    });
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckLogFilesForBanEvasionKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localappdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var temp = Path.GetTempPath();

        var logSearchDirs = new[]
        {
            Path.Combine(appdata, "RageMP"),
            Path.Combine(localappdata, "RageMP"),
            Path.Combine(appdata, "RAGE Multiplayer"),
            Path.Combine(localappdata, "RAGE Multiplayer"),
            Path.Combine(appdata, "Rockstar Games"),
            Path.Combine(localappdata, "Rockstar Games"),
            temp,
            Path.Combine(localappdata, "Temp"),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };

        foreach (var logDir in logSearchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(logDir)) continue;

            IEnumerable<string> logFiles;
            try
            {
                logFiles = Directory.EnumerateFiles(logDir, "*", SearchOption.AllDirectories)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f);
                        return ext.Equals(".log", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".txt", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".json", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase);
                    });
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var logFile in logFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fi = new FileInfo(logFile);
                if (fi.Length > 20 * 1024 * 1024) continue;

                string content;
                try
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException)
                {
                    continue;
                }

                foreach (var keyword in BanEvasionLogKeywords)
                {
                    if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Ban-evasion keyword in log: {Path.GetFileName(logFile)}",
                        Risk = RiskLevel.High,
                        Location = logFile,
                        FileName = Path.GetFileName(logFile),
                        Reason = $"Log file '{logFile}' contains ban-evasion keyword '{keyword}'. " +
                                 "This indicates activity related to HWID spoofing, MAC spoofing, " +
                                 "or fingerprint cleaning targeting RageMP bans.",
                        Detail = $"Keyword: {keyword} | Log: {logFile}"
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckKnownBanEvasionTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var amcachePath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Amcache.hve";
        var amcacheHivePath = @"C:\Windows\AppCompat\Programs\Amcache.hve";

        if (File.Exists(amcacheHivePath))
        {
            ctx.IncrementFiles();
        }

        var installedSoftwareKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (var uninstallPath in installedSoftwareKeys)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var uninstallKey = Registry.LocalMachine.OpenSubKey(uninstallPath, writable: false);
                if (uninstallKey is null) continue;

                foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    try
                    {
                        using var appKey = uninstallKey.OpenSubKey(subKeyName, writable: false);
                        if (appKey is null) continue;

                        var displayName = appKey.GetValue("DisplayName") as string ?? string.Empty;
                        var installLocation = appKey.GetValue("InstallLocation") as string ?? string.Empty;

                        bool isBanEvasion = KnownBanEvasionExecutables.Any(e =>
                            displayName.Contains(Path.GetFileNameWithoutExtension(e), StringComparison.OrdinalIgnoreCase));

                        if (!isBanEvasion)
                        {
                            isBanEvasion = BanEvasionFileWildcardPrefixes.Any(p =>
                                displayName.Contains(p, StringComparison.OrdinalIgnoreCase)
                                || installLocation.Contains(p, StringComparison.OrdinalIgnoreCase));
                        }

                        if (!isBanEvasion) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Installed ban-evasion software: {displayName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                            Reason = $"Installed software '{displayName}' matches known RageMP ban-evasion tool patterns. " +
                                     "This entry indicates the software was formally installed on this machine.",
                            Detail = $"DisplayName: {displayName} | InstallLocation: {installLocation} | Key: {subKeyName}"
                        });
                    }
                    catch { }
                }
            }
            catch { }
        }

        var currentUserUninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        try
        {
            ctx.IncrementRegistryKeys();
            using var hkcuUninstall = Registry.CurrentUser.OpenSubKey(currentUserUninstall, writable: false);
            if (hkcuUninstall is not null)
            {
                foreach (var subKeyName in hkcuUninstall.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    try
                    {
                        using var appKey = hkcuUninstall.OpenSubKey(subKeyName, writable: false);
                        if (appKey is null) continue;

                        var displayName = appKey.GetValue("DisplayName") as string ?? string.Empty;

                        bool isBanEvasion = BanEvasionFileWildcardPrefixes.Any(p =>
                            displayName.Contains(p, StringComparison.OrdinalIgnoreCase));

                        if (!isBanEvasion) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"User-installed ban-evasion software: {displayName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{currentUserUninstall}\{subKeyName}",
                            Reason = $"User-installed software '{displayName}' matches RageMP ban-evasion tool patterns. " +
                                     "This indicates an HWID spoofer or related tool was user-installed.",
                            Detail = $"DisplayName: {displayName} | HKCU Uninstall key: {subKeyName}"
                        });
                    }
                    catch { }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckTempFolderSpooferArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var tempDirs = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
        };

        foreach (var tempDir in tempDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(tempDir)) continue;

            IEnumerable<string> tempFiles;
            try
            {
                tempFiles = Directory.EnumerateFiles(tempDir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var tempFile in tempFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(tempFile);
                var fileNameLower = fileName.ToLowerInvariant();

                bool isPrefixMatch = TempFileUuidPatterns.Any(p =>
                    fileNameLower.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                bool isSpooferFile = BanEvasionFileWildcardPrefixes.Any(p =>
                    fileNameLower.Contains(p, StringComparison.OrdinalIgnoreCase));

                if (isPrefixMatch || isSpooferFile)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Spoofer temp artifact: {fileName}",
                        Risk = RiskLevel.Medium,
                        Location = tempFile,
                        FileName = fileName,
                        Reason = $"Temporary file '{fileName}' in '{tempDir}' matches patterns created by " +
                                 "HWID spoofer operations (serial backup, UUID storage, or spoofer config files). " +
                                 "Spoofer tools create these artifacts during HWID manipulation.",
                        Detail = $"Match: {(isPrefixMatch ? "temp prefix" : "spoofer wildcard")} | Temp dir: {tempDir}"
                    });
                    continue;
                }

                var ext = Path.GetExtension(tempFile).ToLowerInvariant();
                if (ext != ".dat" && ext != ".tmp" && ext != ".bak" && ext != ".cfg") continue;

                var fi = new FileInfo(tempFile);
                if (fi.Length < 10 || fi.Length > 4 * 1024 * 1024) continue;

                string content;
                try
                {
                    using var fs = new FileStream(tempFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException)
                {
                    continue;
                }

                bool hasUuid = UuidLikePattern.IsMatch(content);
                bool hasSerial = SerialLikePattern.IsMatch(content);
                bool hasSpooferKeyword = BanEvasionLogKeywords.Any(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (!hasSpooferKeyword) continue;

                if (hasUuid || hasSerial)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Spoofer temp data file with UUID/serial: {fileName}",
                        Risk = RiskLevel.Medium,
                        Location = tempFile,
                        FileName = fileName,
                        Reason = $"Temporary file '{fileName}' in '{tempDir}' contains ban-evasion keywords " +
                                 "and UUID/serial-like patterns. HWID spoofers store original and spoofed " +
                                 "hardware identifiers in temp files during operation.",
                        Detail = $"Has UUID pattern: {hasUuid} | Has serial pattern: {hasSerial} | Temp: {tempDir}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckPrefetchForSpooferExes(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir)) return;

        IEnumerable<string> pfFiles;
        try
        {
            pfFiles = Directory.EnumerateFiles(prefetchDir, "*.pf");
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach (var pfFile in pfFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var pfName = Path.GetFileNameWithoutExtension(pfFile);
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            bool isKnownTool = KnownBanEvasionExecutables.Any(e =>
                exeName.Equals(Path.GetFileNameWithoutExtension(e), StringComparison.OrdinalIgnoreCase));

            bool isWildcard = BanEvasionFileWildcardPrefixes.Any(p =>
                exeName.StartsWith(p, StringComparison.OrdinalIgnoreCase));

            if (!isKnownTool && !isWildcard) continue;

            DateTime? lastWrite = null;
            try { lastWrite = File.GetLastWriteTimeUtc(pfFile); } catch { }

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Prefetch: RageMP ban-evasion tool executed: {exeName}.exe",
                Risk = RiskLevel.High,
                Location = pfFile,
                FileName = exeName + ".exe",
                Reason = $"Prefetch file indicates execution of RageMP ban-evasion tool '{exeName}.exe'. " +
                         "Prefetch entries persist even after the executable is deleted, " +
                         "making them reliable forensic indicators of prior tool usage.",
                Detail = $"Prefetch: {pfFile}" +
                         (lastWrite.HasValue ? $" | Last activity: {lastWrite.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                         $" | Match type: {(isKnownTool ? "exact" : "wildcard")}"
            });
        }
    }, ct);

    private Task CheckUserAssistForBanEvasionTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string userAssistBase =
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

        try
        {
            using var baseKey = Registry.CurrentUser.OpenSubKey(userAssistBase, writable: false);
            if (baseKey is null) return;

            foreach (var guidName in baseKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var countKey = baseKey.OpenSubKey($@"{guidName}\Count", writable: false);
                    if (countKey is null) continue;

                    foreach (var encodedName in countKey.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        var decoded = Rot13Decode(encodedName);
                        var decodedLower = decoded.ToLowerInvariant();

                        bool isBanEvasion = KnownBanEvasionExecutables.Any(e =>
                            decodedLower.Contains(e.ToLowerInvariant(), StringComparison.OrdinalIgnoreCase));

                        if (!isBanEvasion)
                        {
                            isBanEvasion = BanEvasionFileWildcardPrefixes.Any(p =>
                                decodedLower.Contains(p, StringComparison.OrdinalIgnoreCase));
                        }

                        if (!isBanEvasion) continue;

                        int runCount = 0;
                        DateTime? lastRun = null;
                        try
                        {
                            var data = countKey.GetValue(encodedName) as byte[];
                            if (data is { Length: >= 16 })
                            {
                                runCount = BitConverter.ToInt32(data, 4);
                                var fileTime = BitConverter.ToInt64(data, 8);
                                if (fileTime > 0)
                                    lastRun = DateTime.FromFileTimeUtc(fileTime);
                            }
                        }
                        catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"UserAssist: Ban-evasion tool executed: {Path.GetFileName(decoded)}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason = $"Windows UserAssist entry records execution of RageMP ban-evasion tool " +
                                     $"'{Path.GetFileName(decoded)}' ({runCount} time(s)" +
                                     (lastRun.HasValue ? $", last {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                     "). This entry persists after the file is deleted.",
                            Detail = $"Decoded path: {decoded} | Run count: {runCount} | " +
                                     $"Last run: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}"
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }, ct);

    private Task CheckDiscordCacheForBanEvasionKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var discordClients = new[] { "discord", "discordptb", "discordcanary" };

        foreach (var client in discordClients)
        {
            if (ct.IsCancellationRequested) return;
            var discordRoot = Path.Combine(appdata, client);
            if (!Directory.Exists(discordRoot)) continue;

            var cacheDirs = new[]
            {
                Path.Combine(discordRoot, "Cache", "Cache_Data"),
                Path.Combine(discordRoot, "Cache"),
                Path.Combine(discordRoot, "Local Storage", "leveldb"),
                Path.Combine(discordRoot, "Session Storage"),
                Path.Combine(discordRoot, "Code Cache", "js"),
            };

            foreach (var cacheDir in cacheDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(cacheDir)) continue;

                IEnumerable<string> cacheFiles;
                try
                {
                    cacheFiles = Directory.EnumerateFiles(cacheDir).Take(120);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var cacheFile in cacheFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fi = new FileInfo(cacheFile);
                    if (fi.Length > 10 * 1024 * 1024) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.Latin1);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException)
                    {
                        continue;
                    }

                    foreach (var keyword in DiscordBanEvasionKeywords)
                    {
                        if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Discord cache: RageMP ban-evasion keyword found",
                            Risk = RiskLevel.Medium,
                            Location = cacheFile,
                            FileName = Path.GetFileName(cacheFile),
                            Reason = $"Discord cache file in '{cacheDir}' contains ban-evasion keyword '{keyword}'. " +
                                     "This indicates activity in a Discord server distributing RageMP spoofers " +
                                     "or unban tools.",
                            Detail = $"Client: {client} | Keyword: {keyword} | Cache dir: {cacheDir}"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckSuspiciousPowerShellScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localappdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        var temp = Path.GetTempPath();

        var psScriptDirs = new[]
        {
            temp, appdata, localappdata, docs, desktop, downloads,
            Path.Combine(docs, "WindowsPowerShell"),
            Path.Combine(docs, "PowerShell"),
            Path.Combine(appdata, "Microsoft", "Windows", "PowerShell"),
        };

        foreach (var psDir in psScriptDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(psDir)) continue;

            IEnumerable<string> psFiles;
            try
            {
                psFiles = Directory.EnumerateFiles(psDir, "*.ps1", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.EnumerateFiles(psDir, "*.psm1", SearchOption.TopDirectoryOnly))
                    .Concat(Directory.EnumerateFiles(psDir, "*.psd1", SearchOption.TopDirectoryOnly));
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var psFile in psFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(psFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException)
                {
                    continue;
                }

                var matchedKeyword = SuspiciousPsScriptKeywords.FirstOrDefault(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (matchedKeyword is null) continue;

                bool hasBanEvasionContext = BanEvasionLogKeywords.Any(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                var risk = hasBanEvasionContext ? RiskLevel.High : RiskLevel.Medium;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspicious PowerShell script for serial manipulation: {Path.GetFileName(psFile)}",
                    Risk = risk,
                    Location = psFile,
                    FileName = Path.GetFileName(psFile),
                    Reason = $"PowerShell script '{psFile}' contains serial/HWID manipulation keyword '{matchedKeyword}'. " +
                             "Scripts performing registry serial manipulation, MAC address changes, or disk ID " +
                             "modification are commonly used by RageMP ban-evasion toolkits.",
                    Detail = $"Keyword: {matchedKeyword} | Ban-evasion context: {hasBanEvasionContext} | Dir: {psDir}"
                });
            }
        }

        var psHistoryPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");

        if (!File.Exists(psHistoryPath)) return;

        string histContent;
        try
        {
            using var fs = new FileStream(psHistoryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            histContent = await sr.ReadToEndAsync(ct);
        }
        catch (IOException)
        {
            return;
        }

        foreach (var keyword in SuspiciousPsScriptKeywords)
        {
            if (!histContent.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "PowerShell history: Serial/HWID manipulation command found",
                Risk = RiskLevel.High,
                Location = psHistoryPath,
                FileName = "ConsoleHost_history.txt",
                Reason = $"PowerShell command history contains serial manipulation keyword '{keyword}'. " +
                         "This indicates interactive HWID/serial manipulation commands were executed, " +
                         "consistent with RageMP ban-evasion activity.",
                Detail = $"Keyword: {keyword} | History file: {psHistoryPath}"
            });
            break;
        }
    }, ct);

    private Task CheckSuspiciousBatchScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localappdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var docs = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        var temp = Path.GetTempPath();

        var batchDirs = new[]
        {
            temp, appdata, localappdata, docs, desktop, downloads,
        };

        foreach (var batchDir in batchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(batchDir)) continue;

            IEnumerable<string> batchFiles;
            try
            {
                batchFiles = Directory.EnumerateFiles(batchDir, "*.bat", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.EnumerateFiles(batchDir, "*.cmd", SearchOption.TopDirectoryOnly));
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var batchFile in batchFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(batchFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException)
                {
                    continue;
                }

                var matchedKeyword = SuspiciousBatchScriptKeywords.FirstOrDefault(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (matchedKeyword is null) continue;

                bool hasBanEvasionContext = BanEvasionLogKeywords.Any(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                var risk = hasBanEvasionContext ? RiskLevel.High : RiskLevel.Medium;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspicious batch script for serial manipulation: {Path.GetFileName(batchFile)}",
                    Risk = risk,
                    Location = batchFile,
                    FileName = Path.GetFileName(batchFile),
                    Reason = $"Batch script '{batchFile}' contains serial/registry manipulation keyword '{matchedKeyword}'. " +
                             "Batch scripts performing diskpart UNIQUEID changes, registry serial writes, " +
                             "or MAC address manipulation are common RageMP ban-evasion script artifacts.",
                    Detail = $"Keyword: {matchedKeyword} | Ban-evasion context: {hasBanEvasionContext} | Dir: {batchDir}"
                });
            }
        }
    }, ct);

    private Task CheckHardwareSerialRegistryAnomalies(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var serialRelatedPaths = new[]
        {
            @"SYSTEM\CurrentControlSet\Control\HardwareSerial",
            @"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001",
            @"SYSTEM\CurrentControlSet\Services\Disk\Enum",
            @"SOFTWARE\Microsoft\Cryptography",
            @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}",
        };

        foreach (var regPath in serialRelatedPaths)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementRegistryKeys();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    bool isSuspiciousValueName = SuspiciousRegistryValueNames.Any(s =>
                        valueName.Equals(s, StringComparison.OrdinalIgnoreCase));

                    if (!isSuspiciousValueName) continue;

                    var value = key.GetValue(valueName);
                    var valueStr = value?.ToString() ?? string.Empty;

                    bool isFakeSerial = IsFakeSpoofedSerial(valueStr);

                    if (!isFakeSerial) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious registry serial value: {valueName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{regPath}",
                        Reason = $"Registry value 'HKLM\\{regPath}\\{valueName}' contains a serial value " +
                                 $"'{valueStr}' consistent with HWID spoofing (all-zero, placeholder, or repeated pattern). " +
                                 "HWID spoofers overwrite genuine hardware serials with fake values to evade bans.",
                        Detail = $"Value name: {valueName} | Value: {valueStr} | Path: HKLM\\{regPath}"
                    });
                }
            }
            catch { }
        }

        try
        {
            ctx.IncrementRegistryKeys();
            using var cryptoKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Cryptography", writable: false);

            if (cryptoKey is not null)
            {
                var machineGuid = cryptoKey.GetValue("MachineGuid") as string ?? string.Empty;
                if (!string.IsNullOrEmpty(machineGuid) && IsFakeSpoofedSerial(machineGuid.Replace("-", "")))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Suspicious MachineGuid: possible spoof detected",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\SOFTWARE\Microsoft\Cryptography",
                        Reason = $"MachineGuid value '{machineGuid}' has characteristics of a spoofed or " +
                                 "manipulated value (all-zero pattern, repeated bytes, or placeholder). " +
                                 "HWID spoofers frequently replace MachineGuid to evade hardware-based bans.",
                        Detail = $"MachineGuid: {machineGuid}"
                    });
                }
            }
        }
        catch { }

        var nicBaseKey = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
        try
        {
            ctx.IncrementRegistryKeys();
            using var nicClass = Registry.LocalMachine.OpenSubKey(nicBaseKey, writable: false);
            if (nicClass is null) return;

            foreach (var subKeyName in nicClass.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                try
                {
                    using var nicKey = nicClass.OpenSubKey(subKeyName, writable: false);
                    if (nicKey is null) continue;

                    var networkAddress = nicKey.GetValue("NetworkAddress") as string ?? string.Empty;
                    var driverDesc = nicKey.GetValue("DriverDesc") as string ?? string.Empty;

                    if (string.IsNullOrEmpty(networkAddress)) continue;

                    var macClean = networkAddress.Replace(":", "").Replace("-", "").Trim();
                    if (macClean.Length < 12) continue;

                    bool isFakeMac = IsFakeSpoofedSerial(macClean)
                        || macClean.All(c => c == macClean[0]);

                    if (!isFakeMac) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Suspicious custom MAC address in NIC registry: {driverDesc}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{nicBaseKey}\{subKeyName}",
                        Reason = $"Network adapter '{driverDesc}' has a registry-set MAC address '{networkAddress}' " +
                                 "that appears to be a placeholder or spoofed value. The 'NetworkAddress' key " +
                                 "is used by MAC spoofers to override hardware MAC addresses for ban evasion.",
                        Detail = $"NIC: {driverDesc} | NetworkAddress: {networkAddress} | Subkey: {subKeyName}"
                    });
                }
                catch { }
            }
        }
        catch { }
    }, ct);

    private static bool IsFakeSpoofedSerial(string serial)
    {
        if (string.IsNullOrWhiteSpace(serial)) return false;

        var s = serial.Trim().ToLowerInvariant();

        if (s.Length >= 8 && s.All(c => c == s[0])) return true;

        var fakePatterns = new[]
        {
            "0000000000000000", "1111111111111111", "ffffffffffffffff",
            "deadbeef", "baadbeef", "00000000", "12345678",
            "aabbccdd", "abcdef01", "cafebabe", "feedface",
            "to be filled", "to be determined", "not specified",
            "serial number", "default string", "system serial",
            "none", "n/a", "empty", "xxxxxxxxxxxx", "000000000000",
            "spoofer", "spoofed", "hwidspoof", "hwid_spoof",
        };

        return fakePatterns.Any(p => s == p || s.Contains(p, StringComparison.OrdinalIgnoreCase));
    }
}
