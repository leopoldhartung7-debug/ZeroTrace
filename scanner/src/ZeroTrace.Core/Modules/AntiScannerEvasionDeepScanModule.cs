using System.Runtime.Versioning;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class AntiScannerEvasionDeepScanModule : IScanModule
{
    public string Name => "Anti-Scanner Evasion Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] AntiForensicToolNames =
    [
        "eraser", "bleachbit", "privaze", "privazer", "fileshredder", "file_shredder",
        "wisecleaner", "wise_disk_cleaner", "wisediskcleaner",
        "moo0_anti_recovery", "moo0antirecover", "hardwipe", "hard_wipe",
        "freeraser", "free_raser", "cybershredder", "cyber_shredder",
        "superfdisk", "killdisk", "kill_disk", "disk_wiper", "diskwiper",
        "secure_erase", "secureerase", "secure_delete", "securedelete",
        "evidence_eliminator", "evidence_nuker", "evidencenuker",
        "window_washer", "windowwasher", "east_tec_eraser", "east_tec",
        "shreddit", "confidential_disk_wiper", "active_killdisk",
        "datashredder", "data_shredder", "wipe_drive", "wipedrive",
        "dban", "darik", "nwipe",
        "ccleaner", "cleanmgr", "diskclean", "disk_clean",
    ];

    private static readonly string[] ScannerKeywords =
    [
        "zerotrace", "zero_trace", "ocean_scanner", "ocean scanner",
        "detect.ac", "detectac", "detect_ac", "anticheat_scanner",
        "fivem_scanner", "cheat_scanner", "cheatscanner",
        "forensic_scanner", "forensicscanner", "scan_artifacts",
        "scanner_evasion", "evade_scan", "bypass_scan", "anti_scan",
        "antiscan", "antiscanner", "beat_scan",
        "delete_before_scan", "clean_before_scan",
        "scanner_bypass", "scan_bypass",
    ];

    private static readonly string[] CleanerScriptKeywords =
    [
        "del /f /s /q", "rd /s /q", "rmdir /s", "remove-item -recurse",
        "rm -rf", "shred -u", "wipe", "secure delete", "overwrite",
        "sdelete", "cipher /w", "fsutil usn deletejournal",
        "wevtutil cl", "clear-eventlog", "Remove-EventLog",
        "vssadmin delete shadows", "wmic shadowcopy delete",
        "bcdedit", "compact /u",
        "reg delete", "Remove-ItemProperty",
        "attrib -h -s", "icacls /reset",
        "taskkill /f /im", "sc stop", "net stop",
        "ipconfig /flushdns", "arp -d",
    ];

    private static readonly string[] AntiForensicRegistryPaths =
    [
        @"SOFTWARE\Eraser",
        @"SOFTWARE\Piriform\CCleaner",
        @"SOFTWARE\BleachBit",
        @"SOFTWARE\PrivaZer",
        @"SOFTWARE\WiseCleaner",
        @"SOFTWARE\MooSoft Development",
        @"SOFTWARE\FreeRaser",
        @"SOFTWARE\Heidi Computers\Eraser",
        @"SOFTWARE\Sami Tolvanen\File Shredder",
        @"SOFTWARE\East-Tec\Eraser",
        @"SOFTWARE\Evidence Nuker",
        @"SOFTWARE\CyberShredder",
        @"SOFTWARE\HardWipe",
        @"SOFTWARE\Active KillDisk",
    ];

    private static readonly string[] SuspiciousScheduledTaskKeywords =
    [
        "clean", "wipe", "erase", "delete", "shred", "purge",
        "remove cheat", "pre_scan", "before_scan", "prescan",
        "clean_fivem", "fivem_clean", "wipe_logs", "delete_logs",
        "clear_history", "clean_artifacts",
    ];

    private static readonly string[] CheatPathKeywords =
    [
        "fivem", "ragemp", "altv", "gta", "gtav", "kiddion",
        "eulen", "2take1", "stand", "cherax", "outbreak", "impulse",
        "cheat", "hack", "bypass", "inject", "mod",
    ];

    private static readonly string[] PowerShellEvasionKeywords =
    [
        "zero", "trace", "zerotrace", "ocean", "detect.ac", "scanner",
        "remove-item.*fivem", "remove-item.*cheat", "remove-item.*hack",
        "del.*fivem", "del.*cheat", "del.*bypass",
        "clear-eventlog", "wevtutil cl", "vssadmin delete",
        "set-mpreference.*disable", "add-mppreference.*exclusion",
        "disable.*defender", "stop.*windefend",
        "bypass.*amsi", "amsi.*bypass",
        "obfusc", "invoke-obfuscation", "base64", "encodedcommand",
        "-enc ", "-encodedcommand", "frombase64string",
    ];

    private static readonly string[] EvasionLogFiles =
    [
        "evasion.log", "anti_scan.log", "clean.log", "wipe.log",
        "prescan.log", "scanner_bypass.log", "cleanup.log",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckAntiForensicToolInstalls(ctx, ct),
            CheckAntiForensicRegistryArtifacts(ctx, ct),
            CheckScannerEvasionScheduledTasks(ctx, ct),
            CheckPowerShellHistoryForEvasion(ctx, ct),
            CheckBulkDeletionPatterns(ctx, ct),
            CheckCleanerConfigFiles(ctx, ct),
            CheckErasureToolLogs(ctx, ct),
            CheckTempFolderWipePatterns(ctx, ct),
            CheckRecycleBinMassWipe(ctx, ct),
            CheckScannerEvasionInStartup(ctx, ct),
            CheckAntiForensicBatchScripts(ctx, ct),
            CheckTimestompArtifacts(ctx, ct),
            CheckVSSDeleteArtifacts(ctx, ct),
            CheckEventLogClearArtifacts(ctx, ct),
            CheckShellBagWipePatterns(ctx, ct),
            CheckPrefetchManipulation(ctx, ct),
            CheckMRUWipePatterns(ctx, ct),
            CheckAntiForensicChainArtifacts(ctx, ct)
        );
    }

    private Task CheckAntiForensicToolInstalls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        using var hklm = Registry.LocalMachine;
        using var hkcu = Registry.CurrentUser;

        foreach (var hive in new[] { hklm, hkcu })
        {
            foreach (var uninstallPath in uninstallPaths)
            {
                try
                {
                    using var uninstallKey = hive.OpenSubKey(uninstallPath);
                    if (uninstallKey == null) continue;
                    foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using var appKey = uninstallKey.OpenSubKey(subKeyName);
                            if (appKey == null) continue;
                            ctx.IncrementRegistryKeys();
                            var displayName = appKey.GetValue("DisplayName")?.ToString() ?? string.Empty;
                            foreach (var tool in AntiForensicToolNames)
                            {
                                if (displayName.Contains(tool, StringComparison.OrdinalIgnoreCase))
                                {
                                    var installDate = appKey.GetValue("InstallDate")?.ToString() ?? "unknown";
                                    var installLoc = appKey.GetValue("InstallLocation")?.ToString() ?? "unknown";
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name, Title = "Anti-Forensic Tool Installed",
                                        Risk = Risk.High,
                                        Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                        FileName = displayName,
                                        Reason = $"Anti-forensic / file wipe tool '{displayName}' is installed — used to destroy evidence",
                                        Detail = $"Install date: {installDate}, Location: {installLoc}"
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAntiForensicRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hkcu = Registry.CurrentUser;
        using var hklm = Registry.LocalMachine;

        foreach (var regPath in AntiForensicRegistryPaths)
        {
            foreach (var hive in new[] { hkcu, hklm })
            {
                try
                {
                    using var key = hive.OpenSubKey(regPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                    var names = key.GetValueNames();
                    var toolName = regPath.Split('\\').Last();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "Anti-Forensic Tool Registry Artifact",
                        Risk = Risk.High,
                        Location = $@"HKCU\{regPath}",
                        FileName = toolName,
                        Reason = $"Registry artifact from anti-forensic tool '{toolName}' — indicates evidence destruction tool usage",
                        Detail = $"Registry path: {regPath}, Values: {string.Join(", ", names.Take(10))}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckScannerEvasionScheduledTasks(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var taskPaths = new[]
        {
            @"C:\Windows\System32\Tasks",
            @"C:\Windows\SysWOW64\Tasks",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs\Startup"),
        };

        foreach (var taskRoot in taskPaths)
        {
            if (!Directory.Exists(taskRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(taskRoot, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);

                        foreach (var kw in SuspiciousScheduledTaskKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Scheduled Task: Scanner Evasion / Cleaner",
                                    Risk = Risk.High, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Scheduled task contains cleanup keyword '{kw}' — may run before scans",
                                    Detail = content.Length > 500 ? content[..500] : content
                                });
                                break;
                            }
                        }

                        foreach (var kw in ScannerKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Scheduled Task: Scanner-Specific Evasion",
                                    Risk = Risk.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Scheduled task references scanner name '{kw}' — designed to evade specific scanner",
                                    Detail = content.Length > 500 ? content[..500] : content
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckPowerShellHistoryForEvasion(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var psHistoryPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                @"Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                @"Documents\PowerShell\Microsoft.PowerShell_profile.ps1"),
        };

        foreach (var psPath in psHistoryPaths)
        {
            if (!File.Exists(psPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(psPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                var content = await sr.ReadToEndAsync(ct);

                foreach (var kw in PowerShellEvasionKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "PowerShell History: Scanner Evasion Command",
                            Risk = Risk.Critical, Location = psPath,
                            FileName = Path.GetFileName(psPath),
                            Reason = $"Scanner evasion pattern '{kw}' found in PowerShell history",
                            Detail = content.Length > 600 ? content[..600] : content
                        });
                        break;
                    }
                }

                foreach (var kw in CleanerScriptKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "PowerShell History: Evidence Destruction Command",
                            Risk = Risk.High, Location = psPath,
                            FileName = Path.GetFileName(psPath),
                            Reason = $"Evidence destruction command '{kw}' in PowerShell history",
                            Detail = content.Length > 600 ? content[..600] : content
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckBulkDeletionPatterns(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var tempPath = Path.GetTempPath();
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchPaths = new[]
        {
            tempPath,
            Path.Combine(userProfile, "AppData", "Local", "Temp"),
        };

        var deletionLogKeywords = new[] { "deleted", "wiped", "erased", "removed", "cleaned", "shredded" };
        var cheatPathPatterns = new[] { "fivem", "ragemp", "altv", "gta", "cheat", "hack", "bypass", "kiddion", "eulen" };

        foreach (var searchRoot in searchPaths)
        {
            if (!Directory.Exists(searchRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(searchRoot, "*.log", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        bool hasDeletion = deletionLogKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        bool hasCheatPath = cheatPathPatterns.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hasDeletion && hasCheatPath)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Temp Log: Bulk Cheat Artifact Deletion",
                                Risk = Risk.High, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "Temporary log shows deletion of cheat-related file paths",
                                Detail = content.Length > 600 ? content[..600] : content
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckCleanerConfigFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var cleanerConfigPaths = new[]
        {
            Path.Combine(appData, "CCleaner"),
            Path.Combine(localAppData, "CCleaner"),
            Path.Combine(programFiles, "CCleaner"),
            Path.Combine(programFilesX86, "CCleaner"),
            Path.Combine(appData, "BleachBit"),
            Path.Combine(localAppData, "BleachBit"),
            Path.Combine(appData, "PrivaZer"),
            Path.Combine(localAppData, "PrivaZer"),
            Path.Combine(appData, "Wise Disk Cleaner"),
            Path.Combine(localAppData, "Wise Disk Cleaner"),
            Path.Combine(appData, "Eraser"),
        };

        foreach (var cleanerRoot in cleanerConfigPaths)
        {
            if (!Directory.Exists(cleanerRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(cleanerRoot, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext is not (".ini" or ".cfg" or ".xml" or ".json" or ".log" or ".txt")) continue;

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        foreach (var kw in CheatPathKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Cleaner Config: Cheat Path Targeted",
                                    Risk = Risk.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Cleaner config targets cheat-related path ('{kw}') — configured to erase cheat evidence",
                                    Detail = content.Length > 600 ? content[..600] : content
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckErasureToolLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var logSearchPaths = new[]
        {
            Path.Combine(appData, "Eraser"),
            Path.Combine(appData, "BleachBit"),
            Path.Combine(appData, "PrivaZer"),
            Path.Combine(userProfile, "Documents"),
        };

        foreach (var logRoot in logSearchPaths)
        {
            if (!Directory.Exists(logRoot)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(logRoot, "*.log", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        foreach (var kw in CheatPathKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Erasure Tool Log: Cheat Files Wiped",
                                    Risk = Risk.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Erasure tool log contains cheat path '{kw}' — evidence of targeted cheat file destruction",
                                    Detail = content.Length > 600 ? content[..600] : content
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckTempFolderWipePatterns(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var tempPath = Path.GetTempPath();
        if (!Directory.Exists(tempPath)) return Task.CompletedTask;

        try
        {
            var files = Directory.EnumerateFiles(tempPath, "*", SearchOption.TopDirectoryOnly).ToList();
            var fileCount = files.Count;

            if (fileCount == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "Temp Folder: Completely Empty",
                    Risk = Risk.Medium, Location = tempPath,
                    FileName = "Temp",
                    Reason = "Temp folder is completely empty — suggests deliberate wipe before scan",
                    Detail = $"Temp path: {tempPath}"
                });
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var name = Path.GetFileName(file).ToLowerInvariant();
                foreach (var tool in AntiForensicToolNames)
                {
                    if (name.Contains(tool, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Temp Folder: Anti-Forensic Tool Artifact",
                            Risk = Risk.High, Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Anti-forensic tool artifact '{tool}' found in temp folder",
                            Detail = $"Path: {file}"
                        });
                        break;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { }
        return Task.CompletedTask;
    }, ct);

    private Task CheckRecycleBinMassWipe(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var drives = DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
            .Select(d => d.RootDirectory.FullName);

        foreach (var drive in drives)
        {
            var recycleBin = Path.Combine(drive, "$Recycle.Bin");
            if (!Directory.Exists(recycleBin)) continue;
            try
            {
                foreach (var sidDir in Directory.EnumerateDirectories(recycleBin))
                {
                    foreach (var iFile in Directory.EnumerateFiles(sidDir, "$I*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(iFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            var content = await sr.ReadToEndAsync(ct);
                            foreach (var kw in CheatPathKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name, Title = "Recycle Bin: Cheat File Deleted",
                                        Risk = Risk.High, Location = iFile,
                                        FileName = Path.GetFileName(iFile),
                                        Reason = $"Recycle Bin $I metadata shows deleted cheat-related file ('{kw}')",
                                        Detail = content.Length > 300 ? content[..300] : content
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckScannerEvasionInStartup(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var startupPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        };

        using var hkcu = Registry.CurrentUser;
        using var hklm = Registry.LocalMachine;

        foreach (var hive in new[] { hkcu, hklm })
        {
            foreach (var startupPath in startupPaths)
            {
                try
                {
                    using var key = hive.OpenSubKey(startupPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                    foreach (var valueName in key.GetValueNames())
                    {
                        var val = key.GetValue(valueName)?.ToString()?.ToLowerInvariant() ?? string.Empty;
                        foreach (var tool in AntiForensicToolNames)
                        {
                            if (val.Contains(tool, StringComparison.OrdinalIgnoreCase) ||
                                valueName.Contains(tool, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Startup: Anti-Forensic Tool Auto-Run",
                                    Risk = Risk.High,
                                    Location = $@"HKCU\{startupPath}\{valueName}",
                                    FileName = valueName,
                                    Reason = $"Anti-forensic tool '{tool}' configured to run at startup — persistent evidence erasure",
                                    Detail = $"Value: {val}"
                                });
                                break;
                            }
                        }

                        foreach (var kw in ScannerKeywords)
                        {
                            if (val.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Startup: Scanner Evasion Tool",
                                    Risk = Risk.Critical,
                                    Location = $@"HKCU\{startupPath}\{valueName}",
                                    FileName = valueName,
                                    Reason = $"Startup entry references scanner name '{kw}' — scanner-specific evasion tool",
                                    Detail = $"Value: {val}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckAntiForensicBatchScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            Path.GetTempPath(),
        };

        foreach (var root in searchPaths)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.bat", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.EnumerateFiles(root, "*.cmd", SearchOption.TopDirectoryOnly))
                    .Concat(Directory.EnumerateFiles(root, "*.ps1", SearchOption.TopDirectoryOnly)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);

                        bool hasCleanerKw = CleanerScriptKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        bool hasCheatKw = CheatPathKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        bool hasScannerKw = ScannerKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (hasScannerKw)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Script: Scanner-Specific Evasion Script",
                                Risk = Risk.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "Script contains scanner-specific evasion keywords — designed to bypass forensic scan",
                                Detail = content.Length > 600 ? content[..600] : content
                            });
                        }
                        else if (hasCleanerKw && hasCheatKw)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Script: Cheat Evidence Destruction Script",
                                Risk = Risk.High, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "Script combines evidence destruction commands with cheat path keywords",
                                Detail = content.Length > 600 ? content[..600] : content
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckTimestompArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var fiveMPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM");
        if (!Directory.Exists(fiveMPath)) return Task.CompletedTask;

        try
        {
            foreach (var file in Directory.EnumerateFiles(fiveMPath, "*.dll", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                try
                {
                    var creationTime = File.GetCreationTimeUtc(file);
                    var lastWriteTime = File.GetLastWriteTimeUtc(file);
                    var now = DateTime.UtcNow;

                    if (creationTime > now || lastWriteTime > now)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Timestomp Artifact: Future Timestamp",
                            Risk = Risk.High, Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "File has a future timestamp — indicates timestomping (anti-forensic technique)",
                            Detail = $"Created: {creationTime:u}, Modified: {lastWriteTime:u}, Now: {now:u}"
                        });
                    }

                    if (creationTime > lastWriteTime.AddDays(1))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Timestomp Artifact: Creation After Write Time",
                            Risk = Risk.High, Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "File creation time is later than last write time — classic timestomping indicator",
                            Detail = $"Created: {creationTime:u}, Modified: {lastWriteTime:u}"
                        });
                    }
                }
                catch { }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { }
        return Task.CompletedTask;
    }, ct);

    private Task CheckVSSDeleteArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var systemEventLogPath = @"C:\Windows\System32\winevt\Logs\System.evtx";
        if (!File.Exists(systemEventLogPath)) return;
        ctx.IncrementFiles();

        var psHistoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
        if (!File.Exists(psHistoryPath)) return;
        ctx.IncrementFiles();

        try
        {
            using var fs = new FileStream(psHistoryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            var content = await sr.ReadToEndAsync(ct);
            var vssPatterns = new[] { "vssadmin delete shadows", "wmic shadowcopy delete", "delete shadows", "shadowcopy delete" };
            foreach (var pattern in vssPatterns)
            {
                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "VSS Delete: Shadow Copies Destroyed via PowerShell",
                        Risk = Risk.Critical, Location = psHistoryPath,
                        FileName = Path.GetFileName(psHistoryPath),
                        Reason = $"VSS shadow copy deletion command '{pattern}' found in PS history — destroys forensic restore points",
                        Detail = content.Length > 500 ? content[..500] : content
                    });
                    break;
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckEventLogClearArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var psHistoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
        if (!File.Exists(psHistoryPath)) return;
        ctx.IncrementFiles();

        try
        {
            using var fs = new FileStream(psHistoryPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            var content = await sr.ReadToEndAsync(ct);
            var logClearPatterns = new[]
            {
                "wevtutil cl", "clear-eventlog", "remove-eventlog",
                "wevtutil clear", "clear event log", "clearevtx",
            };
            foreach (var pattern in logClearPatterns)
            {
                if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "Event Log Clear: Anti-Forensic Command in PS History",
                        Risk = Risk.Critical, Location = psHistoryPath,
                        FileName = Path.GetFileName(psHistoryPath),
                        Reason = $"Event log clear command '{pattern}' in PS history — destroys cheat activity logs",
                        Detail = content.Length > 500 ? content[..500] : content
                    });
                    break;
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckShellBagWipePatterns(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var shellBagPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\Shell\BagMRU",
            @"SOFTWARE\Microsoft\Windows\Shell\Bags",
            @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
            @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
        };

        using var hkcu = Registry.CurrentUser;
        int bagCount = 0;

        foreach (var path in shellBagPaths)
        {
            try
            {
                using var key = hkcu.OpenSubKey(path);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();
                bagCount += key.GetSubKeyNames().Length;
            }
            catch { }
        }

        if (bagCount == 0)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name, Title = "ShellBags: All Entries Wiped",
                Risk = Risk.High,
                Location = @"HKCU\SOFTWARE\Microsoft\Windows\Shell",
                FileName = "BagMRU",
                Reason = "ShellBag entries are completely absent — deliberate wipe removes evidence of folder navigation history",
                Detail = "ShellBags track all folder access history; their absence indicates anti-forensic activity"
            });
        }
    }, ct);

    private Task CheckPrefetchManipulation(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var prefetchPath = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchPath)) return Task.CompletedTask;

        try
        {
            var prefetchFiles = Directory.EnumerateFiles(prefetchPath, "*.pf", SearchOption.TopDirectoryOnly).ToList();
            ctx.IncrementFiles();

            if (prefetchFiles.Count == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "Prefetch: Folder Completely Empty",
                    Risk = Risk.High, Location = prefetchPath,
                    FileName = "Prefetch",
                    Reason = "Prefetch folder is empty — all execution history erased (anti-forensic)",
                    Detail = "Normal systems have 100-1024 prefetch files"
                });
            }

            foreach (var pf in prefetchFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var name = Path.GetFileNameWithoutExtension(pf).ToLowerInvariant();
                foreach (var tool in AntiForensicToolNames)
                {
                    if (name.Contains(tool, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Prefetch: Anti-Forensic Tool Execution",
                            Risk = Risk.High, Location = pf,
                            FileName = Path.GetFileName(pf),
                            Reason = $"Anti-forensic tool '{tool}' prefetch entry — confirms tool was executed",
                            Detail = $"Path: {pf}"
                        });
                        break;
                    }
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { }
        return Task.CompletedTask;
    }, ct);

    private Task CheckMRUWipePatterns(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var mruPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        };

        using var hkcu = Registry.CurrentUser;
        foreach (var mruPath in mruPaths)
        {
            try
            {
                using var key = hkcu.OpenSubKey(mruPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();
                var subKeys = key.GetSubKeyNames();
                var valueNames = key.GetValueNames();

                if (subKeys.Length == 0 && valueNames.Length == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "MRU Wiped: Recent Document History Empty",
                        Risk = Risk.Medium,
                        Location = $@"HKCU\{mruPath}",
                        FileName = mruPath.Split('\\').Last(),
                        Reason = "MRU (Most Recently Used) list is empty — deliberate wipe removes file access history",
                        Detail = $"Registry: {mruPath}"
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckAntiForensicChainArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchPaths = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Path.Combine(userProfile, "Desktop"),
            Path.GetTempPath(),
        };

        foreach (var root in searchPaths)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileName(file).ToLowerInvariant();
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    int toolMatches = AntiForensicToolNames.Count(t => name.Contains(t, StringComparison.OrdinalIgnoreCase));
                    if (toolMatches > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Anti-Forensic Chain: Cleaner Tool Artifact",
                            Risk = Risk.High, Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Multiple anti-forensic tool references in file — evidence of chained cleaning",
                            Detail = $"Path: {file}"
                        });
                    }

                    if (ext is ".bat" or ".ps1" or ".cmd")
                    {
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            var content = await sr.ReadToEndAsync(ct);
                            int cleanerCount = AntiForensicToolNames.Count(t => content.Contains(t, StringComparison.OrdinalIgnoreCase));
                            if (cleanerCount >= 2)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Anti-Forensic Chain: Multi-Tool Erasure Script",
                                    Risk = Risk.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Script invokes {cleanerCount} anti-forensic tools — chained erasure to defeat forensic recovery",
                                    Detail = content.Length > 600 ? content[..600] : content
                                });
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);
}
