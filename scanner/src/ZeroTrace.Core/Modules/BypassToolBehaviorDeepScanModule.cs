using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class BypassToolBehaviorDeepScanModule : IScanModule
{
    public string Name => "Bypass Tool Behavior Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string System32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
    private static readonly string ProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
    private static readonly string Windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    private static readonly string[] CheatKeywords =
    [
        "cheat", "hack", "bypass", "inject", "aimbot", "wallhack", "esp",
        "triggerbot", "speedhack", "godmode", "noclip", "teleport",
        "eac_bypass", "be_bypass", "vac_bypass", "hwid_bypass", "hwid_spoof",
        "fivem_hack", "fivem_cheat", "fivem_bypass", "ragemp_hack", "ragemp_cheat",
        "altv_hack", "altv_cheat", "altv_bypass",
        "kdmapper", "manualmapper", "drivermapper", "kernelhack",
        "mhyprot", "iqvw64e", "dbutildrv2", "rtcore64",
        "cheatengine", "trainer hack", "game hack",
        "inject dll", "dll inject", "reflective dll",
        "neverlose", "fatality", "onetap", "skeet", "gamesense",
        "internal cheat", "external cheat", "kernel cheat",
        "superiorware", "hyperion bypass", "orbit cheat"
    ];

    private static readonly string[] BypassToolNames =
    [
        "kdmapper", "drivermapper", "vulnerable_driver", "byovd",
        "eac_bypass", "be_bypass", "vac_bypass", "vanguard_bypass",
        "faceit_bypass", "esea_bypass", "nprotect_bypass",
        "gg_bypass", "gameguard_bypass", "xigncode_bypass",
        "equ8_bypass", "mhyprot2", "iqvw64e", "dbutildrv2",
        "rtcore64", "gdrv", "dbutil_2_3", "winring0",
        "pcdsrvc", "asio64", "hw64", "inpoutx64",
        "rzpnk", "capcom", "hacksys", "procexp",
        "evil_driver", "hwid_bypass_driver", "spoofer_driver",
        "manual_mapper", "kernel_mapper", "ring0_loader",
        "ac_bypass_tool", "anti_bypass", "anti_cheat_bypass",
        "easyanticheat_bypass", "battleye_bypass",
        "testsigning_bypass", "dsense_bypass", "ci_bypass"
    ];

    private static readonly string[] SuspiciousInstallerNames =
    [
        "cheat_setup", "hack_setup", "bypass_setup", "injector_setup",
        "loader_setup", "spoofer_setup", "hwid_setup", "cheat_install",
        "hack_install", "bypass_install", "cheatsetup", "hacksetup",
        "cheat_installer", "hack_installer", "bypass_installer",
        "cheat_update", "hack_update", "bypass_update",
        "loader_update", "spoofer_update", "hwid_update",
        "eac_patcher", "be_patcher", "vac_patcher",
        "cheat_launcher", "hack_launcher", "bypass_launcher",
        "fivem_cheat_setup", "ragemp_cheat_setup", "altv_cheat_setup"
    ];

    private static readonly string[] WindowsInstallerLogKeywords =
    [
        "cheat", "hack", "bypass", "inject", "aimbot", "wallhack",
        "eac_bypass", "be_bypass", "vac_bypass", "hwid",
        "kdmapper", "mhyprot", "kernel cheat", "spoofer",
        "fivem cheat", "ragemp cheat", "altv cheat"
    ];

    private static readonly string[] CbsLogBypassKeywords =
    [
        "Driver_bypass", "cheat_driver", "unsigned_driver", "test_signing",
        "setenforce", "bypass_ci", "disabled_ci", "driver_blocked"
    ];

    private static readonly string[] PowerShellHistoryPaths =
    [
        @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        @"AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    ];

    private static readonly string[] WindowsInstallerLogPaths =
    [
        @"Windows\Logs\CBS\CBS.log",
        @"Windows\Logs\DISM\dism.log",
        @"Windows\Inf\setupapi.dev.log",
        @"Windows\Inf\setupapi.app.log",
        @"Windows\Panther\UnattendGC\setupact.log"
    ];

    private static readonly string[] SoftwareDistributionPaths =
    [
        @"C:\Windows\SoftwareDistribution\DataStore\Logs\edb.log",
        @"C:\Windows\SoftwareDistribution\ReportingEvents.log",
        @"C:\Windows\WindowsUpdate.log"
    ];

    private static readonly string[] ServiceInstallEventPaths =
    [
        @"C:\Windows\INF\setupapi.dev.log",
        @"C:\Windows\INF\setupapi.app.log",
        @"C:\Windows\INF\oem*.inf"
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckWindowsInstallerLogs(ctx, ct),
            CheckCbsAndDismLogs(ctx, ct),
            CheckSetupApiLogs(ctx, ct),
            CheckMsiInstallHistory(ctx, ct),
            CheckWerCrashDumps(ctx, ct),
            CheckDrWatsonLogs(ctx, ct),
            CheckApplicationEventLogArtifacts(ctx, ct),
            CheckServiceInstallHistory(ctx, ct),
            CheckBypassDriverServiceHistory(ctx, ct),
            CheckRegistryTransactionLogs(ctx, ct),
            CheckWindowsLogsDirectory(ctx, ct),
            CheckRecycleBinBypassArtifacts(ctx, ct),
            CheckVolumeBootRecordArtifacts(ctx, ct),
            CheckInstalledDriversBypassHistory(ctx, ct),
            CheckWindowsUpdateBypassLogs(ctx, ct),
            CheckBypassToolDownloadHistory(ctx, ct),
            CheckCryptoUsageForBypass(ctx, ct),
            CheckBcdStoreBypassArtifacts(ctx, ct)
        );
    }

    private Task CheckWindowsInstallerLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logPaths = new[]
        {
            Path.Combine(Windows, "Logs", "CBS", "CBS.log"),
            Path.Combine(Windows, "Logs", "MoSetup", "BlueBox.log"),
            Path.Combine(Windows, "Logs", "DPX", "setupact.log")
        };

        var tempLogs = new List<string>();
        try
        {
            tempLogs.AddRange(Directory.GetFiles(Path.GetTempPath(), "MSI*.log", SearchOption.TopDirectoryOnly));
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        try
        {
            tempLogs.AddRange(Directory.GetFiles(Path.Combine(Windows, "Temp"), "MSI*.log", SearchOption.TopDirectoryOnly));
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        foreach (var logPath in logPaths.Concat(tempLogs))
        {
            ctx.IncrementFiles();
            if (!File.Exists(logPath)) continue;
            try
            {
                using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (var keyword in WindowsInstallerLogKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        var lines = content.Split('\n')
                            .Where(l => l.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            .Take(3).ToList();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Bypass/Cheat Tool in Windows Installer Log",
                            Risk = RiskLevel.High,
                            Location = logPath,
                            FileName = Path.GetFileName(logPath),
                            Reason = $"Windows Installer log references cheat/bypass keyword: '{keyword}'",
                            Detail = string.Join("; ", lines.Select(l => l.Trim()).Take(2))
                        });
                        break;
                    }
                }

                foreach (var tn in BypassToolNames)
                {
                    if (content.Contains(tn, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Known Bypass Tool Name in Installer Log",
                            Risk = RiskLevel.Critical,
                            Location = logPath,
                            FileName = Path.GetFileName(logPath),
                            Reason = $"Installer log references known bypass tool: '{tn}'",
                            Detail = $"Log: {Path.GetFileName(logPath)}"
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckCbsAndDismLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var cbsLogPath = Path.Combine(Windows, "Logs", "CBS", "CBS.log");
        var dismLogPath = Path.Combine(Windows, "Logs", "DISM", "dism.log");

        foreach (var logPath in new[] { cbsLogPath, dismLogPath })
        {
            ctx.IncrementFiles();
            if (!File.Exists(logPath)) continue;
            try
            {
                using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                if (content.Contains("TestSigning", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("test signing", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Test Signing Mode Reference in CBS/DISM Log",
                        Risk = RiskLevel.High,
                        Location = logPath,
                        FileName = Path.GetFileName(logPath),
                        Reason = "CBS/DISM log references test signing mode — bypass tools enable this to load unsigned kernel drivers",
                        Detail = $"Log: {Path.GetFileName(logPath)}"
                    });
                }

                if (content.Contains("code integrity disabled", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("unsigned driver", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("driver blocked", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Code Integrity/Driver Signing Issue in CBS/DISM Log",
                        Risk = RiskLevel.High,
                        Location = logPath,
                        FileName = Path.GetFileName(logPath),
                        Reason = "CBS/DISM log references unsigned driver or CI bypass activity",
                        Detail = $"Log: {Path.GetFileName(logPath)}"
                    });
                }

                foreach (var ck in CheatKeywords)
                {
                    if (content.Contains(ck, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Keyword in CBS/DISM Log",
                            Risk = RiskLevel.High,
                            Location = logPath,
                            FileName = Path.GetFileName(logPath),
                            Reason = $"System log references cheat/bypass keyword: '{ck}'",
                            Detail = $"Log: {Path.GetFileName(logPath)}"
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckSetupApiLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var setupLogs = new[]
        {
            Path.Combine(Windows, "INF", "setupapi.dev.log"),
            Path.Combine(Windows, "INF", "setupapi.app.log"),
            Path.Combine(Windows, "INF", "setupapi.offline.log")
        };

        foreach (var logPath in setupLogs)
        {
            ctx.IncrementFiles();
            if (!File.Exists(logPath)) continue;
            try
            {
                using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (var tn in BypassToolNames)
                {
                    if (content.Contains(tn, StringComparison.OrdinalIgnoreCase))
                    {
                        var lines = content.Split('\n')
                            .Where(l => l.Contains(tn, StringComparison.OrdinalIgnoreCase))
                            .Take(2).ToList();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Bypass/Vulnerable Driver in Setup Log: {tn}",
                            Risk = RiskLevel.Critical,
                            Location = logPath,
                            FileName = Path.GetFileName(logPath),
                            Reason = $"SetupAPI log records installation of known bypass/vulnerable driver: '{tn}'",
                            Detail = string.Join("; ", lines.Select(l => l.Trim()).Take(2))
                        });
                    }
                }

                if (content.Contains("failed to install driver", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("driver was not successfully installed", StringComparison.OrdinalIgnoreCase))
                {
                    var failLines = content.Split('\n')
                        .Where(l => l.Contains("failed to install driver", StringComparison.OrdinalIgnoreCase) ||
                                    l.Contains("not successfully installed", StringComparison.OrdinalIgnoreCase))
                        .Take(3).ToList();

                    foreach (var line in failLines)
                    {
                        if (BypassToolNames.Any(bn => line.Contains(bn, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Bypass Driver Install Failure in SetupAPI Log",
                                Risk = RiskLevel.High,
                                Location = logPath,
                                FileName = Path.GetFileName(logPath),
                                Reason = "SetupAPI log shows failed bypass/vulnerable driver installation attempt",
                                Detail = line.Trim()[..Math.Min(200, line.Length)]
                            });
                        }
                    }
                }

                foreach (var ck in CheatKeywords)
                {
                    if (content.Contains(ck, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Keyword in SetupAPI Driver Log",
                            Risk = RiskLevel.High,
                            Location = logPath,
                            FileName = Path.GetFileName(logPath),
                            Reason = $"SetupAPI log references cheat/bypass tool: '{ck}'",
                            Detail = $"Log: {Path.GetFileName(logPath)}"
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckMsiInstallHistory(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var msiInstallKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData",
            @"SOFTWARE\Classes\Installer\Products"
        };

        foreach (var keyPath in msiInstallKeys)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                foreach (var sidName in key.GetSubKeyNames())
                {
                    try
                    {
                        using var sidKey = key.OpenSubKey(sidName);
                        var productsKey = sidKey?.OpenSubKey("Products");
                        if (productsKey == null) continue;

                        foreach (var productGuid in productsKey.GetSubKeyNames())
                        {
                            try
                            {
                                using var productKey = productsKey.OpenSubKey(productGuid);
                                var installProps = productKey?.OpenSubKey("InstallProperties");
                                if (installProps == null) continue;

                                var displayName = installProps.GetValue("DisplayName")?.ToString()?.ToLowerInvariant() ?? "";
                                var installSource = installProps.GetValue("InstallSource")?.ToString()?.ToLowerInvariant() ?? "";
                                var installDate = installProps.GetValue("InstallDate")?.ToString() ?? "";

                                ctx.IncrementRegistryKeys();

                                foreach (var ck in CheatKeywords)
                                {
                                    if (displayName.Contains(ck.ToLowerInvariant()) ||
                                        installSource.Contains(ck.ToLowerInvariant()))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = Name,
                                            Title = "Cheat/Bypass Tool in MSI Install History",
                                            Risk = RiskLevel.Critical,
                                            Location = $@"HKLM\{keyPath}\{sidName}\Products\{productGuid}",
                                            FileName = "Registry",
                                            Reason = $"MSI install history references cheat/bypass tool: '{ck}'",
                                            Detail = $"DisplayName: {displayName}, InstallDate: {installDate}, Source: {installSource}"
                                        });
                                        break;
                                    }
                                }

                                foreach (var tn in SuspiciousInstallerNames)
                                {
                                    if (displayName.Contains(tn.ToLowerInvariant()) ||
                                        installSource.Contains(tn.ToLowerInvariant()))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = Name,
                                            Title = "Suspicious Installer in MSI History",
                                            Risk = RiskLevel.High,
                                            Location = $@"HKLM\{keyPath}\{sidName}\Products\{productGuid}",
                                            FileName = "Registry",
                                            Reason = $"MSI install history has suspicious installer name: '{tn}'",
                                            Detail = $"Product: {displayName}, Date: {installDate}"
                                        });
                                        break;
                                    }
                                }
                            }
                            catch (UnauthorizedAccessException) { }
                            catch (IOException) { }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckWerCrashDumps(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var werPaths = new List<string>
        {
            Path.Combine(ProgramData, @"Microsoft\Windows\WER\ReportQueue"),
            Path.Combine(ProgramData, @"Microsoft\Windows\WER\ReportArchive"),
            Path.Combine(ProgramData, @"Microsoft\Windows\WER\Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Windows\WER\ReportQueue"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Windows\WER\ReportArchive"),
            @"C:\Windows\Minidump",
            @"C:\Windows\LiveKernelReports"
        };

        var userDirs = new List<string>();
        try { userDirs.AddRange(Directory.GetDirectories(@"C:\Users")); }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        foreach (var u in userDirs)
        {
            werPaths.Add(Path.Combine(u, @"AppData\Local\Microsoft\Windows\WER\ReportQueue"));
            werPaths.Add(Path.Combine(u, @"AppData\Local\Microsoft\Windows\WER\ReportArchive"));
        }

        foreach (var werPath in werPaths.Distinct())
        {
            if (!Directory.Exists(werPath)) continue;
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(werPath))
                {
                    var dirName = Path.GetFileName(dir).ToLowerInvariant();
                    foreach (var ck in CheatKeywords)
                    {
                        if (dirName.Contains(ck.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat/Bypass Process in WER Crash Report",
                                Risk = RiskLevel.High,
                                Location = dir,
                                FileName = Path.GetFileName(dir),
                                Reason = $"Windows Error Reporting crash directory references cheat tool: '{ck}'",
                                Detail = $"WER report: {dir}"
                            });
                            break;
                        }
                    }

                    foreach (var tn in BypassToolNames)
                    {
                        if (dirName.Contains(tn.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Known Bypass Tool Crash Dump in WER",
                                Risk = RiskLevel.Critical,
                                Location = dir,
                                FileName = Path.GetFileName(dir),
                                Reason = $"WER crash report for known bypass tool: '{tn}'",
                                Detail = $"WER directory: {dir}"
                            });
                            break;
                        }
                    }

                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(dir))
                        {
                            ctx.IncrementFiles();
                            var fileName = Path.GetFileName(file).ToLowerInvariant();
                            if (fileName.EndsWith(".wer", StringComparison.OrdinalIgnoreCase))
                            {
                                try
                                {
                                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                    using var sr = new StreamReader(fs);
                                    string content = sr.ReadToEnd();
                                    foreach (var ck in CheatKeywords)
                                    {
                                        if (content.Contains(ck, StringComparison.OrdinalIgnoreCase))
                                        {
                                            ctx.AddFinding(new Finding
                                            {
                                                Module = Name,
                                                Title = "Cheat Tool Referenced in WER Report File",
                                                Risk = RiskLevel.High,
                                                Location = file,
                                                FileName = Path.GetFileName(file),
                                                Reason = $"WER report file references cheat tool: '{ck}'",
                                                Detail = $"File: {file}"
                                            });
                                            break;
                                        }
                                    }
                                }
                                catch (UnauthorizedAccessException) { }
                                catch (IOException) { }
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckDrWatsonLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var drWatsonPaths = new[]
        {
            Path.Combine(Windows, "System32", "config", "systemprofile", "AppData", "Local", "Microsoft", "Windows", "WER"),
            @"C:\DrWatson",
            Path.Combine(Windows, "drwtsn32.log")
        };

        var localDumps = Path.Combine(Windows, "MEMORY.DMP");
        ctx.IncrementFiles();
        if (File.Exists(localDumps))
        {
            try
            {
                var fi = new FileInfo(localDumps);
                if ((DateTime.UtcNow - fi.LastWriteTimeUtc).TotalDays <= 7)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Recent Full Memory Dump Found",
                        Risk = RiskLevel.Medium,
                        Location = localDumps,
                        FileName = "MEMORY.DMP",
                        Reason = $"Full kernel memory dump created within the last {(DateTime.UtcNow - fi.LastWriteTimeUtc).TotalDays:F0} days — may indicate system crash caused by bypass driver",
                        Detail = $"File: {localDumps}, Modified: {fi.LastWriteTimeUtc:u}, Size: {fi.Length / 1024 / 1024}MB"
                    });
                }
            }
            catch (IOException) { }
        }

        try
        {
            using var localDumpsKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps");
            ctx.IncrementRegistryKeys();
            if (localDumpsKey != null)
            {
                foreach (var subKeyName in localDumpsKey.GetSubKeyNames())
                {
                    var lower = subKeyName.ToLowerInvariant();
                    foreach (var ck in CheatKeywords)
                    {
                        if (lower.Contains(ck.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat Tool in WER LocalDumps Configuration",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\{subKeyName}",
                                FileName = "Registry",
                                Reason = $"WER local dumps configured for cheat process: '{subKeyName}' — may be set to capture AC process memory",
                                Detail = $"Process: {subKeyName}"
                            });
                            break;
                        }
                    }
                }

                var dumpFolder = localDumpsKey.GetValue("DumpFolder")?.ToString() ?? "";
                if (!string.IsNullOrEmpty(dumpFolder) && Directory.Exists(dumpFolder))
                {
                    try
                    {
                        foreach (var dmpFile in Directory.EnumerateFiles(dumpFolder, "*.dmp", SearchOption.TopDirectoryOnly))
                        {
                            ctx.IncrementFiles();
                            var dmpName = Path.GetFileNameWithoutExtension(dmpFile).ToLowerInvariant();
                            foreach (var ck in CheatKeywords)
                            {
                                if (dmpName.Contains(ck.ToLowerInvariant()))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Cheat Process Crash Dump Found",
                                        Risk = RiskLevel.High,
                                        Location = dmpFile,
                                        FileName = Path.GetFileName(dmpFile),
                                        Reason = $"Crash dump for cheat-related process: '{ck}'",
                                        Detail = $"Dump: {dmpFile}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckApplicationEventLogArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var appLogPath = Path.Combine(System32, "winevt", "Logs", "Application.evtx");
        ctx.IncrementFiles();
        if (!File.Exists(appLogPath))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Application Event Log Missing",
                Risk = RiskLevel.High,
                Location = appLogPath,
                FileName = "Application.evtx",
                Reason = "Application event log file absent — may have been deleted by cleaner/bypass to hide application crash/install events",
                Detail = $"Expected: {appLogPath}"
            });
            return;
        }

        try
        {
            var fi = new FileInfo(appLogPath);
            if (fi.Length < 131072)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Application Event Log Suspiciously Small",
                    Risk = RiskLevel.Medium,
                    Location = appLogPath,
                    FileName = "Application.evtx",
                    Reason = $"Application event log is only {fi.Length / 1024}KB — may have been cleared to remove bypass/install evidence",
                    Detail = $"Size: {fi.Length} bytes"
                });
            }
        }
        catch (IOException) { }
    }, ct);

    private Task CheckServiceInstallHistory(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            ctx.IncrementRegistryKeys();
            if (servicesKey == null) return;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                try
                {
                    using var svcKey = servicesKey.OpenSubKey(svcName);
                    if (svcKey == null) continue;

                    var imagePath = svcKey.GetValue("ImagePath")?.ToString()?.ToLowerInvariant() ?? "";
                    var displayName = svcKey.GetValue("DisplayName")?.ToString()?.ToLowerInvariant() ?? "";
                    var description = svcKey.GetValue("Description")?.ToString()?.ToLowerInvariant() ?? "";
                    var type = svcKey.GetValue("Type");

                    ctx.IncrementRegistryKeys();

                    var combined = svcName.ToLowerInvariant() + " " + imagePath + " " + displayName + " " + description;

                    foreach (var tn in BypassToolNames)
                    {
                        if (combined.Contains(tn.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Known Bypass Tool Service Found: {svcName}",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = "Registry",
                                Reason = $"Windows service matches known bypass tool name: '{tn}'",
                                Detail = $"Service: {svcName}, ImagePath: {imagePath}"
                            });
                            break;
                        }
                    }

                    if (type is int t && t == 1 && imagePath.Contains("\\temp\\", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Kernel Driver Service Running from Temp Directory",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = "Registry",
                            Reason = $"Kernel driver service '{svcName}' has ImagePath in Temp directory — BYOVD/bypass tool pattern",
                            Detail = $"ImagePath: {imagePath}"
                        });
                    }

                    if (!string.IsNullOrEmpty(imagePath) && imagePath.Contains("\\driver", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (var ck in CheatKeywords)
                        {
                            if (combined.Contains(ck.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Cheat-Related Driver Service: {svcName}",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                    FileName = "Registry",
                                    Reason = $"Driver service with cheat keyword in name/path/description: '{ck}'",
                                    Detail = $"Service: {svcName}, ImagePath: {imagePath}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckBypassDriverServiceHistory(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var knownBypassServices = new Dictionary<string, string>
        {
            ["iqvw64e"] = "Intel Network Adapter Diagnostic Driver (BYOVD exploit)",
            ["dbutil_2_3"] = "Dell DBUtil BIOS Update Driver (BYOVD exploit)",
            ["mhyprot2"] = "MiHoYo anti-cheat driver (BYOVD exploit)",
            ["RTCore64"] = "MSI Afterburner Ring-0 Read/Write Driver (BYOVD)",
            ["gdrv"] = "Gigabyte Driver Helper (BYOVD exploit)",
            ["WinRing0x64"] = "WinRing0 I/O Driver (BYOVD exploit)",
            ["rzpnk"] = "Razer Overlay Support Driver (BYOVD)",
            ["AsrDrv101"] = "ASRock Driver (BYOVD exploit)",
            ["AsrDrv102"] = "ASRock Driver v2 (BYOVD exploit)",
            ["HW64"] = "HWiNFO64 Driver (BYOVD exploit)",
            ["cpuz134_x64"] = "CPU-Z Driver (BYOVD exploit)",
            ["asmmap64"] = "ASMMAP64 Driver (BYOVD)",
            ["pcdsrvc_x64"] = "PC Doctor Service (BYOVD)",
            ["AsIO64"] = "ASUS IO Driver (BYOVD exploit)",
            ["Netis_x64"] = "Netis Driver (BYOVD)",
            ["netfilter64"] = "NetFilter Driver (BYOVD)",
            ["ProcExp152"] = "Process Explorer Driver (BYOVD)",
            ["PROCEXP"] = "Process Explorer SYSTEM driver",
            ["kdmapper_driver"] = "kdmapper custom driver",
            ["dmapper_driver"] = "drivermapper custom driver"
        };

        foreach (var svc in knownBypassServices)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svc.Key}");
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Known BYOVD/Bypass Driver Service Registered: {svc.Key}",
                    Risk = RiskLevel.Critical,
                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svc.Key}",
                    FileName = "Registry",
                    Reason = $"Known vulnerable/bypass driver service present: '{svc.Key}' — {svc.Value}",
                    Detail = $"Service key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc.Key}"
                });
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRegistryTransactionLogs(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var regTransactionPaths = new[]
        {
            Path.Combine(Windows, "System32", "config", "SYSTEM.LOG"),
            Path.Combine(Windows, "System32", "config", "SYSTEM.LOG1"),
            Path.Combine(Windows, "System32", "config", "SYSTEM.LOG2"),
            Path.Combine(Windows, "System32", "config", "SOFTWARE.LOG"),
            Path.Combine(Windows, "System32", "config", "SOFTWARE.LOG1"),
            Path.Combine(Windows, "System32", "config", "SECURITY.LOG")
        };

        foreach (var logPath in regTransactionPaths)
        {
            ctx.IncrementFiles();
            if (!File.Exists(logPath)) continue;
            try
            {
                var fi = new FileInfo(logPath);
                if (fi.Length < 512)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Registry Transaction Log Unusually Small",
                        Risk = RiskLevel.Medium,
                        Location = logPath,
                        FileName = Path.GetFileName(logPath),
                        Reason = $"Registry transaction log is only {fi.Length} bytes — normal transaction logs are larger, may indicate log wiping",
                        Detail = $"Path: {logPath}, Size: {fi.Length} bytes"
                    });
                }
            }
            catch (IOException) { }
        }

        var regHiveDir = Path.Combine(Windows, "System32", "config");
        ctx.IncrementFiles();
        if (!Directory.Exists(regHiveDir)) return;

        try
        {
            var secHive = Path.Combine(regHiveDir, "SECURITY");
            if (File.Exists(secHive))
            {
                var fi = new FileInfo(secHive);
                if (fi.Length < 32768)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "SECURITY Registry Hive Unusually Small",
                        Risk = RiskLevel.High,
                        Location = secHive,
                        FileName = "SECURITY",
                        Reason = $"SECURITY hive is only {fi.Length} bytes — unusually small, may indicate corruption or tampering",
                        Detail = $"Normal size: >32KB, Current: {fi.Length} bytes"
                    });
                }
            }
        }
        catch (IOException) { }
    }, ct);

    private Task CheckWindowsLogsDirectory(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var windowsLogsDir = Path.Combine(Windows, "Logs");
        if (!Directory.Exists(windowsLogsDir)) return;

        var importantLogDirs = new[]
        {
            Path.Combine(windowsLogsDir, "CBS"),
            Path.Combine(windowsLogsDir, "DISM"),
            Path.Combine(windowsLogsDir, "DPX"),
            Path.Combine(windowsLogsDir, "MoSetup"),
            Path.Combine(windowsLogsDir, "WindowsUpdate"),
            Path.Combine(windowsLogsDir, "NetSetup")
        };

        foreach (var logDir in importantLogDirs)
        {
            ctx.IncrementFiles();
            if (!Directory.Exists(logDir)) continue;
            try
            {
                var logFiles = Directory.GetFiles(logDir, "*", SearchOption.TopDirectoryOnly);
                if (logFiles.Length == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Windows Log Directory Empty: {Path.GetFileName(logDir)}",
                        Risk = RiskLevel.Medium,
                        Location = logDir,
                        FileName = Path.GetFileName(logDir),
                        Reason = $"Windows log directory '{Path.GetFileName(logDir)}' is empty — logs may have been wiped by cleaner/bypass tool",
                        Detail = $"Directory: {logDir}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRecycleBinBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var drives = DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed)
            .Select(d => d.RootDirectory.FullName)
            .ToList();

        foreach (var drive in drives)
        {
            var recycleBin = Path.Combine(drive, "$Recycle.Bin");
            if (!Directory.Exists(recycleBin)) continue;
            try
            {
                foreach (var userDir in Directory.GetDirectories(recycleBin))
                {
                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(userDir, "$R*", SearchOption.TopDirectoryOnly))
                        {
                            ctx.IncrementFiles();
                            var infFile = file.Replace("$R", "$I");
                            if (!File.Exists(infFile)) continue;

                            try
                            {
                                using var fs = new FileStream(infFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var br = new BinaryReader(fs);
                                if (fs.Length < 24) continue;

                                fs.Seek(0, SeekOrigin.Begin);
                                var header = br.ReadInt64();
                                if (header != 0x0000000000000002 && header != 0x0000000000000001) continue;

                                fs.Seek(16, SeekOrigin.Begin);
                                var pathBytes = br.ReadBytes((int)Math.Min(fs.Length - 16, 520));
                                var originalPath = System.Text.Encoding.Unicode.GetString(pathBytes).TrimEnd('\0').ToLowerInvariant();

                                foreach (var ck in CheatKeywords)
                                {
                                    if (originalPath.Contains(ck.ToLowerInvariant()))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = Name,
                                            Title = "Cheat/Bypass Tool Deleted to Recycle Bin",
                                            Risk = RiskLevel.High,
                                            Location = file,
                                            FileName = Path.GetFileName(file),
                                            Reason = $"Recycle bin contains deleted cheat/bypass file: '{ck}'",
                                            Detail = $"Original path: {originalPath}"
                                        });
                                        break;
                                    }
                                }

                                foreach (var tn in BypassToolNames)
                                {
                                    if (originalPath.Contains(tn.ToLowerInvariant()))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = Name,
                                            Title = "Known Bypass Tool Deleted to Recycle Bin",
                                            Risk = RiskLevel.Critical,
                                            Location = file,
                                            FileName = Path.GetFileName(file),
                                            Reason = $"Recycle bin contains deleted known bypass tool: '{tn}'",
                                            Detail = $"Original path: {originalPath}"
                                        });
                                        break;
                                    }
                                }
                            }
                            catch (IOException) { }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckVolumeBootRecordArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var bcdKey = Registry.LocalMachine.OpenSubKey(@"BCD00000000\Objects");
            ctx.IncrementRegistryKeys();
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        try
        {
            using var loadOptionsKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control");
            ctx.IncrementRegistryKeys();
            if (loadOptionsKey != null)
            {
                var systemStartOptions = loadOptionsKey.GetValue("SystemStartOptions")?.ToString() ?? "";
                if (systemStartOptions.Contains("TESTSIGNING", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Test Signing Mode Active in Boot Options",
                        Risk = RiskLevel.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SystemStartOptions",
                        FileName = "Registry",
                        Reason = "Test signing mode detected in system start options — allows loading of unsigned bypass/cheat kernel drivers",
                        Detail = $"SystemStartOptions: {systemStartOptions}"
                    });
                }

                if (systemStartOptions.Contains("NOINTEGRITYCHECKS", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Code Integrity Checks Disabled in Boot Options",
                        Risk = RiskLevel.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SystemStartOptions",
                        FileName = "Registry",
                        Reason = "NOINTEGRITYCHECKS in boot options — kernel code integrity checks bypassed, all unsigned drivers load",
                        Detail = $"SystemStartOptions: {systemStartOptions}"
                    });
                }

                if (systemStartOptions.Contains("DEBUG", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Kernel Debug Mode Active",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\SystemStartOptions",
                        FileName = "Registry",
                        Reason = "Kernel debug mode detected in boot options — enables kernel manipulation by bypass tools",
                        Detail = $"SystemStartOptions: {systemStartOptions}"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckInstalledDriversBypassHistory(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var driverDirs = new[]
        {
            Path.Combine(System32, "drivers"),
            Path.Combine(System32, "drivers", "etc"),
            @"C:\Windows\SysWOW64\drivers"
        };

        var bypassDriverExtensions = new[] { ".sys" };

        foreach (var driverDir in driverDirs)
        {
            if (!Directory.Exists(driverDir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(driverDir, "*.sys", SearchOption.TopDirectoryOnly))
                {
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();

                    foreach (var tn in BypassToolNames)
                    {
                        var tnLower = tn.ToLowerInvariant().Replace("_", "").Replace("-", "");
                        var fileNameNorm = fileName.Replace("_", "").Replace("-", "");
                        if (fileNameNorm.Contains(tnLower) || tnLower.Contains(fileNameNorm))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Known Bypass Driver File in Drivers Directory: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Known BYOVD/bypass driver found: '{tn}'",
                                Detail = $"Driver path: {file}"
                            });
                            break;
                        }
                    }

                    foreach (var ck in CheatKeywords)
                    {
                        if (fileName.Contains(ck.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Cheat-Keyword Driver in System32: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Kernel driver with cheat keyword in name: '{ck}'",
                                Detail = $"Driver: {file}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckWindowsUpdateBypassLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var wuLogPaths = new[]
        {
            Path.Combine(ProgramData, @"Microsoft\Windows\WER\EventLog\Windows Update.evtx"),
            @"C:\Windows\WindowsUpdate.log",
            Path.Combine(ProgramData, @"USOShared\Logs\System")
        };

        foreach (var wuPath in wuLogPaths)
        {
            ctx.IncrementFiles();
            if (!File.Exists(wuPath) && !Directory.Exists(wuPath)) continue;

            if (File.Exists(wuPath) && wuPath.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    using var fs = new FileStream(wuPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    if (content.Contains("blocked driver", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("unsigned driver", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Driver Blocking Event in Windows Update Log",
                            Risk = RiskLevel.High,
                            Location = wuPath,
                            FileName = Path.GetFileName(wuPath),
                            Reason = "Windows Update log shows blocked/unsigned driver activity — may relate to BYOVD bypass driver",
                            Detail = $"Log: {wuPath}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckBypassToolDownloadHistory(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var downloadDirs = new List<string>();
        var userDirs = new List<string>();
        try { userDirs.AddRange(Directory.GetDirectories(@"C:\Users")); }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        foreach (var u in userDirs)
        {
            downloadDirs.Add(Path.Combine(u, "Downloads"));
            downloadDirs.Add(Path.Combine(u, "Desktop"));
            downloadDirs.Add(Path.Combine(u, "AppData", "Local", "Temp"));
        }

        downloadDirs.Add(@"C:\Users\Public\Downloads");

        foreach (var dir in downloadDirs.Distinct())
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file).ToLowerInvariant();

                    foreach (var tn in BypassToolNames)
                    {
                        if (fileName.Contains(tn.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Known Bypass Tool Downloaded: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Known bypass tool file found in download/temp location: '{tn}'",
                                Detail = $"Path: {file}"
                            });
                            break;
                        }
                    }

                    foreach (var si in SuspiciousInstallerNames)
                    {
                        if (fileName.Contains(si.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Suspicious Installer Downloaded",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Suspicious installer matching cheat/bypass pattern: '{si}'",
                                Detail = $"Path: {file}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckCryptoUsageForBypass(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var cryptoKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography\Defaults\Provider Types");
            ctx.IncrementRegistryKeys();
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        var certStorePaths = new[]
        {
            @"SOFTWARE\Microsoft\SystemCertificates\Root\Certificates",
            @"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates"
        };

        foreach (var storePath in certStorePaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(storePath);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                foreach (var thumbprint in key.GetSubKeyNames())
                {
                    try
                    {
                        using var certKey = key.OpenSubKey(thumbprint);
                        var blob = certKey?.GetValue("Blob");
                        ctx.IncrementRegistryKeys();
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var certFiles = new List<string>();
        var searchDirs = new[]
        {
            Path.GetTempPath(),
            @"C:\Windows\Temp",
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                certFiles.AddRange(Directory.GetFiles(dir, "*.cer", SearchOption.TopDirectoryOnly));
                certFiles.AddRange(Directory.GetFiles(dir, "*.crt", SearchOption.TopDirectoryOnly));
                certFiles.AddRange(Directory.GetFiles(dir, "*.p12", SearchOption.TopDirectoryOnly));
                certFiles.AddRange(Directory.GetFiles(dir, "*.pfx", SearchOption.TopDirectoryOnly));
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        foreach (var certFile in certFiles)
        {
            ctx.IncrementFiles();
            var fileName = Path.GetFileName(certFile).ToLowerInvariant();
            if (CheatKeywords.Any(ck => fileName.Contains(ck.ToLowerInvariant())) ||
                BypassToolNames.Any(tn => fileName.Contains(tn.ToLowerInvariant())))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Suspicious Certificate File Found",
                    Risk = RiskLevel.High,
                    Location = certFile,
                    FileName = Path.GetFileName(certFile),
                    Reason = "Certificate file with cheat/bypass-related name found — may be fake code signing cert for bypass tool",
                    Detail = $"Path: {certFile}"
                });
            }
        }
    }, ct);

    private Task CheckBcdStoreBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var bcdPath = @"C:\Boot\BCD";
        ctx.IncrementFiles();
        if (File.Exists(bcdPath))
        {
            try
            {
                var fi = new FileInfo(bcdPath);
                if (fi.Length < 32768)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "BCD Store Unusually Small",
                        Risk = RiskLevel.Medium,
                        Location = bcdPath,
                        FileName = "BCD",
                        Reason = $"Boot Configuration Data store is only {fi.Length} bytes — unusually small, may indicate tampering",
                        Detail = $"BCD path: {bcdPath}, Size: {fi.Length} bytes"
                    });
                }
            }
            catch (IOException) { }
        }

        try
        {
            using var bcdKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management");
            ctx.IncrementRegistryKeys();
            if (bcdKey != null)
            {
                var clearPageFile = bcdKey.GetValue("ClearPageFileAtShutdown");
                if (clearPageFile is int cpf && cpf == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Page File Cleared at Shutdown (Anti-Forensic)",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\ClearPageFileAtShutdown",
                        FileName = "Registry",
                        Reason = "Page file cleared at shutdown (ClearPageFileAtShutdown=1) — deliberately destroys memory forensic evidence including cheat process artifacts",
                        Detail = "Anti-forensic technique: page file wipe removes cheat strings from memory dumps"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        try
        {
            using var hibernateKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Power");
            ctx.IncrementRegistryKeys();
            if (hibernateKey != null)
            {
                var hibEnabled = hibernateKey.GetValue("HibernateEnabled");
                if (hibEnabled is int he && he == 0)
                {
                    var hibPath = @"C:\hiberfil.sys";
                    if (!File.Exists(hibPath))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Hibernate Disabled and Hibernate File Missing",
                            Risk = RiskLevel.Medium,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Power\HibernateEnabled",
                            FileName = "Registry",
                            Reason = "Hibernate disabled and hiberfil.sys absent — eliminates hibernation memory dump forensic evidence",
                            Detail = "Anti-forensic: no hiberfil.sys means no hibernation-based memory forensics"
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);
}
