using System.Runtime.Versioning;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class CleanerDeepWipeForensicScanModule : IScanModule
{
    public string Name => "Cleaner Deep Wipe Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] CheatCleanerToolNames =
    [
        "fivem_cleaner", "fivem_clean", "fivemcleaner", "fivem_wipe",
        "ragemp_cleaner", "ragemp_clean", "altv_cleaner", "altv_clean",
        "gta_cleaner", "gtav_cleaner", "gta5_cleaner",
        "cheat_cleaner", "hack_cleaner", "bypass_cleaner",
        "spoofer_cleaner", "inject_cleaner", "trace_cleaner",
        "forensic_cleaner", "ac_cleaner", "anticheat_cleaner",
        "evidence_cleaner", "artifact_cleaner", "log_cleaner",
        "history_cleaner", "trace_remover", "trace_wiper",
        "clean_traces", "remove_traces", "wipe_traces",
        "clean_artifacts", "remove_artifacts",
        "kiddion_cleaner", "eulen_cleaner", "2take1_cleaner",
        "stand_cleaner", "cherax_cleaner", "outbreak_cleaner",
        "impulse_cleaner", "bypass_wiper", "bypass_remover",
        "pre_scan_clean", "prescan_clean", "before_scan",
        "scan_cleaner", "scanner_clean", "zerotrace_bypass",
        "ocean_bypass", "detectac_bypass",
        "cleanmgr_custom", "diskclean_custom",
    ];

    private static readonly string[] CheatPathTargets =
    [
        "fivem", "fivem.app", "citizenfx", "cfx",
        "ragemp", "rage multiplayer", "rage mp",
        "altv", "alt:v", "altv-client",
        "gta5", "gtav", "grand theft auto",
        "kiddion", "eulen", "2take1", "stand", "cherax", "outbreak", "impulse",
        "redengine", "hammafia", "nightfall", "emperor",
        "cheat", "hack", "bypass", "inject", "modmenu", "trainer",
        "spoofer", "hwid", "battleye", "easyanticheat",
        "prefetch", "eventlog", "winevt",
    ];

    private static readonly string[] CleanerRegistryPaths =
    [
        @"SOFTWARE\Piriform\CCleaner",
        @"SOFTWARE\Piriform",
        @"SOFTWARE\BleachBit",
        @"SOFTWARE\PrivaZer",
        @"SOFTWARE\WiseCleaner",
        @"SOFTWARE\Wise Disk Cleaner",
        @"SOFTWARE\Glary Utilities",
        @"SOFTWARE\Advanced SystemCare",
        @"SOFTWARE\IObit",
        @"SOFTWARE\Eraser",
        @"SOFTWARE\Heidi Computers",
        @"SOFTWARE\FreeRaser",
        @"SOFTWARE\CyberShredder",
        @"SOFTWARE\MooSoft",
        @"SOFTWARE\HardWipe",
        @"SOFTWARE\Evidence Nuker",
        @"SOFTWARE\Comodo\System Cleaner",
        @"SOFTWARE\AusLogics\BoostSpeed",
        @"SOFTWARE\Iolo Technologies\System Mechanic",
    ];

    private static readonly string[] CleanerExeNames =
    [
        "ccleaner", "ccleaner64", "ccupdater",
        "bleachbit", "bleachbit_console",
        "privazer", "privazer_console",
        "wisecleaner", "wise_disk_cleaner", "wisediskcleaner",
        "eraser", "eraser64", "eraserclient",
        "glaryutilities", "glary",
        "advancedsystemcare", "asc",
        "iobituninstaller",
        "cleanmaster", "clean_master",
        "freeraser", "hardwipe", "cybershredder",
        "fileshredder", "moo0_anti_recovery",
        "evidencenuker", "evidence_nuker",
        "dpurifier", "disk_purifier",
        "mcleans", "mcafee_clean",
        "superfetch_clean",
    ];

    private static readonly string[] CleanerLogKeywords =
    [
        "deleted", "wiped", "erased", "removed", "cleaned",
        "shredded", "overwritten", "purged", "sanitized",
        "files deleted", "registry cleaned", "history cleared",
        "traces removed", "artifacts removed",
    ];

    private static readonly string[] StartupCleanerKeys =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
        @"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    ];

    private static readonly string[] CheatCleanerPowerShellPatterns =
    [
        "remove-item.*fivem", "del.*fivem", "rd.*fivem",
        "remove-item.*ragemp", "del.*ragemp", "rd.*ragemp",
        "remove-item.*altv", "del.*altv", "rd.*altv",
        "remove-item.*kiddion", "del.*kiddion",
        "remove-item.*eulen", "del.*eulen",
        "remove-item.*cheat", "del.*cheat",
        "remove-item.*bypass", "del.*bypass",
        "remove-item.*inject", "del.*inject",
        "clear-eventlog", "wevtutil cl",
        "remove-item.*prefetch", "del.*prefetch",
        "remove-item.*winevt", "del.*winevt",
        "fsutil usn deletejournal",
        "vssadmin delete shadows",
        "reg delete.*battleye",
        "reg delete.*easyanticheat",
        "cipher /w",
        "sdelete",
    ];

    private static readonly string[] ScheduledCleanerTaskKeywords =
    [
        "clean", "wipe", "erase", "purge", "shred", "remove",
        "delete logs", "clear history", "clean traces",
        "fivem", "ragemp", "altv", "cheat", "bypass",
        "before_scan", "pre_scan", "prescan",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckCCleanerArtifacts(ctx, ct),
            CheckBleachBitArtifacts(ctx, ct),
            CheckPrivaZerArtifacts(ctx, ct),
            CheckEraserArtifacts(ctx, ct),
            CheckCheatSpecificCleanerTools(ctx, ct),
            CheckCleanerRegistryArtifacts(ctx, ct),
            CheckCleanerPrefetchArtifacts(ctx, ct),
            CheckPowerShellCleanerHistory(ctx, ct),
            CheckBatchCleanerScripts(ctx, ct),
            CheckScheduledCleanerTasks(ctx, ct),
            CheckStartupCleanerEntries(ctx, ct),
            CheckCleanerLogFiles(ctx, ct),
            CheckCheatPathTargetingInConfigs(ctx, ct),
            CheckWindowsCleanMgrArtifacts(ctx, ct),
            CheckRecycleBinCleanArtifacts(ctx, ct),
            CheckWiseDiskCleanerArtifacts(ctx, ct),
            CheckAntiForensicChainCleanerArtifacts(ctx, ct),
            CheckGlaryUtilitiesArtifacts(ctx, ct)
        );
    }

    private Task CheckCCleanerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var ccleanerPaths = new[]
        {
            Path.Combine(appData, "CCleaner"),
            Path.Combine(localAppData, "CCleaner"),
            Path.Combine(programFiles, "CCleaner"),
            Path.Combine(programFilesX86, "CCleaner"),
        };

        foreach (var ccRoot in ccleanerPaths)
        {
            if (!Directory.Exists(ccRoot)) continue;
            try
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "CCleaner: Installation Directory Found",
                    Risk = RiskLevel.Medium, Location = ccRoot,
                    FileName = "CCleaner",
                    Reason = "CCleaner directory found — used to erase cheat evidence (browser history, temp files, registry)",
                    Detail = $"Path: {ccRoot}"
                });

                foreach (var file in Directory.EnumerateFiles(ccRoot, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext is not (".ini" or ".cfg" or ".log" or ".txt" or ".xml")) continue;

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        foreach (var kw in CheatPathTargets)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "CCleaner Config: Cheat Path in Cleanup List",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"CCleaner config/log contains cheat path '{kw}' — configured to erase cheat evidence",
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

        using var hkcu = Registry.CurrentUser;
        var ccRegPaths = new[]
        {
            @"SOFTWARE\Piriform\CCleaner",
            @"SOFTWARE\CCleaner",
        };
        foreach (var ccReg in ccRegPaths)
        {
            try
            {
                using var key = hkcu.OpenSubKey(ccReg);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();
                var lastRun = key.GetValue("LastRunTime")?.ToString() ?? "unknown";
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "CCleaner Registry: Run History",
                    Risk = RiskLevel.Medium,
                    Location = $@"HKCU\{ccReg}",
                    FileName = "CCleaner",
                    Reason = "CCleaner registry artifact with run history — evidence of CCleaner usage",
                    Detail = $"Last run: {lastRun}"
                });
            }
            catch { }
        }
    }, ct);

    private Task CheckBleachBitArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var bleachbitPaths = new[]
        {
            Path.Combine(appData, "BleachBit"),
            Path.Combine(localAppData, "BleachBit"),
        };

        foreach (var bbRoot in bleachbitPaths)
        {
            if (!Directory.Exists(bbRoot)) continue;
            try
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "BleachBit: Installation/Data Directory",
                    Risk = RiskLevel.High, Location = bbRoot,
                    FileName = "BleachBit",
                    Reason = "BleachBit directory found — aggressive file shredder, used to permanently destroy cheat evidence",
                    Detail = $"Path: {bbRoot}"
                });

                foreach (var file in Directory.EnumerateFiles(bbRoot, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext is not (".log" or ".txt" or ".xml" or ".json" or ".ini")) continue;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        foreach (var kw in CheatPathTargets)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "BleachBit Log: Cheat Path Erased",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"BleachBit log shows cheat path '{kw}' was erased",
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

    private Task CheckPrivaZerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var privazerPaths = new[]
        {
            Path.Combine(appData, "PrivaZer"),
            Path.Combine(localAppData, "PrivaZer"),
        };

        foreach (var pzRoot in privazerPaths)
        {
            if (!Directory.Exists(pzRoot)) continue;
            ctx.AddFinding(new Finding
            {
                Module = Name, Title = "PrivaZer: Privacy Cleaner Artifact",
                Risk = RiskLevel.High, Location = pzRoot,
                FileName = "PrivaZer",
                Reason = "PrivaZer directory found — deep privacy cleaner that permanently destroys forensic evidence",
                Detail = $"Path: {pzRoot}"
            });

            try
            {
                foreach (var file in Directory.EnumerateFiles(pzRoot, "*.log", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        bool hasCheatKw = CheatPathTargets.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hasCheatKw)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "PrivaZer Log: Cheat Evidence Erased",
                                Risk = RiskLevel.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "PrivaZer log references cheat-related paths — cheat evidence was permanently destroyed",
                                Detail = content.Length > 500 ? content[..500] : content
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckEraserArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var eraserPaths = new[]
        {
            Path.Combine(appData, "Eraser"),
            Path.Combine(appData, "Heidi Computers", "Eraser"),
        };

        foreach (var eraserRoot in eraserPaths)
        {
            if (!Directory.Exists(eraserRoot)) continue;
            ctx.AddFinding(new Finding
            {
                Module = Name, Title = "Eraser: File Shredder Artifact",
                Risk = RiskLevel.High, Location = eraserRoot,
                FileName = "Eraser",
                Reason = "Eraser file shredder directory found — used to permanently overwrite and destroy cheat artifacts",
                Detail = $"Path: {eraserRoot}"
            });

            try
            {
                foreach (var file in Directory.EnumerateFiles(eraserRoot, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var ext = Path.GetExtension(file).ToLowerInvariant();
                    if (ext is not (".xml" or ".log" or ".json" or ".txt")) continue;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        foreach (var kw in CheatPathTargets)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Eraser Task: Cheat Path Scheduled for Erasure",
                                    Risk = RiskLevel.Critical, Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Eraser task file references cheat path '{kw}' — cheat evidence scheduled for permanent destruction",
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

    private Task CheckCheatSpecificCleanerTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var searchPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            Path.GetTempPath(),
            @"C:\",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)),
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
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    var ext = Path.GetExtension(file).ToLowerInvariant();

                    foreach (var cleanerName in CheatCleanerToolNames)
                    {
                        if (name.Contains(cleanerName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Cheat Cleaner Tool: Dedicated Artifact Wiper",
                                Risk = RiskLevel.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Cheat-specific cleaner tool '{cleanerName}' found — designed to destroy cheat evidence before scans",
                                Detail = $"Path: {file}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
        return Task.CompletedTask;
    }, ct);

    private Task CheckCleanerRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hkcu = Registry.CurrentUser;
        using var hklm = Registry.LocalMachine;

        foreach (var regPath in CleanerRegistryPaths)
        {
            foreach (var hive in new[] { hkcu, hklm })
            {
                try
                {
                    using var key = hive.OpenSubKey(regPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                    var cleanerName = regPath.Split('\\').Last();
                    var valueNames = key.GetValueNames();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = $"Cleaner Registry: '{cleanerName}' Artifact",
                        Risk = RiskLevel.Medium,
                        Location = $@"HKCU\{regPath}",
                        FileName = cleanerName,
                        Reason = $"Registry artifact from cleaner tool '{cleanerName}' — evidence of systematic file cleanup",
                        Detail = $"Values: {string.Join(", ", valueNames.Take(8))}"
                    });
                }
                catch { }
            }
        }
    }, ct);

    private Task CheckCleanerPrefetchArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var prefetchPath = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchPath)) return Task.CompletedTask;

        try
        {
            foreach (var pf in Directory.EnumerateFiles(prefetchPath, "*.pf"))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var pfName = Path.GetFileNameWithoutExtension(pf).ToLowerInvariant();
                foreach (var cleanerExe in CleanerExeNames)
                {
                    if (pfName.Contains(cleanerExe, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Prefetch: Cleaner Tool Execution History",
                            Risk = RiskLevel.High, Location = pf,
                            FileName = Path.GetFileName(pf),
                            Reason = $"Cleaner tool '{cleanerExe}' prefetch entry — confirms cleaner was run on this system",
                            Detail = $"Prefetch: {pf}"
                        });
                        break;
                    }
                }

                foreach (var cleanerName in CheatCleanerToolNames)
                {
                    var sanitized = cleanerName.Replace("_", "").Replace(" ", "").Replace("-", "");
                    if (pfName.Contains(sanitized, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Prefetch: Cheat Cleaner Tool Execution",
                            Risk = RiskLevel.Critical, Location = pf,
                            FileName = Path.GetFileName(pf),
                            Reason = $"Cheat-specific cleaner '{cleanerName}' prefetch — cheat evidence destruction tool was run",
                            Detail = $"Prefetch: {pf}"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
        return Task.CompletedTask;
    }, ct);

    private Task CheckPowerShellCleanerHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var psHistoryPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"),
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
                var lines = content.Split('\n');

                foreach (var pattern in CheatCleanerPowerShellPatterns)
                {
                    bool found = lines.Any(l => l.Contains(pattern.Replace(".*", ""), StringComparison.OrdinalIgnoreCase));
                    if (found)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "PS History: Cheat Evidence Cleanup Command",
                            Risk = RiskLevel.Critical, Location = psPath,
                            FileName = Path.GetFileName(psPath),
                            Reason = $"Cheat evidence cleanup pattern '{pattern}' found in PowerShell history",
                            Detail = content.Length > 600 ? content[..600] : content
                        });
                        break;
                    }
                }

                int cleanupCommandCount = CheatCleanerPowerShellPatterns
                    .Count(p => content.Contains(p.Replace(".*", ""), StringComparison.OrdinalIgnoreCase));
                if (cleanupCommandCount >= 3)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name, Title = "PS History: Systematic Cheat Evidence Destruction",
                        Risk = RiskLevel.Critical, Location = psPath,
                        FileName = Path.GetFileName(psPath),
                        Reason = $"{cleanupCommandCount} different cheat cleanup commands in PS history — systematic evidence destruction",
                        Detail = content.Length > 600 ? content[..600] : content
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckBatchCleanerScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        };

        foreach (var root in searchPaths)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                var scriptFiles = Directory.EnumerateFiles(root, "*.bat", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.EnumerateFiles(root, "*.cmd", SearchOption.TopDirectoryOnly))
                    .Concat(Directory.EnumerateFiles(root, "*.vbs", SearchOption.TopDirectoryOnly));

                foreach (var file in scriptFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();

                    bool hasCleanerName = CheatCleanerToolNames.Any(c => name.Contains(c.Replace("_", ""), StringComparison.OrdinalIgnoreCase));
                    if (hasCleanerName)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name, Title = "Batch Script: Cheat Cleaner Script Name",
                            Risk = RiskLevel.Critical, Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "Batch/VBS script with cheat cleaner name — designed to erase cheat artifacts",
                            Detail = $"Path: {file}"
                        });
                    }

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);

                        bool hasCheatPath = CheatPathTargets.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        var deletionPatterns = new[] { "del ", "rd ", "rmdir", "erase ", "format " };
                        bool hasDeletion = deletionPatterns.Any(p => content.Contains(p, StringComparison.OrdinalIgnoreCase));

                        if (hasCheatPath && hasDeletion)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Batch Script: Cheat Path Deletion Script",
                                Risk = RiskLevel.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "Batch script deletes cheat-related paths — designed to destroy cheat evidence",
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

    private Task CheckScheduledCleanerTasks(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var taskPaths = new[]
        {
            @"C:\Windows\System32\Tasks",
            @"C:\Windows\SysWOW64\Tasks",
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
                    var taskName = Path.GetFileName(file).ToLowerInvariant();
                    bool hasCleanerName = CheatCleanerToolNames.Any(c => taskName.Contains(c.Replace("_", ""), StringComparison.OrdinalIgnoreCase));

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);

                        bool hasCleanerKw = ScheduledCleanerTaskKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        bool hasCheatPath = CheatPathTargets.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (hasCleanerName || (hasCleanerKw && hasCheatPath))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Scheduled Task: Cheat Cleaner Auto-Run",
                                Risk = RiskLevel.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "Scheduled task configured to automatically clean cheat evidence",
                                Detail = content.Length > 500 ? content[..500] : content
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckStartupCleanerEntries(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        using var hkcu = Registry.CurrentUser;
        using var hklm = Registry.LocalMachine;

        foreach (var hive in new[] { hkcu, hklm })
        {
            foreach (var startupPath in StartupCleanerKeys)
            {
                try
                {
                    using var key = hive.OpenSubKey(startupPath);
                    if (key == null) continue;
                    ctx.IncrementRegistryKeys();
                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        var val = key.GetValue(valueName)?.ToString()?.ToLowerInvariant() ?? string.Empty;
                        foreach (var cleanerExe in CleanerExeNames)
                        {
                            if (val.Contains(cleanerExe, StringComparison.OrdinalIgnoreCase) ||
                                valueName.Contains(cleanerExe, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Startup: Cleaner Tool Auto-Start",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKCU\{startupPath}\{valueName}",
                                    FileName = valueName,
                                    Reason = $"Cleaner tool '{cleanerExe}' in startup — runs on every boot to destroy evidence",
                                    Detail = $"Value: {val}"
                                });
                                break;
                            }
                        }

                        foreach (var cleanerName in CheatCleanerToolNames)
                        {
                            if (val.Contains(cleanerName.Replace("_", ""), StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name, Title = "Startup: Cheat Cleaner Auto-Start",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKCU\{startupPath}\{valueName}",
                                    FileName = valueName,
                                    Reason = $"Cheat-specific cleaner '{cleanerName}' in startup — persistent cheat evidence erasure",
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

    private Task CheckCleanerLogFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logSearchPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CCleaner"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "BleachBit"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "PrivaZer"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Eraser"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Wise Disk Cleaner"),
            Path.GetTempPath(),
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

                        bool hasCleanKw = CleanerLogKeywords.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        bool hasCheatPath = CheatPathTargets.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (hasCleanKw && hasCheatPath)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Cleaner Log: Cheat Evidence Destruction Logged",
                                Risk = RiskLevel.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "Cleaner log shows cheat-related files were deleted/erased",
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

    private Task CheckCheatPathTargetingInConfigs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var configSearchPaths = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        foreach (var root in configSearchPaths)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.ini", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(root, "*.cfg", SearchOption.AllDirectories)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var dirName = Path.GetDirectoryName(file)?.ToLowerInvariant() ?? string.Empty;
                    bool isCleanerDir = CleanerExeNames.Any(c => dirName.Contains(c, StringComparison.OrdinalIgnoreCase));
                    if (!isCleanerDir) continue;

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        int cheatKwCount = CheatPathTargets.Count(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (cheatKwCount >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Cleaner Config: Cheat Paths Explicitly Targeted",
                                Risk = RiskLevel.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Cleaner config explicitly targets {cheatKwCount} cheat-related paths",
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

    private Task CheckWindowsCleanMgrArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var cleanMgrPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches";
        using var hklm = Registry.LocalMachine;
        try
        {
            using var key = hklm.OpenSubKey(cleanMgrPath);
            if (key == null) return;
            ctx.IncrementRegistryKeys();
            foreach (var cacheName in key.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var cacheKey = key.OpenSubKey(cacheName);
                    if (cacheKey == null) continue;
                    var stateFlags = cacheKey.GetValue("StateFlags0064")?.ToString();
                    if (stateFlags == "2")
                    {
                        if (cacheName.Contains("Temporary", StringComparison.OrdinalIgnoreCase) ||
                            cacheName.Contains("Recycle", StringComparison.OrdinalIgnoreCase) ||
                            cacheName.Contains("Log", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Windows CleanMgr: Scheduled Cleanup Configured",
                                Risk = RiskLevel.Medium,
                                Location = $@"HKLM\{cleanMgrPath}\{cacheName}",
                                FileName = cacheName,
                                Reason = $"Windows Disk Cleanup scheduled to clear '{cacheName}' — may remove cheat logs/temps",
                                Detail = $"StateFlags: {stateFlags}"
                            });
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }, ct);

    private Task CheckRecycleBinCleanArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
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
                            var buf = new byte[Math.Min(1024, fs.Length)];
                            await fs.ReadAsync(buf, ct);
                            var content = System.Text.Encoding.Unicode.GetString(buf);
                            foreach (var cleanerExe in CleanerExeNames)
                            {
                                if (content.Contains(cleanerExe, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name, Title = "Recycle Bin: Cleaner Tool Deleted",
                                        Risk = RiskLevel.High, Location = iFile,
                                        FileName = Path.GetFileName(iFile),
                                        Reason = $"Cleaner tool '{cleanerExe}' was deleted to Recycle Bin — attempted to hide cleaner usage",
                                        Detail = content.Length > 200 ? content[..200] : content
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

    private Task CheckWiseDiskCleanerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var wisePaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Wise Disk Cleaner"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Wise Disk Cleaner"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Wise Disk Cleaner"),
        };

        foreach (var wiseRoot in wisePaths)
        {
            if (!Directory.Exists(wiseRoot)) continue;
            ctx.AddFinding(new Finding
            {
                Module = Name, Title = "Wise Disk Cleaner: Installation/Data Directory",
                Risk = RiskLevel.High, Location = wiseRoot,
                FileName = "Wise Disk Cleaner",
                Reason = "Wise Disk Cleaner found — configurable file deletion tool used to erase cheat artifacts",
                Detail = $"Path: {wiseRoot}"
            });

            try
            {
                foreach (var file in Directory.EnumerateFiles(wiseRoot, "*.xml", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        if (CheatPathTargets.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Wise Disk Cleaner Config: Cheat Path Target",
                                Risk = RiskLevel.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "Wise Disk Cleaner config includes cheat paths — configured to erase cheat evidence",
                                Detail = content.Length > 500 ? content[..500] : content
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);

    private Task CheckAntiForensicChainCleanerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
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

            int cleanerToolCount = CleanerExeNames.Count(c => content.Contains(c, StringComparison.OrdinalIgnoreCase));
            if (cleanerToolCount >= 2)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "PS History: Multi-Cleaner Chain Detected",
                    Risk = RiskLevel.Critical, Location = psHistoryPath,
                    FileName = Path.GetFileName(psHistoryPath),
                    Reason = $"{cleanerToolCount} different cleaner tools referenced in PS history — chained cleaning operation to defeat forensic recovery",
                    Detail = content.Length > 600 ? content[..600] : content
                });
            }

            bool hasCheatClean = CheatCleanerToolNames.Any(c => content.Contains(c.Replace("_", ""), StringComparison.OrdinalIgnoreCase));
            bool hasGeneralCleaner = CleanerExeNames.Any(c => content.Contains(c, StringComparison.OrdinalIgnoreCase));
            if (hasCheatClean && hasGeneralCleaner)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name, Title = "PS History: Cheat Cleaner + General Cleaner Chain",
                    Risk = RiskLevel.Critical, Location = psHistoryPath,
                    FileName = Path.GetFileName(psHistoryPath),
                    Reason = "Both cheat-specific cleaner and general cleaner used — maximum evidence destruction chain",
                    Detail = content.Length > 600 ? content[..600] : content
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckGlaryUtilitiesArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var glaryPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Glary Utilities"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Glary Utilities"),
        };

        foreach (var glaryRoot in glaryPaths)
        {
            if (!Directory.Exists(glaryRoot)) continue;
            ctx.AddFinding(new Finding
            {
                Module = Name, Title = "Glary Utilities: System Cleaner Artifact",
                Risk = RiskLevel.Medium, Location = glaryRoot,
                FileName = "Glary Utilities",
                Reason = "Glary Utilities found — comprehensive system cleaner that can erase cheat artifacts",
                Detail = $"Path: {glaryRoot}"
            });

            try
            {
                foreach (var file in Directory.EnumerateFiles(glaryRoot, "*.log", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        var content = await sr.ReadToEndAsync(ct);
                        if (CheatPathTargets.Any(k => content.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name, Title = "Glary Utilities Log: Cheat Path Cleaned",
                                Risk = RiskLevel.Critical, Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "Glary Utilities log shows cheat-related path was cleaned",
                                Detail = content.Length > 500 ? content[..500] : content
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { }
        }
    }, ct);
}
