using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class WindowsEventDeepForensicScanModule : IScanModule
{
    public string Name => "Windows Event Log Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] CheatProcessNames = new[]
    {
        "cheat", "hack", "inject", "bypass", "spoof", "loader", "trainer", "menu", "esp",
        "aimbot", "triggerbot", "bhop", "kiddion", "stand", "eulen", "disturbed",
        "cherax", "2take1", "midnight", "lynx", "rage", "neverlose", "onetap", "gamesense",
        "skycheats", "aimware", "interwebz", "supremacy", "fatality", "hvhest",
        "cobramod", "excalibur", "frostbyte", "redengine", "osiris", "nier",
        "guided hacking", "unknowncheats", "mpgh", "milleniumrat", "mw2lobby",
        "menyoo", "openiv", "sparkiv", "scripthookvdotnet", "asi loader",
        "stracciatella", "dsound", "dinput8", "winmm",
        "processhacker", "cheatengine", "ce", "artmoney",
        "extremeinjector", "winject", "gjinjector", "remoteinjection",
        "manualmap", "reflective", "shellcode", "runpe",
        "uabea", "dnspy", "dotpeek", "ilspy", "jusdecompile",
        "ohoh", "xenos", "dllinjector",
    };

    private static readonly string[] CheatServiceNames = new[]
    {
        "cheat", "hack", "inject", "bypass", "spoof", "hwid", "unban", "eac", "be",
        "battleye", "anticheat", "loader", "kernel", "drv", "driver",
        "kms", "kmservice", "tbhook", "monitor", "ring0",
        "aimhook", "gamesense", "dbk32", "dbk64",
        "kdmapper", "winrings", "msio32", "msio64", "gdrv",
        "cpuz141", "elbycdio", "rtcore64", "ntiolib",
        "aswrvrt", "procexp", "gmer",
    };

    private static readonly string[] DriverLoadCheatNames = new[]
    {
        "kdmapper", "gdrv", "cpuz141", "elbycdio", "rtcore64", "ntiolib", "msio",
        "dbk32", "dbk64", "winring", "rwdrv", "iobit", "asio",
        "virtu", "glitch", "bypusvr", "nal", "inpoutx64",
        "npcap", "winpcap", "wintun", "tap0901",
        "cheat", "hack", "spoof", "inject", "bypass", "hook",
    };

    private static readonly string[] LogClearEventIds = new[]
    {
        "1102", "104", "4647", "4634",
    };

    private static readonly string[] SuspiciousCommandLineKeywords = new[]
    {
        "inject", "bypass", "cheat", "hack", "spoof", "hwid", "unban",
        "dump", "mimikatz", "procdump", "lsass", "sekurlsa",
        "disable defender", "set-mppreference", "wdfilter", "malwarebytes",
        "-nop -w hidden -enc", "downloadstring", "invoke-expression",
        "reflectiveinjection", "shellcode", "runpe", "hollow",
        "patchguard", "dse", "ci.dll", "ntoskrnl",
        "-exec bypass", "-executionpolicy bypass", "-encoded",
        "net user add", "net localgroup administrators",
    };

    private static readonly string[] EvtxPaths = new[]
    {
        @"C:\Windows\System32\winevt\Logs\System.evtx",
        @"C:\Windows\System32\winevt\Logs\Security.evtx",
        @"C:\Windows\System32\winevt\Logs\Application.evtx",
        @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
        @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx",
        @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-CodeIntegrity%4Operational.evtx",
        @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx",
        @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx",
        @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-WinRM%4Operational.evtx",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckEvtxFileSizeAnomaly(ctx, ct),
            CheckEventLogClearedArtifacts(ctx, ct),
            CheckWerCheatProcessCrashes(ctx, ct),
            CheckReliabilityHistoryCheat(ctx, ct),
            CheckPrefetchForCheatEvents(ctx, ct),
            CheckSystemEventArtifacts(ctx, ct),
            CheckSecurityEventArtifacts(ctx, ct),
            CheckPowerShellEventArtifacts(ctx, ct),
            CheckCodeIntegrityEventArtifacts(ctx, ct),
            CheckTaskSchedulerEventArtifacts(ctx, ct),
            CheckDriverLoadEventArtifacts(ctx, ct),
            CheckServiceInstallEventArtifacts(ctx, ct),
            CheckApplicationEventArtifacts(ctx, ct),
            CheckWMIEventArtifacts(ctx, ct),
            CheckEventLogRegistryManipulation(ctx, ct),
            CheckOldEvtxArchives(ctx, ct),
            CheckSysmonEventArtifacts(ctx, ct),
            CheckWindowsErrorReportingRegistry(ctx, ct)
        );
    }

    private Task CheckEvtxFileSizeAnomaly(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (string evtxPath in EvtxPaths)
        {
            if (!File.Exists(evtxPath)) continue;
            ctx.IncrementFiles();
            try
            {
                var info = new FileInfo(evtxPath);
                if (info.Length < 70000)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Event Log File Suspiciously Small",
                        Risk = RiskLevel.High,
                        Location = evtxPath,
                        FileName = Path.GetFileName(evtxPath),
                        Reason = $"Event log file size is only {info.Length} bytes — may indicate log clearing",
                        Detail = "Abnormally small event log files suggest the log was recently cleared or truncated to hide cheat activity"
                    });
                }
                else if (info.LastWriteTime > info.CreationTime.AddDays(30) &&
                         info.Length < 200000)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Event Log File Suspicious Size After Long Run",
                        Risk = RiskLevel.Medium,
                        Location = evtxPath,
                        FileName = Path.GetFileName(evtxPath),
                        Reason = $"Event log file is small ({info.Length} bytes) despite being {(int)(DateTime.Now - info.CreationTime).TotalDays} days old",
                        Detail = "Log file may have been cleared or tampered with to conceal forensic evidence"
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckEventLogClearedArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string securityEvtx = @"C:\Windows\System32\winevt\Logs\Security.evtx";
        string systemEvtx = @"C:\Windows\System32\winevt\Logs\System.evtx";

        foreach (string evtxPath in new[] { securityEvtx, systemEvtx })
        {
            if (!File.Exists(evtxPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(evtxPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 1 * 1024 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);

                if (content.Contains("1102", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("Log clear", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("audit log was cleared", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Security Audit Log Cleared (Event 1102)",
                        Risk = RiskLevel.Critical,
                        Location = evtxPath,
                        FileName = Path.GetFileName(evtxPath),
                        Reason = "Security event log contains Event ID 1102 — audit log cleared",
                        Detail = "Event 1102 (audit log cleared) is a primary anti-forensic indicator used by cheat operators"
                    });
                }

                if (content.Contains("EventID>104<", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains(">104</", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("System log was cleared", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "System Log Cleared (Event 104)",
                        Risk = RiskLevel.Critical,
                        Location = evtxPath,
                        FileName = Path.GetFileName(evtxPath),
                        Reason = "System event log contains Event ID 104 — system log cleared",
                        Detail = "Event 104 (system log cleared) indicates intentional log tampering to hide cheat-related driver or service installations"
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckWerCheatProcessCrashes(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] werPaths = new[]
        {
            Path.Combine(userProfile, @"AppData\Local\CrashDumps"),
            @"C:\ProgramData\Microsoft\Windows\WER\ReportArchive",
            @"C:\ProgramData\Microsoft\Windows\WER\ReportQueue",
            Path.Combine(userProfile, @"AppData\Local\Microsoft\Windows\WER\ReportArchive"),
        };

        foreach (string werPath in werPaths)
        {
            if (!Directory.Exists(werPath)) continue;
            foreach (string werFolder in Directory.GetDirectories(werPath, "*", SearchOption.TopDirectoryOnly))
            {
                if (ct.IsCancellationRequested) return;
                string folderName = Path.GetFileName(werFolder).ToLowerInvariant();
                foreach (string cheatName in CheatProcessNames)
                {
                    if (folderName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "WER Crash Report — Cheat Process Crash",
                            Risk = RiskLevel.Critical,
                            Location = werFolder,
                            FileName = folderName,
                            Reason = $"Windows Error Reporting contains crash report for cheat-related process: '{cheatName}'",
                            Detail = "WER crash reports reveal that a cheat process was running and crashed — strong forensic indicator"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckReliabilityHistoryCheat(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string[] reliabilityPaths = new[]
        {
            @"C:\ProgramData\Microsoft\RAC\PublishedData\RacWmiDatabase.sdf",
            @"C:\Windows\System32\sru\SRUDB.dat",
        };

        foreach (string reliPath in reliabilityPaths)
        {
            if (!File.Exists(reliPath)) continue;
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(reliPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                byte[] buf = new byte[Math.Min(fs.Length, 2 * 1024 * 1024)];
                int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
                string content = Encoding.UTF8.GetString(buf, 0, read);
                string contentLower = content.ToLowerInvariant();

                foreach (string cheatName in CheatProcessNames)
                {
                    if (contentLower.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Reliability History — Cheat Process Entry",
                            Risk = RiskLevel.High,
                            Location = reliPath,
                            FileName = Path.GetFileName(reliPath),
                            Reason = $"Reliability or SRUM database contains cheat process name: '{cheatName}'",
                            Detail = "Windows Reliability/SRUM databases track all running processes and reveal cheat tool execution history"
                        });
                        break;
                    }
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckPrefetchForCheatEvents(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string prefetchPath = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchPath)) return;

        foreach (string pfFile in Directory.GetFiles(prefetchPath, "*.pf", SearchOption.TopDirectoryOnly))
        {
            if (ct.IsCancellationRequested) return;
            string fileName = Path.GetFileName(pfFile).ToLowerInvariant();
            foreach (string cheatName in CheatProcessNames)
            {
                if (fileName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Prefetch — Cheat Process Execution",
                        Risk = RiskLevel.Critical,
                        Location = pfFile,
                        FileName = Path.GetFileName(pfFile),
                        Reason = $"Windows Prefetch contains execution record for cheat process: '{cheatName}'",
                        Detail = "Prefetch files prove that a specific executable was run — strong forensic evidence of cheat tool execution"
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckSystemEventArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string systemEvtx = @"C:\Windows\System32\winevt\Logs\System.evtx";
        if (!File.Exists(systemEvtx)) return;
        ctx.IncrementFiles();
        try
        {
            using var fs = new FileStream(systemEvtx, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
            int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
            string content = Encoding.UTF8.GetString(buf, 0, read);

            foreach (string svcName in CheatServiceNames)
            {
                if (content.Contains(svcName, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "System Event Log — Suspicious Service",
                        Risk = RiskLevel.High,
                        Location = systemEvtx,
                        FileName = "System.evtx",
                        Reason = $"System event log contains suspicious service name: '{svcName}'",
                        Detail = "System events may record cheat-related service installation (Event 7045) or state changes"
                    });
                }
            }

            foreach (string drvName in DriverLoadCheatNames)
            {
                if (content.Contains(drvName, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "System Event Log — Suspicious Driver Loaded",
                        Risk = RiskLevel.Critical,
                        Location = systemEvtx,
                        FileName = "System.evtx",
                        Reason = $"System event log references known BYOVD/cheat driver: '{drvName}'",
                        Detail = "Driver load events in System log reveal kernel-level cheat or bypass driver activity"
                    });
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckSecurityEventArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string securityEvtx = @"C:\Windows\System32\winevt\Logs\Security.evtx";
        if (!File.Exists(securityEvtx)) return;
        ctx.IncrementFiles();
        try
        {
            using var fs = new FileStream(securityEvtx, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
            int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
            string content = Encoding.UTF8.GetString(buf, 0, read);

            foreach (string cheatProc in CheatProcessNames)
            {
                if (content.Contains(cheatProc, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Security Event Log — Cheat Process Creation",
                        Risk = RiskLevel.Critical,
                        Location = securityEvtx,
                        FileName = "Security.evtx",
                        Reason = $"Security event log contains cheat process name (Event 4688): '{cheatProc}'",
                        Detail = "Event 4688 (process creation) records show cheat tool was executed — critical forensic evidence"
                    });
                }
            }

            foreach (string cmdKw in SuspiciousCommandLineKeywords)
            {
                if (content.Contains(cmdKw, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Security Event Log — Suspicious Command Line",
                        Risk = RiskLevel.High,
                        Location = securityEvtx,
                        FileName = "Security.evtx",
                        Reason = $"Security event log contains suspicious command line keyword: '{cmdKw}'",
                        Detail = "Process creation events (4688) with suspicious command lines indicate cheat loader or anti-forensic activity"
                    });
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckPowerShellEventArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string psEvtx = @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx";
        if (!File.Exists(psEvtx)) return;
        ctx.IncrementFiles();
        try
        {
            using var fs = new FileStream(psEvtx, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
            int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
            string content = Encoding.UTF8.GetString(buf, 0, read);

            string[] psCheatKeywords = new[]
            {
                "Set-MpPreference", "DisableRealtimeMonitoring", "Invoke-Expression",
                "DownloadString", "DownloadFile", "WebClient",
                "-EncodedCommand", "-Encoded", "-ExecutionPolicy Bypass",
                "bypass", "inject", "cheat", "spoof", "hwid",
                "Remove-Item -Recurse", "Clear-EventLog", "wevtutil",
                "sc.exe stop", "sc.exe delete", "net stop",
                "reg add.*DisableAntiSpyware", "DisableAVProtection",
            };

            foreach (string psKw in psCheatKeywords)
            {
                if (content.Contains(psKw, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PowerShell Event Log — Cheat/Evasion Command",
                        Risk = RiskLevel.Critical,
                        Location = psEvtx,
                        FileName = "Microsoft-Windows-PowerShell_Operational.evtx",
                        Reason = $"PowerShell operational log contains suspicious keyword: '{psKw}'",
                        Detail = "PowerShell Event 4104 (script block logging) reveals cheat loader or anti-forensic commands that were executed"
                    });
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckCodeIntegrityEventArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string ciEvtx = @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-CodeIntegrity%4Operational.evtx";
        if (!File.Exists(ciEvtx)) return;
        ctx.IncrementFiles();
        try
        {
            using var fs = new FileStream(ciEvtx, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buf = new byte[Math.Min(fs.Length, 2 * 1024 * 1024)];
            int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
            string content = Encoding.UTF8.GetString(buf, 0, read);

            foreach (string drvName in DriverLoadCheatNames)
            {
                if (content.Contains(drvName, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Code Integrity Log — Unsigned Cheat Driver",
                        Risk = RiskLevel.Critical,
                        Location = ciEvtx,
                        FileName = "Microsoft-Windows-CodeIntegrity_Operational.evtx",
                        Reason = $"Code Integrity events reference suspicious driver: '{drvName}'",
                        Detail = "Code Integrity events (3001, 3002, 3004) record unsigned or vulnerable driver loads used in BYOVD attacks"
                    });
                }
            }

            if (content.Contains("3001", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("3004", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Code Integrity — Driver Signature Bypass Events",
                    Risk = RiskLevel.High,
                    Location = ciEvtx,
                    FileName = "Microsoft-Windows-CodeIntegrity_Operational.evtx",
                    Reason = "Code Integrity log shows driver signature verification failures (Event 3001/3004)",
                    Detail = "Repeated driver signature failures indicate BYOVD exploitation for kernel-level cheat injection"
                });
            }
        }
        catch { }
    }, ct);

    private Task CheckTaskSchedulerEventArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string tsEvtx = @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx";
        if (!File.Exists(tsEvtx)) return;
        ctx.IncrementFiles();
        try
        {
            using var fs = new FileStream(tsEvtx, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buf = new byte[Math.Min(fs.Length, 2 * 1024 * 1024)];
            int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
            string content = Encoding.UTF8.GetString(buf, 0, read);

            foreach (string cheatName in CheatProcessNames)
            {
                if (content.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Task Scheduler Events — Cheat Task Execution",
                        Risk = RiskLevel.High,
                        Location = tsEvtx,
                        FileName = "Microsoft-Windows-TaskScheduler_Operational.evtx",
                        Reason = $"Task Scheduler events reference cheat process: '{cheatName}'",
                        Detail = "Task Scheduler operational log reveals scheduled cheat loader or cleaner tasks that were executed"
                    });
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckDriverLoadEventArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string systemPath = @"C:\Windows\System32";
        string[] vulnerableDriverNames = new[]
        {
            "gdrv.sys", "cpuz141.sys", "elbycdio.sys", "rtcore64.sys", "ntiolib_x64.sys",
            "msio64.sys", "msio32.sys", "winring0x64.sys", "winring0.sys", "rwdrv.sys",
            "dbk32.sys", "dbk64.sys", "nal.sys", "inpoutx64.sys", "speedfan.sys",
            "aswrvrt.sys", "procexp152.sys", "procexp.sys", "winio.sys",
            "glbhook.sys", "cpuz.sys", "afd.sys",
        };

        foreach (string drvName in vulnerableDriverNames)
        {
            string drvPath = Path.Combine(systemPath, "drivers", drvName);
            if (File.Exists(drvPath))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Vulnerable/BYOVD Driver Present",
                    Risk = RiskLevel.Critical,
                    Location = drvPath,
                    FileName = drvName,
                    Reason = $"Known vulnerable driver found on disk: '{drvName}'",
                    Detail = "BYOVD (Bring Your Own Vulnerable Driver) technique uses known-vulnerable drivers to disable kernel protection"
                });
            }
        }
    }, ct);

    private Task CheckServiceInstallEventArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string systemEvtx = @"C:\Windows\System32\winevt\Logs\System.evtx";
        if (!File.Exists(systemEvtx)) return;
        ctx.IncrementFiles();
        try
        {
            using var fs = new FileStream(systemEvtx, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
            int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
            string content = Encoding.UTF8.GetString(buf, 0, read);

            if (content.Contains("7045", StringComparison.OrdinalIgnoreCase))
            {
                foreach (string svcName in CheatServiceNames)
                {
                    if (content.Contains(svcName, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Event 7045 — Cheat Service Installation",
                            Risk = RiskLevel.Critical,
                            Location = systemEvtx,
                            FileName = "System.evtx",
                            Reason = $"Service install event (7045) found for cheat-related service: '{svcName}'",
                            Detail = "Event 7045 records new service installations — cheat kernel drivers are commonly installed as services"
                        });
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckApplicationEventArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string appEvtx = @"C:\Windows\System32\winevt\Logs\Application.evtx";
        if (!File.Exists(appEvtx)) return;
        ctx.IncrementFiles();
        try
        {
            using var fs = new FileStream(appEvtx, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
            int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
            string content = Encoding.UTF8.GetString(buf, 0, read);

            foreach (string cheatName in CheatProcessNames)
            {
                if (content.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Application Event Log — Cheat Process Error/Crash",
                        Risk = RiskLevel.High,
                        Location = appEvtx,
                        FileName = "Application.evtx",
                        Reason = $"Application event log contains cheat process reference: '{cheatName}'",
                        Detail = "Application events may contain error, crash, or installation records for cheat tools"
                    });
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckWMIEventArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string wmiEvtx = @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx";
        if (!File.Exists(wmiEvtx)) return;
        ctx.IncrementFiles();
        try
        {
            using var fs = new FileStream(wmiEvtx, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buf = new byte[Math.Min(fs.Length, 2 * 1024 * 1024)];
            int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
            string content = Encoding.UTF8.GetString(buf, 0, read);

            string[] wmiCheatKeywords = new[]
            {
                "Win32_Process", "Create", "inject", "bypass", "cheat", "hack", "spoof",
                "powershell", "cmd.exe", "wscript", "cscript", "mshta",
            };

            foreach (string wmiKw in wmiCheatKeywords)
            {
                if (content.Contains(wmiKw, StringComparison.OrdinalIgnoreCase) &&
                    content.Contains("cheat", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "WMI Event Log — Cheat Process via WMI",
                        Risk = RiskLevel.High,
                        Location = wmiEvtx,
                        FileName = "Microsoft-Windows-WMI-Activity_Operational.evtx",
                        Reason = $"WMI activity log references process creation with cheat keyword: '{wmiKw}'",
                        Detail = "WMI process creation (Win32_Process.Create) is used to spawn cheat loaders with reduced visibility"
                    });
                    break;
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckEventLogRegistryManipulation(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string[] eventLogRegistryPaths = new[]
        {
            @"SYSTEM\CurrentControlSet\Services\EventLog\Application",
            @"SYSTEM\CurrentControlSet\Services\EventLog\System",
            @"SYSTEM\CurrentControlSet\Services\EventLog\Security",
        };

        foreach (string regPath in eventLogRegistryPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();

                object? maxSize = key.GetValue("MaxSize");
                if (maxSize is int maxSizeInt && maxSizeInt < 1048576)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Event Log Max Size Reduced",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{regPath}\MaxSize",
                        FileName = "MaxSize",
                        Reason = $"Event log MaxSize reduced to {maxSizeInt} bytes — may hide cheat activity by overwriting old events",
                        Detail = "Reducing event log size causes older events to be overwritten faster, destroying forensic evidence"
                    });
                }

                object? retentionDays = key.GetValue("Retention");
                if (retentionDays is int retInt && retInt == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Event Log Retention Disabled",
                        Risk = RiskLevel.Medium,
                        Location = $@"HKLM\{regPath}\Retention",
                        FileName = "Retention",
                        Reason = "Event log retention set to 0 — overwrite enabled, reducing forensic retention",
                        Detail = "Setting Retention=0 means events are overwritten as needed, allowing cheat activity to be lost"
                    });
                }
            }
            catch { }
        }
    }, ct);

    private Task CheckOldEvtxArchives(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string archivePath = @"C:\Windows\System32\winevt\Logs";
        if (!Directory.Exists(archivePath)) return;

        foreach (string archivedEvtx in Directory.GetFiles(archivePath, "Archive-*.evtx", SearchOption.TopDirectoryOnly))
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            string fileName = Path.GetFileName(archivedEvtx);
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Archived Event Log File Found",
                Risk = RiskLevel.Low,
                Location = archivedEvtx,
                FileName = fileName,
                Reason = $"Archived event log file found: '{fileName}' — may contain evidence of past cheat activity",
                Detail = "Archived event logs are created when logs are manually cleared — the archive preserves events before the clear"
            });
        }
    }, ct);

    private Task CheckSysmonEventArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string sysmonEvtx = @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx";
        if (!File.Exists(sysmonEvtx)) return;
        ctx.IncrementFiles();
        try
        {
            using var fs = new FileStream(sysmonEvtx, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buf = new byte[Math.Min(fs.Length, 4 * 1024 * 1024)];
            int read = await fs.ReadAsync(buf, 0, buf.Length, ct);
            string content = Encoding.UTF8.GetString(buf, 0, read);

            foreach (string cheatName in CheatProcessNames)
            {
                if (content.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Sysmon Event Log — Cheat Process Activity",
                        Risk = RiskLevel.Critical,
                        Location = sysmonEvtx,
                        FileName = "Microsoft-Windows-Sysmon_Operational.evtx",
                        Reason = $"Sysmon operational log contains cheat process: '{cheatName}'",
                        Detail = "Sysmon records detailed process creation, network connections, and file events — provides rich cheat activity evidence"
                    });
                }
            }

            foreach (string drvName in DriverLoadCheatNames)
            {
                if (content.Contains(drvName, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Sysmon Event Log — Cheat Driver Load",
                        Risk = RiskLevel.Critical,
                        Location = sysmonEvtx,
                        FileName = "Microsoft-Windows-Sysmon_Operational.evtx",
                        Reason = $"Sysmon log records driver load for cheat-related driver: '{drvName}'",
                        Detail = "Sysmon Event 6 (driver loaded) captures all kernel driver loads including BYOVD exploitation"
                    });
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckWindowsErrorReportingRegistry(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        string[] werRegPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\Windows Error Reporting",
            @"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps",
        };

        foreach (string werPath in werRegPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(werPath);
                if (key == null) continue;
                ctx.IncrementRegistryKeys();

                object? disabled = key.GetValue("Disabled");
                if (disabled is int disabledInt && disabledInt == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Error Reporting Disabled",
                        Risk = RiskLevel.Medium,
                        Location = $@"HKLM\{werPath}\Disabled",
                        FileName = "Disabled",
                        Reason = "WER is disabled via registry — prevents crash dump creation for cheat processes",
                        Detail = "Disabling WER hides crash dumps that would reveal cheat tool execution and loaded modules"
                    });
                }

                string dumpFolder = key.GetValue("DumpFolder")?.ToString() ?? string.Empty;
                if (!string.IsNullOrEmpty(dumpFolder))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Custom WER Dump Folder Configured",
                        Risk = RiskLevel.Low,
                        Location = $@"HKLM\{werPath}\DumpFolder",
                        FileName = "DumpFolder",
                        Reason = $"WER configured to write dumps to custom location: '{dumpFolder}'",
                        Detail = "Custom dump folders may redirect crash evidence away from standard locations to avoid forensic discovery"
                    });
                }
            }
            catch { }
        }

        try
        {
            using var excKey = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications");
            if (excKey != null)
            {
                ctx.IncrementRegistryKeys();
                foreach (string valueName in excKey.GetValueNames())
                {
                    foreach (string cheatName in CheatProcessNames)
                    {
                        if (valueName.Contains(cheatName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "WER Exclusion — Cheat Process Excluded",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications\{valueName}",
                                FileName = valueName,
                                Reason = $"Cheat process excluded from WER crash reporting: '{valueName}'",
                                Detail = "Excluding a cheat executable from WER prevents crash dump creation — intentional forensic evasion"
                            });
                        }
                    }
                }
            }
        }
        catch { }
    }, ct);
}
