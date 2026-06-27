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

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class SecurityAuditPolicyForensicScanModule : IScanModule
{
    public string Name => "Security Audit Policy Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string System32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
    private static readonly string ProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

    private static readonly string[] CheatKeywords =
    [
        "cheat", "hack", "bypass", "inject", "aimbot", "wallhack", "esp",
        "triggerbot", "speedhack", "godmode", "noclip", "teleport",
        "eac_bypass", "be_bypass", "vac_bypass", "hwid_bypass", "hwid_spoof",
        "fivem_hack", "fivem_cheat", "fivem_bypass", "ragemp_hack", "ragemp_cheat",
        "altv_hack", "altv_cheat", "altv_bypass", "kdmapper", "manualmapper",
        "mhyprot", "iqvw64e", "dbutildrv2", "rtcore64", "kernel_cheat",
        "ezfrags", "skinchanger", "neverlose", "fatality", "onetap",
        "skeet", "gamesense", "aimware", "supremacy", "hyperion_bypass"
    ];

    private static readonly string[] AuditTamperKeywords =
    [
        "audit policy change", "log cleared", "log wiped", "event log deleted",
        "auditpol", "sc stop eventlog", "net stop eventlog", "wevtutil cl",
        "clearev", "clear-eventlog", "remove-eventlog", "limit-eventlog",
        "disable audit", "no auditing", "disable logging"
    ];

    private static readonly string[] PowerShellBypassKeywords =
    [
        "Set-ExecutionPolicy Bypass", "Set-ExecutionPolicy Unrestricted",
        "ExecutionPolicy Bypass", "ExecutionPolicy Unrestricted",
        "-ExecutionPolicy bypass", "-ExecutionPolicy unrestricted",
        "Bypass -Scope", "Unrestricted -Scope",
        "amsi bypass", "amsi patch", "amsi.dll",
        "[Ref].Assembly.GetType", "AmsiScanBuffer",
        "AMSI_RESULT_CLEAN", "amsiInitFailed",
        "IEX ", "Invoke-Expression ", "IEX(", "Invoke-Expression(",
        "DownloadString", "DownloadFile", "WebClient",
        "[Net.ServicePointManager]", "SecurityProtocol",
        "Add-MpPreference -ExclusionPath",
        "Set-MpPreference -DisableRealtimeMonitoring",
        "Set-MpPreference -DisableBehaviorMonitoring",
        "Set-MpPreference -DisableIOAVProtection",
        "Set-MpPreference -DisableScriptScanning",
        "Set-MpPreference -DisableAntiVirus",
        "Set-MpPreference -DisableAntiSpyware",
        "Remove-MpPreference", "Add-MpPreference",
        "Unblock-File", "Unblock-File -Path",
        "bypass execution policy", "unrestricted execution",
        "-NonInteractive", "-NoProfile", "-WindowStyle Hidden",
        "-EncodedCommand", "-enc ", "FromBase64String",
        "vssadmin delete shadows", "wmic shadowcopy delete",
        "bcdedit /set recoveryenabled no",
        "sc stop EasyAntiCheat", "sc stop BEService",
        "sc delete EasyAntiCheat", "sc delete BEService",
        "taskkill /f /im EasyAntiCheat", "taskkill /f /im BEService.exe",
        "reg delete HKLM.*EasyAntiCheat", "reg delete HKLM.*BattlEye",
        "net stop WinDefend", "net stop MpsSvc",
        "Stop-Service WinDefend", "Disable-WindowsOptionalFeature"
    ];

    private static readonly string[] AppLockerRegistryPaths =
    [
        @"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe",
        @"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Dll",
        @"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script",
        @"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Msi",
        @"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Appx"
    ];

    private static readonly string[] EventLogNames =
    [
        "Security", "System", "Application",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-CodeIntegrity/Operational",
        "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
    ];

    private static readonly string[] EventLogFilePaths =
    [
        @"Microsoft-Windows-Windows Defender%4Operational.evtx",
        @"Microsoft-Windows-PowerShell%4Operational.evtx",
        @"Microsoft-Windows-PowerShell%4Admin.evtx",
        @"Microsoft-Windows-TaskScheduler%4Operational.evtx",
        @"Microsoft-Windows-CodeIntegrity%4Operational.evtx",
        @"Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx",
        @"Microsoft-Windows-Security-Auditing.evtx",
        @"Security.evtx",
        @"System.evtx",
        @"Application.evtx"
    ];

    private static readonly string[] WdacPolicyPaths =
    [
        @"C:\Windows\System32\CodeIntegrity\SIPolicy.p7b",
        @"C:\Windows\System32\CodeIntegrity\driversipolicy.p7b",
        @"C:\Windows\System32\CodeIntegrity\SIPolicy.p7",
        @"C:\Windows\System32\CodeIntegrity\CIPolicies",
        @"C:\Windows\System32\CodeIntegrity\Active"
    ];

    private static readonly string[] PowerShellHistoryPaths =
    [
        @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        @"AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    ];

    private static readonly string[] SuspiciousAuditEventIds =
    [
        "1102", // Security log cleared
        "4719", // Audit policy change
        "4907", // Auditing settings change
        "4713", // Kerberos policy change
        "4912", // Per-user audit policy change
        "4904", // Security event source registration
        "4905", // Security event source deregistration
        "4946", // Windows Firewall rule added
        "4947", // Windows Firewall rule modified
        "4950", // Windows Firewall setting changed
        "4697", // Service installed
        "7045", // New service installed (System log)
        "7036", // Service state change
        "7040", // Service start type change
        "4688", // Process created (with command line auditing)
        "4698", // Scheduled task created
        "4702", // Scheduled task modified
        "4700", // Scheduled task enabled
        "4701"  // Scheduled task disabled
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckAuditPolicyRegistry(ctx, ct),
            CheckEventLogChannelConfiguration(ctx, ct),
            CheckEventLogFileSizes(ctx, ct),
            CheckPowerShellLoggingPolicy(ctx, ct),
            CheckPowerShellHistoryForAuditTamper(ctx, ct),
            CheckAppLockerPolicy(ctx, ct),
            CheckWdacCodeIntegrity(ctx, ct),
            CheckScriptBlockLogging(ctx, ct),
            CheckModuleLogging(ctx, ct),
            CheckEventLogServiceRegistry(ctx, ct),
            CheckSysmonArtifacts(ctx, ct),
            CheckAuditCsvFiles(ctx, ct),
            CheckSecurityCenterAudit(ctx, ct),
            CheckWdacPolicyFiles(ctx, ct),
            CheckGroupPolicySecuritySettings(ctx, ct),
            CheckEventTracingForWindows(ctx, ct),
            CheckWindowsSecurityPolicyCsv(ctx, ct),
            CheckProcessCreationAuditEnabled(ctx, ct)
        );
    }

    private Task CheckAuditPolicyRegistry(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var auditPaths = new Dictionary<string, string>
        {
            [@"SYSTEM\CurrentControlSet\Control\Lsa"] = "AuditBaseObjects",
            [@"SYSTEM\CurrentControlSet\Control\Lsa"] = "fullprivilegeauditing",
            [@"SYSTEM\CurrentControlSet\Services\EventLog\Security"] = "MaxSize",
            [@"SYSTEM\CurrentControlSet\Services\EventLog\System"] = "MaxSize",
            [@"SYSTEM\CurrentControlSet\Services\EventLog\Application"] = "MaxSize"
        };

        try
        {
            using var lsaKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
            ctx.IncrementRegistryKeys();
            if (lsaKey != null)
            {
                var crashOnAuditFail = lsaKey.GetValue("CrashOnAuditFail");
                if (crashOnAuditFail is int caf && caf == 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "CrashOnAuditFail Configured (Locks System)",
                        Risk = Risk.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\CrashOnAuditFail",
                        FileName = "Registry",
                        Reason = "CrashOnAuditFail=2 will lock the system if audit log is full — can be exploited by attackers to prevent logging",
                        Detail = "This setting makes the system unbootable when security log is full"
                    });
                }

                var auditBaseObjects = lsaKey.GetValue("AuditBaseObjects");
                var restrictAnonymous = lsaKey.GetValue("RestrictAnonymous");
                if (restrictAnonymous is int ra && ra == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Anonymous Access to LSA Not Restricted",
                        Risk = Risk.Medium,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous",
                        FileName = "Registry",
                        Reason = "RestrictAnonymous=0 allows null-session enumeration — weakened security posture",
                        Detail = "Anonymous access should be restricted (value should be 1 or 2)"
                    });
                }

                var noLmHash = lsaKey.GetValue("NoLMHash");
                if (noLmHash is int nlm && nlm == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "LM Hash Storage Enabled in LSA",
                        Risk = Risk.Medium,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash",
                        FileName = "Registry",
                        Reason = "NoLMHash=0 allows weak LM hash storage — credential theft risk",
                        Detail = "LM hash storage should be disabled (NoLMHash=1)"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        var securityLogKeys = new[]
        {
            @"SYSTEM\CurrentControlSet\Services\EventLog\Security",
            @"SYSTEM\CurrentControlSet\Services\EventLog\System",
            @"SYSTEM\CurrentControlSet\Services\EventLog\Application"
        };

        foreach (var keyPath in securityLogKeys)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                var maxSize = key.GetValue("MaxSize");
                if (maxSize is int ms && ms < 20971520)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Event Log Max Size Too Small: {keyPath.Split('\\').Last()}",
                        Risk = Risk.Medium,
                        Location = $@"HKLM\{keyPath}\MaxSize",
                        FileName = "Registry",
                        Reason = $"Event log max size is only {ms / 1024 / 1024}MB — may cause early overwrites hiding cheat/bypass activity",
                        Detail = $"MaxSize: {ms} bytes ({ms / 1024 / 1024}MB). Recommended: ≥20MB"
                    });
                }

                var retention = key.GetValue("Retention");
                if (retention is int ret && ret == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Event Log Overwrite Oldest Enabled: {keyPath.Split('\\').Last()}",
                        Risk = Risk.Low,
                        Location = $@"HKLM\{keyPath}\Retention",
                        FileName = "Registry",
                        Reason = "Retention=0 (overwrite as needed) — old forensic events may be overwritten by bypass activity",
                        Detail = "Events from cheat tool activity may not be preserved"
                    });
                }

                var autoBackup = key.GetValue("AutoBackupLogFiles");
                if (autoBackup is int ab && ab == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Event Log Auto-Backup Enabled: {keyPath.Split('\\').Last()}",
                        Risk = Risk.Low,
                        Location = $@"HKLM\{keyPath}\AutoBackupLogFiles",
                        FileName = "Registry",
                        Reason = "Event log auto-backup enabled — backup files may contain pre-wipe cheat activity records",
                        Detail = "Check event log backup location for archived evidence"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckEventLogChannelConfiguration(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var channelPaths = new Dictionary<string, string>
        {
            ["Microsoft-Windows-PowerShell/Operational"] = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Operational",
            ["Microsoft-Windows-TaskScheduler/Operational"] = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational",
            ["Microsoft-Windows-Windows Defender/Operational"] = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational",
            ["Microsoft-Windows-CodeIntegrity/Operational"] = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CodeIntegrity/Operational",
            ["Microsoft-Windows-DriverFrameworks-UserMode/Operational"] = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DriverFrameworks-UserMode/Operational",
            ["Microsoft-Windows-Sysmon/Operational"] = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational"
        };

        foreach (var kvp in channelPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(kvp.Value);
                ctx.IncrementRegistryKeys();
                if (key == null)
                {
                    if (kvp.Key.Contains("Sysmon"))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Sysmon Not Installed (No Extended Event Logging)",
                            Risk = Risk.Medium,
                            Location = $@"HKLM\{kvp.Value}",
                            FileName = "Registry",
                            Reason = "Sysmon event channel absent — extended process/network/file monitoring not configured",
                            Detail = "Sysmon provides detailed forensic telemetry used by Ocean/detect.ac"
                        });
                    }
                    continue;
                }

                var enabled = key.GetValue("Enabled");
                if (enabled is int e && e == 0)
                {
                    var risk = kvp.Key.Contains("Defender") || kvp.Key.Contains("PowerShell")
                        ? Risk.Critical : Risk.High;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Event Log Channel Disabled: {kvp.Key}",
                        Risk = risk,
                        Location = $@"HKLM\{kvp.Value}\Enabled",
                        FileName = "Registry",
                        Reason = $"Event log channel '{kvp.Key}' is disabled — bypass tools disable logging channels to avoid detection",
                        Detail = "Enabled=0 prevents events from being recorded in this channel"
                    });
                }

                var maxSize = key.GetValue("MaxSize");
                if (maxSize is int ms && ms < 4096000 && kvp.Key.Contains("PowerShell"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PowerShell Event Log Too Small: {kvp.Key}",
                        Risk = Risk.Medium,
                        Location = $@"HKLM\{kvp.Value}\MaxSize",
                        FileName = "Registry",
                        Reason = $"PowerShell event log max size only {ms / 1024}KB — bypass PS scripts may not be fully recorded",
                        Detail = $"MaxSize: {ms} bytes"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckEventLogFileSizes(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var logDir = Path.Combine(System32, "winevt", "Logs");
        if (!Directory.Exists(logDir)) return;

        var minSizes = new Dictionary<string, long>
        {
            ["Security.evtx"] = 524288,
            ["System.evtx"] = 131072,
            ["Application.evtx"] = 131072,
            ["Microsoft-Windows-PowerShell%4Operational.evtx"] = 65536,
            ["Microsoft-Windows-Windows Defender%4Operational.evtx"] = 131072,
            ["Microsoft-Windows-TaskScheduler%4Operational.evtx"] = 65536
        };

        foreach (var logFile in EventLogFilePaths)
        {
            var fullPath = Path.Combine(logDir, logFile);
            ctx.IncrementFiles();

            if (!File.Exists(fullPath))
            {
                var risk = logFile.Contains("Security") || logFile.Contains("Defender") || logFile.Contains("PowerShell")
                    ? Risk.High : Risk.Medium;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Event Log File Missing: {logFile}",
                    Risk = risk,
                    Location = fullPath,
                    FileName = logFile,
                    Reason = $"Event log file absent — may have been deleted by bypass/cleaner tool: {logFile}",
                    Detail = $"Expected: {fullPath}"
                });
                continue;
            }

            try
            {
                var fi = new FileInfo(fullPath);
                if (minSizes.TryGetValue(logFile, out var minSize) && fi.Length < minSize)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Event Log File Suspiciously Small: {logFile}",
                        Risk = Risk.High,
                        Location = fullPath,
                        FileName = logFile,
                        Reason = $"Event log '{logFile}' is only {fi.Length / 1024}KB — may have been cleared by bypass tool (min expected: {minSize / 1024}KB)",
                        Detail = $"File size: {fi.Length} bytes"
                    });
                }

                var age = (DateTime.UtcNow - fi.LastWriteTimeUtc).TotalDays;
                if (logFile.Contains("Security") && age > 90)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Security Event Log Not Written For 90+ Days",
                        Risk = Risk.Medium,
                        Location = fullPath,
                        FileName = logFile,
                        Reason = $"Security event log last written {age:F0} days ago — unusual unless system was offline or log disabled",
                        Detail = $"Last write: {fi.LastWriteTimeUtc:u}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckPowerShellLoggingPolicy(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var psLoggingKeys = new[]
        {
            @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
            @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription",
            @"SOFTWARE\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            @"SOFTWARE\Microsoft\Windows\PowerShell\ModuleLogging"
        };

        foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            foreach (var keyPath in psLoggingKeys)
            {
                try
                {
                    using var key = hive.OpenSubKey(keyPath);
                    ctx.IncrementRegistryKeys();
                    if (key == null) continue;

                    var hivePrefix = hive == Registry.LocalMachine ? "HKLM" : "HKCU";

                    if (keyPath.Contains("ScriptBlockLogging"))
                    {
                        var enabled = key.GetValue("EnableScriptBlockLogging");
                        if (enabled is int e && e == 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "PowerShell Script Block Logging Disabled via Policy",
                                Risk = Risk.High,
                                Location = $@"{hivePrefix}\{keyPath}\EnableScriptBlockLogging",
                                FileName = "Registry",
                                Reason = "Script block logging disabled — PowerShell bypass/download cradle commands won't be recorded",
                                Detail = "EnableScriptBlockLogging=0"
                            });
                        }

                        var invocation = key.GetValue("EnableScriptBlockInvocationLogging");
                        if (invocation is int iv && iv == 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "PowerShell Script Block Invocation Logging Disabled",
                                Risk = Risk.Medium,
                                Location = $@"{hivePrefix}\{keyPath}\EnableScriptBlockInvocationLogging",
                                FileName = "Registry",
                                Reason = "Script block invocation logging disabled — function call tracking not recorded",
                                Detail = "EnableScriptBlockInvocationLogging=0"
                            });
                        }
                    }

                    if (keyPath.Contains("ModuleLogging"))
                    {
                        var enabled = key.GetValue("EnableModuleLogging");
                        if (enabled is int e && e == 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "PowerShell Module Logging Disabled via Policy",
                                Risk = Risk.High,
                                Location = $@"{hivePrefix}\{keyPath}\EnableModuleLogging",
                                FileName = "Registry",
                                Reason = "Module logging disabled — PowerShell module activity not tracked in event log",
                                Detail = "EnableModuleLogging=0"
                            });
                        }
                    }

                    if (keyPath.Contains("Transcription"))
                    {
                        var enabled = key.GetValue("EnableTranscripting");
                        var invocationHeader = key.GetValue("IncludeInvocationHeader");
                        if (enabled is int e && e == 1)
                        {
                            var dir = key.GetValue("OutputDirectory")?.ToString() ?? "";
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "PowerShell Transcription Enabled (Check Transcripts)",
                                Risk = Risk.Low,
                                Location = $@"{hivePrefix}\{keyPath}",
                                FileName = "Registry",
                                Reason = $"PowerShell transcription enabled — transcript files may contain bypass command evidence",
                                Detail = $"OutputDirectory: {dir}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }

        try
        {
            using var psKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell");
            ctx.IncrementRegistryKeys();
            if (psKey != null)
            {
                var execPolicy = psKey.GetValue("ExecutionPolicy")?.ToString() ?? "";
                if (execPolicy.Equals("Bypass", StringComparison.OrdinalIgnoreCase) ||
                    execPolicy.Equals("Unrestricted", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"PowerShell Execution Policy Set to {execPolicy} via Policy",
                        Risk = Risk.High,
                        Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy",
                        FileName = "Registry",
                        Reason = $"Execution policy permanently set to '{execPolicy}' via group policy — allows unsigned scripts to run, typical bypass tool action",
                        Detail = $"ExecutionPolicy: {execPolicy}"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckPowerShellHistoryForAuditTamper(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var userDirs = new List<string>();
        try { userDirs.AddRange(Directory.GetDirectories(@"C:\Users")); }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        foreach (var userDir in userDirs)
        {
            foreach (var relPath in PowerShellHistoryPaths)
            {
                var fullPath = Path.Combine(userDir, relPath);
                if (!File.Exists(fullPath)) continue;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var keyword in AuditTamperKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            var lines = content.Split('\n')
                                .Where(l => l.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                                .Take(2).ToList();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Audit Log Tampering Command in PowerShell History",
                                Risk = Risk.Critical,
                                Location = fullPath,
                                FileName = Path.GetFileName(fullPath),
                                Reason = $"PowerShell history contains audit-tampering command: '{keyword}'",
                                Detail = string.Join("; ", lines.Select(l => l.Trim()))
                            });
                        }
                    }

                    foreach (var bk in PowerShellBypassKeywords)
                    {
                        if (content.Contains(bk, StringComparison.OrdinalIgnoreCase))
                        {
                            var lines = content.Split('\n')
                                .Where(l => l.Contains(bk, StringComparison.OrdinalIgnoreCase))
                                .Take(2).ToList();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "PowerShell Bypass/AMSI Command in History",
                                Risk = Risk.Critical,
                                Location = fullPath,
                                FileName = Path.GetFileName(fullPath),
                                Reason = $"PowerShell history contains bypass/AMSI command: '{bk}'",
                                Detail = string.Join("; ", lines.Select(l => l.Trim()))
                            });
                        }
                    }

                    foreach (var ck in CheatKeywords)
                    {
                        if (content.Contains(ck, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat-Related Command in PowerShell History",
                                Risk = Risk.High,
                                Location = fullPath,
                                FileName = Path.GetFileName(fullPath),
                                Reason = $"PowerShell history references cheat tool: '{ck}'",
                                Detail = $"User: {Path.GetFileName(userDir)}"
                            });
                            break;
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckAppLockerPolicy(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var srpKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\SrpV2");
            ctx.IncrementRegistryKeys();

            if (srpKey == null)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "AppLocker Not Configured",
                    Risk = Risk.Low,
                    Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2",
                    FileName = "Registry",
                    Reason = "AppLocker application whitelisting not configured — allows execution of unsigned cheat tools",
                    Detail = "AppLocker provides application control that prevents cheat tool execution"
                });
                return;
            }

            foreach (var ruleType in AppLockerRegistryPaths)
            {
                try
                {
                    using var ruleKey = Registry.LocalMachine.OpenSubKey(ruleType);
                    ctx.IncrementRegistryKeys();
                    if (ruleKey == null) continue;

                    foreach (var ruleName in ruleKey.GetSubKeyNames())
                    {
                        try
                        {
                            using var rule = ruleKey.OpenSubKey(ruleName);
                            var data = rule?.GetValue("Value")?.ToString() ?? "";
                            if (data.Contains("Deny", StringComparison.OrdinalIgnoreCase))
                            {
                                foreach (var ck in CheatKeywords)
                                {
                                    if (data.Contains(ck, StringComparison.OrdinalIgnoreCase))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = Name,
                                            Title = "AppLocker Deny Rule for Cheat Tool Found",
                                            Risk = Risk.Medium,
                                            Location = $@"HKLM\{ruleType}\{ruleName}",
                                            FileName = "Registry",
                                            Reason = $"AppLocker deny rule references cheat tool: '{ck}' — confirms cheat was previously blocked",
                                            Detail = $"Rule data: {data.Length > 200 ? data[..200] : data}"
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
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckWdacCodeIntegrity(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var ciKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
            ctx.IncrementRegistryKeys();
            if (ciKey != null)
            {
                var enabled = ciKey.GetValue("Enabled");
                if (enabled is int e && e == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "HVCI (Hypervisor Protected Code Integrity) Disabled",
                        Risk = Risk.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                        FileName = "Registry",
                        Reason = "HVCI disabled — kernel-level cheat drivers and BYOVD exploits can load without code signing enforcement",
                        Detail = "HVCI prevents loading of unsigned or malicious kernel modules"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        try
        {
            using var ciConfigKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Config");
            ctx.IncrementRegistryKeys();
            if (ciConfigKey != null)
            {
                var vulnerability = ciConfigKey.GetValue("VulnerableDriverBlocklistEnable");
                if (vulnerability is int v && v == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Vulnerable Driver Blocklist Disabled",
                        Risk = Risk.Critical,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable",
                        FileName = "Registry",
                        Reason = "Microsoft vulnerable driver blocklist disabled — all known BYOVD (Bring Your Own Vulnerable Driver) exploits can load",
                        Detail = "VulnerableDriverBlocklistEnable=0 allows all documented BYOVD drivers"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        try
        {
            using var policyKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard");
            ctx.IncrementRegistryKeys();
            if (policyKey != null)
            {
                var wdacPolicy = policyKey.GetValue("DeployConfigCIPolicy");
                var hvci = policyKey.GetValue("HypervisorEnforcedCodeIntegrity");
                var cred = policyKey.GetValue("EnableVirtualizationBasedSecurity");

                if (cred is int c && c == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Virtualization Based Security Disabled via Policy",
                        Risk = Risk.Critical,
                        Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity",
                        FileName = "Registry",
                        Reason = "VBS disabled via group policy — all VBS-dependent protections (HVCI, Credential Guard) are unavailable",
                        Detail = "EnableVirtualizationBasedSecurity=0"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckScriptBlockLogging(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var psTranscriptDirs = new List<string>
        {
            @"C:\PSTranscripts",
            @"C:\Windows\Temp\PSTranscripts",
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "PowerShell", "Transcripts")
        };

        var userDirs = new List<string>();
        try { userDirs.AddRange(Directory.GetDirectories(@"C:\Users")); }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        foreach (var u in userDirs)
            psTranscriptDirs.Add(Path.Combine(u, "Documents", "PowerShell", "Transcripts"));

        foreach (var dir in psTranscriptDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.txt", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(dir, "PowerShell_transcript*", SearchOption.AllDirectories)))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PowerShell Transcript Log Found",
                        Risk = Risk.Low,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = "PowerShell transcript file found — may contain bypass/cheat command evidence",
                        Detail = $"Transcript: {file}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var psModuleLogDir = Path.Combine(System32, "winevt", "Logs");
        var psOpLog = Path.Combine(psModuleLogDir, "Microsoft-Windows-PowerShell%4Operational.evtx");
        ctx.IncrementFiles();
        if (!File.Exists(psOpLog))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "PowerShell Operational Event Log Missing",
                Risk = Risk.Critical,
                Location = psOpLog,
                FileName = "Microsoft-Windows-PowerShell%4Operational.evtx",
                Reason = "PowerShell operational event log (script block / module logging sink) is absent — may have been deleted to hide bypass commands",
                Detail = $"Expected: {psOpLog}"
            });
        }
    }, ct);

    private Task CheckModuleLogging(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var mlKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging");
            ctx.IncrementRegistryKeys();
            if (mlKey != null)
            {
                var enabled = mlKey.GetValue("EnableModuleLogging");
                if (enabled is int e && e == 1)
                {
                    using var moduleNamesKey = mlKey.OpenSubKey("ModuleNames");
                    if (moduleNamesKey == null || !moduleNamesKey.GetValueNames().Any())
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "PowerShell Module Logging Enabled But No Modules Listed",
                            Risk = Risk.Low,
                            Location = @"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
                            FileName = "Registry",
                            Reason = "Module logging enabled but no module names specified — may not log all bypass modules",
                            Detail = "Add '*' to ModuleNames to capture all module activity"
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        try
        {
            using var constrainedKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Environment");
            ctx.IncrementRegistryKeys();
            if (constrainedKey != null)
            {
                var clm = constrainedKey.GetValue("__PSLockdownPolicy");
                if (clm == null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PowerShell Constrained Language Mode Not Enforced via Environment",
                        Risk = Risk.Low,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\__PSLockdownPolicy",
                        FileName = "Registry",
                        Reason = "PowerShell Constrained Language Mode not enforced system-wide — cheat scripts can call .NET methods freely",
                        Detail = "CLM restricts PowerShell bypass scripts from calling arbitrary .NET code"
                    });
                }
                else if (clm.ToString() != "4")
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "PowerShell CLM Not Fully Enforced",
                        Risk = Risk.Medium,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\__PSLockdownPolicy",
                        FileName = "Registry",
                        Reason = $"__PSLockdownPolicy={clm} (expected 4 for full CLM) — partial enforcement may allow bypass scripts",
                        Detail = $"Value: {clm}"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckEventLogServiceRegistry(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var criticalLogServices = new[]
        {
            ("EventLog", "Windows Event Log"),
            ("BFE", "Base Filtering Engine"),
            ("MpsSvc", "Windows Firewall"),
            ("Winmgmt", "Windows Management Instrumentation"),
            ("Schedule", "Task Scheduler")
        };

        foreach (var (svcName, svcDesc) in criticalLogServices)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{svcName}");
                ctx.IncrementRegistryKeys();
                if (key == null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Critical Audit Service Key Missing: {svcName}",
                        Risk = Risk.High,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        FileName = "Registry",
                        Reason = $"Service key for '{svcDesc}' absent — may have been tampered with to disable audit/logging infrastructure",
                        Detail = $"Service: {svcName}"
                    });
                    continue;
                }

                var start = key.GetValue("Start");
                if (start is int s && s == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Critical Audit/Infrastructure Service Disabled: {svcName}",
                        Risk = Risk.Critical,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        FileName = "Registry",
                        Reason = $"'{svcDesc}' disabled (Start=4) — disable forensic/audit infrastructure to avoid detection",
                        Detail = $"Start=4 (SERVICE_DISABLED)"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckSysmonArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var sysmonPaths = new[]
        {
            @"C:\Windows\Sysmon.exe",
            @"C:\Windows\Sysmon64.exe",
            @"C:\Windows\System32\Sysmon.exe",
            @"C:\Windows\System32\Sysmon64.exe"
        };

        var sysmonFound = false;
        foreach (var path in sysmonPaths)
        {
            ctx.IncrementFiles();
            if (File.Exists(path))
            {
                sysmonFound = true;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Sysmon Installed (Extended Forensic Logging)",
                    Risk = Risk.Low,
                    Location = path,
                    FileName = Path.GetFileName(path),
                    Reason = "Sysmon found on disk — provides process creation, network, file, registry event logs",
                    Detail = $"Path: {path}"
                });
                break;
            }
        }

        try
        {
            using var sysmonKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Sysmon");
            ctx.IncrementRegistryKeys();
            if (sysmonKey != null && !sysmonFound)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Sysmon Service Registry Exists But Executable Missing",
                    Risk = Risk.High,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services\Sysmon",
                    FileName = "Registry",
                    Reason = "Sysmon service registry key present but sysmon executable missing — may have been removed to disable forensic logging",
                    Detail = "Sysmon was previously installed and appears to have been removed"
                });
            }

            using var sysmon64Key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Sysmon64");
            ctx.IncrementRegistryKeys();
            if (sysmon64Key != null)
            {
                var start = sysmon64Key.GetValue("Start");
                if (start is int s && s == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Sysmon64 Service Disabled",
                        Risk = Risk.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\Sysmon64",
                        FileName = "Registry",
                        Reason = "Sysmon64 service disabled — extended process/network forensic logging stopped, likely by bypass tool",
                        Detail = "Start=4 (SERVICE_DISABLED)"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckAuditCsvFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var auditPaths = new[]
        {
            @"C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv",
            @"C:\Windows\security\audit\audit.csv",
            @"C:\Windows\security\logs\audit.log"
        };

        foreach (var path in auditPaths)
        {
            ctx.IncrementFiles();
            if (!File.Exists(path)) continue;
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                if (content.Contains("No Auditing", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Audit Policy CSV Shows 'No Auditing' Categories",
                        Risk = Risk.High,
                        Location = path,
                        FileName = Path.GetFileName(path),
                        Reason = "Audit policy CSV file contains 'No Auditing' for one or more categories — reduces forensic visibility",
                        Detail = $"File: {path}"
                    });
                }

                var lines = content.Split('\n').Where(l =>
                    l.Contains("No Auditing", StringComparison.OrdinalIgnoreCase) ||
                    l.Contains("Logon", StringComparison.OrdinalIgnoreCase) ||
                    l.Contains("Process Creation", StringComparison.OrdinalIgnoreCase)).Take(5).ToList();

                foreach (var line in lines)
                {
                    if (line.Contains("No Auditing", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Specific Audit Category Disabled in Policy CSV",
                            Risk = Risk.Medium,
                            Location = path,
                            FileName = Path.GetFileName(path),
                            Reason = $"Audit category with 'No Auditing': {line.Trim()[..Math.Min(120, line.Length)]}",
                            Detail = $"Audit.csv: {path}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckSecurityCenterAudit(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var wscKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Security Center\Svc");
            ctx.IncrementRegistryKeys();
            if (wscKey == null) return;

            var vistaSp1Version = wscKey.GetValue("VistaSp1");
            var firstRunDisabled = wscKey.GetValue("FirstRunDisabled");
            var antiVirusOverride = wscKey.GetValue("AntiVirusOverride");
            var antiSpywareOverride = wscKey.GetValue("AntiSpywareOverride");
            var firewallOverride = wscKey.GetValue("FirewallOverride");
            var oobe = wscKey.GetValue("oobe_av");

            if (antiVirusOverride is int avo && avo == 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Security Center AV Override Active",
                    Risk = Risk.High,
                    Location = @"HKLM\SOFTWARE\Microsoft\Security Center\Svc\AntiVirusOverride",
                    FileName = "Registry",
                    Reason = "AntiVirusOverride=1 suppresses Security Center AV status notifications — bypass tool may have set this",
                    Detail = "Override prevents Windows from reporting AV status accurately"
                });
            }

            if (firewallOverride is int fo && fo == 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Security Center Firewall Override Active",
                    Risk = Risk.High,
                    Location = @"HKLM\SOFTWARE\Microsoft\Security Center\Svc\FirewallOverride",
                    FileName = "Registry",
                    Reason = "FirewallOverride=1 suppresses firewall status notifications",
                    Detail = "May be set by bypass tools to hide firewall modifications"
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckWdacPolicyFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var path in WdacPolicyPaths)
        {
            ctx.IncrementFiles();
            if (File.Exists(path))
            {
                try
                {
                    var fi = new FileInfo(path);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "WDAC Code Integrity Policy File Found",
                        Risk = Risk.Low,
                        Location = path,
                        FileName = Path.GetFileName(path),
                        Reason = $"Windows Defender Application Control policy file present ({fi.Length / 1024}KB) — application whitelisting is active",
                        Detail = $"Policy: {path}, Size: {fi.Length} bytes, Modified: {fi.LastWriteTimeUtc:u}"
                    });
                }
                catch (IOException) { }
            }

            if (Directory.Exists(path))
            {
                try
                {
                    var policies = Directory.GetFiles(path, "*.cip", SearchOption.AllDirectories);
                    foreach (var policy in policies)
                    {
                        ctx.IncrementFiles();
                        var fi = new FileInfo(policy);
                        if (fi.Length < 1024)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "WDAC Policy File Suspiciously Small",
                                Risk = Risk.High,
                                Location = policy,
                                FileName = Path.GetFileName(policy),
                                Reason = $"WDAC policy .cip file is only {fi.Length} bytes — may be stub/bypass policy allowing all unsigned code",
                                Detail = $"Policy file: {policy}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckGroupPolicySecuritySettings(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var gpSecPath = @"C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf";
        ctx.IncrementFiles();
        if (!File.Exists(gpSecPath)) return;

        try
        {
            using var fs = new FileStream(gpSecPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            string content = sr.ReadToEnd();

            if (content.Contains("AuditSystemEvents = 0", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("AuditLogonEvents = 0", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("AuditObjectAccess = 0", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Group Policy Security Template Disables Auditing",
                    Risk = Risk.High,
                    Location = gpSecPath,
                    FileName = Path.GetFileName(gpSecPath),
                    Reason = "Security template (GptTmpl.inf) disables critical audit categories — reduces forensic evidence collection",
                    Detail = $"Template: {gpSecPath}"
                });
            }

            if (content.Contains("EnableGuestAccount = 1", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Guest Account Enabled via Group Policy Security Template",
                    Risk = Risk.High,
                    Location = gpSecPath,
                    FileName = Path.GetFileName(gpSecPath),
                    Reason = "Group policy enables guest account — security weakening often paired with bypass tools",
                    Detail = "EnableGuestAccount=1 in security template"
                });
            }

            if (content.Contains("PasswordComplexity = 0", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Password Complexity Disabled via Group Policy",
                    Risk = Risk.Medium,
                    Location = gpSecPath,
                    FileName = Path.GetFileName(gpSecPath),
                    Reason = "Password complexity requirements disabled — reduces account security, often configured by cheat tools targeting multi-account systems",
                    Detail = "PasswordComplexity=0"
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckEventTracingForWindows(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var etwSessions = new[]
        {
            @"SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security",
            @"SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System",
            @"SYSTEM\CurrentControlSet\Control\WMI\Autologger\CIRCULAR KERNEL CONTEXT LOGGER",
            @"SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger",
            @"SYSTEM\CurrentControlSet\Control\WMI\Autologger\NT Kernel Logger"
        };

        foreach (var sessionPath in etwSessions)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(sessionPath);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                var enabled = key.GetValue("Start");
                var enabledInt = key.GetValue("Enabled");

                if ((enabled is int s && s == 0) || (enabledInt is int e && e == 0))
                {
                    var sessionName = sessionPath.Split('\\').Last();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"ETW Autologger Session Disabled: {sessionName}",
                        Risk = Risk.Critical,
                        Location = $@"HKLM\{sessionPath}",
                        FileName = "Registry",
                        Reason = $"ETW auto-logger session '{sessionName}' disabled — kernel event tracing stopped, primary bypass technique to blind forensic tools",
                        Detail = $"Key: HKLM\\{sessionPath}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        try
        {
            using var ckcKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\WMI\Autologger\CIRCULAR KERNEL CONTEXT LOGGER");
            ctx.IncrementRegistryKeys();
            if (ckcKey != null)
            {
                foreach (var subName in ckcKey.GetSubKeyNames())
                {
                    try
                    {
                        using var provKey = ckcKey.OpenSubKey(subName);
                        var enabled = provKey?.GetValue("Enabled");
                        if (enabled is int e && e == 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"ETW Provider Disabled in Kernel Logger: {subName}",
                                Risk = Risk.High,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CIRCULAR KERNEL CONTEXT LOGGER\{subName}",
                                FileName = "Registry",
                                Reason = $"ETW kernel logger provider '{subName}' disabled — reduces kernel-level monitoring",
                                Detail = "Enabled=0 prevents this provider from logging to the kernel session"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckWindowsSecurityPolicyCsv(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var securityPolicyPaths = new[]
        {
            @"C:\Windows\System32\GroupPolicy\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf",
            @"C:\Windows\security\database\secedit.sdb",
            @"C:\Windows\security\logs\winlogon.log",
            @"C:\Windows\security\logs\scecomp.log",
            @"C:\Windows\security\logs\scesrv.log"
        };

        foreach (var path in securityPolicyPaths)
        {
            ctx.IncrementFiles();
            if (!File.Exists(path)) continue;
            if (path.EndsWith(".sdb", StringComparison.OrdinalIgnoreCase)) continue;

            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (var ck in CheatKeywords)
                {
                    if (content.Contains(ck, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat Keyword in Security Policy Log",
                            Risk = Risk.High,
                            Location = path,
                            FileName = Path.GetFileName(path),
                            Reason = $"Windows security policy log references cheat tool: '{ck}'",
                            Detail = $"Log: {path}"
                        });
                        break;
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckProcessCreationAuditEnabled(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var auditKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit");
            ctx.IncrementRegistryKeys();
            if (auditKey != null)
            {
                var processCreation = auditKey.GetValue("ProcessCreationIncludeCmdLine_Enabled");
                if (processCreation == null || (processCreation is int pc && pc == 0))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Process Creation Command Line Audit Not Enabled",
                        Risk = Risk.Medium,
                        Location = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
                        FileName = "Registry",
                        Reason = "Command line auditing for process creation (Event 4688) not enabled — cheat loader command lines not recorded in Security log",
                        Detail = "ProcessCreationIncludeCmdLine_Enabled should be 1 for forensic command-line capture"
                    });
                }
            }
            else
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Process Creation Command Line Audit Policy Key Missing",
                    Risk = Risk.Low,
                    Location = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
                    FileName = "Registry",
                    Reason = "Process creation audit policy key not present — command line capture for security events may not be configured",
                    Detail = "Consider enabling for forensic evidence collection"
                });
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        try
        {
            using var auditPolKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa\Audit");
            ctx.IncrementRegistryKeys();
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        try
        {
            using var samKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa\SamAudit");
            ctx.IncrementRegistryKeys();
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);
}
