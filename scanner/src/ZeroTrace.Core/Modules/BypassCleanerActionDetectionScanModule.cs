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
public sealed class BypassCleanerActionDetectionScanModule : IScanModule
{
    public string Name => "Bypass/Cleaner Action Detection";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] AcProcessNames =
    [
        "EasyAntiCheat", "EasyAntiCheat_EOS", "BEService", "BEClient",
        "vgc", "vgtray", "VAC", "GameGuard", "nProtect", "GGService",
        "EQU8_AntiCheat", "hyperion", "UnknownCheats", "anticheatsdk",
        "FairFight", "PunkBuster", "PnkBstrA", "PnkBstrB",
        "CitizenFX", "FXServer", "rage_mp_d3d11_hook",
        "CrashReporter", "EasyAntiCheat_launcher",
        "SteamService", "steamguard", "steam_api",
        "BE_Service", "BE_Client", "battleye",
        "ZeroTrace", "ocean_scanner", "detect_ac"
    ];

    private static readonly string[] BypassCommandPatterns =
    [
        "sc stop", "sc delete", "net stop", "net start", "taskkill",
        "sc config", "sc failure", "reg delete", "reg add.*eac", "reg add.*battleye",
        "vssadmin delete shadows", "wmic shadowcopy delete", "bcdedit /set",
        "setenforce 0", "Set-MpPreference", "Add-MpPreference",
        "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
        "DisableIOAVProtection", "DisableScriptScanning",
        "DisableAntiSpyware", "DisableAntiVirus",
        "powershell.*bypass", "powershell.*unrestricted",
        "powershell.*hidden", "powershell.*encoded",
        "certutil.*decode", "bitsadmin.*transfer",
        "rundll32.*javascript", "regsvr32.*scrobj",
        "wmic.*process.*call", "wmic.*os.*get",
        "obfuscated bypass", "UD bypass", "FUD loader",
        "inject.*eac", "inject.*battleye", "patch.*anti",
        "kdmapper", "drivermapper", "vulnerable driver",
        "iqvw64e", "dbutildrv2", "mhyprot", "gdrv",
        "rzpnk", "AsIO64", "inpoutx64", "pcdsrvc",
        "dbutil_2_3", "HW64", "winring0",
        "dselist.*bypass", "dselist.*patch",
        "kernelmode.*inject", "kernel.*cheat",
        "hypervisor.*bypass", "vt-x.*bypass",
        "manual.*map", "manualmapper", "manual_map",
        "process.*hollow", "process.*inject",
        "reflective.*dll", "shellcode.*inject",
        "disable.*defender", "kill.*defender",
        "tamper.*protection", "exclusion.*add",
        "fivem.*bypass", "rage.*bypass", "altv.*bypass",
        "eac.*bypass", "be.*bypass", "vac.*bypass",
        "remove.*traces", "clean.*logs", "wipe.*prefetch",
        "clear.*eventlog", "wevtutil.*cl", "clearev"
    ];

    private static readonly string[] KnownBypassDriverNames =
    [
        "iqvw64e.sys", "dbutildrv2.sys", "mhyprot2.sys", "gdrv.sys",
        "rzpnk.sys", "AsIO64.sys", "inpoutx64.sys", "pcdsrvc_x64.pkms",
        "dbutil_2_3.sys", "HW64.sys", "winring0x64.sys", "kdmapper.exe",
        "drivermapper.exe", "vulnerable_driver.sys", "evil_driver.sys",
        "hwid_bypass.sys", "kdmapper", "dmapper", "map_driver",
        "ProcExp152.sys", "PROCEXP.SYS", "procexp", "procmem",
        "capcom.sys", "hacksys.sys", "RTCore64.sys", "aswArPot.sys",
        "AsrDrv101.sys", "AsrDrv102.sys", "asmmap64.sys",
        "bsflash64.sys", "Netis.sys", "netfilter64.sys"
    ];

    private static readonly string[] AcServiceNames =
    [
        "EasyAntiCheat", "BEService", "BattlEye", "vgc", "VAC",
        "EQU8", "nProtect", "GameGuard", "PnkBstrA", "PnkBstrB",
        "FiveM", "CitizenFX", "RageMP", "AltV",
        "WinDefend", "MpsSvc", "wscsvc", "SecurityHealthService",
        "Sense", "WdNisSvc", "WdNisDrv", "WdFilter", "WdBoot"
    ];

    private static readonly string[] ShadowCopyDeletePatterns =
    [
        "delete shadows", "shadowcopy delete", "vssadmin.*delete",
        "wmic.*shadowcopy.*delete", "diskshadow.*delete",
        "bcdedit.*recoveryenabled.*no", "bcdedit.*safeboot"
    ];

    private static readonly string[] CleanerToolSignatures =
    [
        "prefetch_cleaner", "trace_cleaner", "log_wiper", "evidence_cleaner",
        "digital_janitor", "forensic_cleaner", "artifact_remover",
        "history_cleaner", "registry_cleaner_pro", "anti_forensics",
        "track_eraser", "privacy_cleaner", "secure_delete",
        "eraser", "bleachbit", "privazer", "ccleaner",
        "mruview", "lastactivityview", "jumplist_eraser",
        "shellbag_deleter", "prefetch_deleter", "amcache_cleaner",
        "shimcache_cleaner", "bam_cleaner", "usnjrnl_cleaner",
        "cheat_cleaner", "fivem_cleaner", "ragemp_cleaner",
        "altv_cleaner", "eac_bypass_cleaner", "be_bypass_cleaner",
        "vac_bypass_cleaner", "hwid_cleaner", "spoofer_cleaner",
        "hwid_spoofer", "serialspoofer", "diskspoofer",
        "macspoofer", "systemspoofer", "hardwarespoofer"
    ];

    private static readonly string[] PowerShellHistoryPaths =
    [
        @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        @"AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        @"Documents\WindowsPowerShell\ConsoleHost_history.txt"
    ];

    private static readonly string[] CmdHistoryLocations =
    [
        @"AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations",
        @"AppData\Local\Microsoft\Windows\History"
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckPowerShellHistoryForBypassCommands(ctx, ct),
            CheckRegistryForAcServiceModifications(ctx, ct),
            CheckRegistryForDefenderTampering(ctx, ct),
            CheckKnownBypassDriverResidues(ctx, ct),
            CheckWmiSubscriptionArtifacts(ctx, ct),
            CheckScheduledTaskBypassArtifacts(ctx, ct),
            CheckEventLogClearanceTraces(ctx, ct),
            CheckVssCopyDeletionArtifacts(ctx, ct),
            CheckCleanerToolResidues(ctx, ct),
            CheckPrefetchForBypassTools(ctx, ct),
            CheckRecentFilesForBypassActions(ctx, ct),
            CheckMuiCacheForBypassPrograms(ctx, ct),
            CheckUserAssistForBypassActivity(ctx, ct),
            CheckTempDirsForBypassArtifacts(ctx, ct),
            CheckStartupForBypassPersistence(ctx, ct)
        );
    }

    private Task CheckPowerShellHistoryForBypassCommands(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var userDirs = new List<string>();
        try
        {
            userDirs.AddRange(Directory.GetDirectories(@"C:\Users"));
        }
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

                    foreach (var pattern in BypassCommandPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            var lines = content.Split('\n')
                                .Where(l => l.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                .Take(3)
                                .ToList();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Bypass/Cleaner Command in PowerShell History",
                                Risk = DetermineRisk(pattern),
                                Location = fullPath,
                                FileName = Path.GetFileName(fullPath),
                                Reason = $"PowerShell history contains bypass command: '{pattern}'",
                                Detail = string.Join("; ", lines.Select(l => l.Trim()).Take(2))
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckRegistryForAcServiceModifications(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var svcName in AcServiceNames)
        {
            try
            {
                var keyPath = $@"SYSTEM\CurrentControlSet\Services\{svcName}";
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                ctx.IncrementRegistryKeys();

                if (key == null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Anti-Cheat/Security Service Key Missing",
                        Risk = Risk.High,
                        Location = $@"HKLM\{keyPath}",
                        FileName = "Registry",
                        Reason = $"Service registry key for '{svcName}' is absent — may have been deleted by bypass/cleaner",
                        Detail = "Anti-cheat service registration absent from HKLM\\SYSTEM\\CurrentControlSet\\Services"
                    });
                    continue;
                }

                var startVal = key.GetValue("Start");
                if (startVal != null && (int)startVal == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Anti-Cheat Service Disabled in Registry",
                        Risk = Risk.High,
                        Location = $@"HKLM\{keyPath}",
                        FileName = "Registry",
                        Reason = $"Service '{svcName}' Start=4 (disabled) — likely disabled by bypass tool",
                        Detail = $"Start value: {startVal} (4 = SERVICE_DISABLED)"
                    });
                }

                var typeVal = key.GetValue("Type");
                var imageVal = key.GetValue("ImagePath")?.ToString() ?? "";
                if (!string.IsNullOrEmpty(imageVal) && IsKnownBypassImage(imageVal))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Suspicious Driver Registered as Service",
                        Risk = Risk.Critical,
                        Location = $@"HKLM\{keyPath}",
                        FileName = "Registry",
                        Reason = $"Service '{svcName}' ImagePath points to known bypass/vulnerable driver: {imageVal}",
                        Detail = $"ImagePath: {imageVal}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRegistryForDefenderTampering(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var defenderKeys = new Dictionary<string, string[]>
        {
            [@"SOFTWARE\Policies\Microsoft\Windows Defender"] = ["DisableAntiSpyware", "DisableAntiVirus", "DisableRealtimeMonitoring"],
            [@"SOFTWARE\Microsoft\Windows Defender\Features"] = ["TamperProtection"],
            [@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"] = ["DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableScriptScanning"],
            [@"SOFTWARE\Microsoft\Windows Defender\Spynet"] = ["SpynetReporting", "SubmitSamplesConsent"],
            [@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"] = ["DisableRealtimeMonitoring", "DisableOnAccessProtection", "DisableScanOnRealtimeEnable"]
        };

        foreach (var kvp in defenderKeys)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(kvp.Key);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                foreach (var valueName in kvp.Value)
                {
                    var val = key.GetValue(valueName);
                    if (val == null) continue;

                    var intVal = val is int i ? i : -1;
                    var isDisableValue = valueName.StartsWith("Disable", StringComparison.OrdinalIgnoreCase);
                    var isTamperProtection = valueName.Equals("TamperProtection", StringComparison.OrdinalIgnoreCase);

                    if ((isDisableValue && intVal == 1) || (isTamperProtection && intVal == 4))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Windows Defender Tampered via Registry",
                            Risk = Risk.Critical,
                            Location = $@"HKLM\{kvp.Key}\{valueName}",
                            FileName = "Registry",
                            Reason = $"Defender protection disabled: {valueName}={val} — bypass tool likely set this",
                            Detail = $"Key: HKLM\\{kvp.Key}, Value: {valueName} = {val}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        try
        {
            using var excKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths");
            ctx.IncrementRegistryKeys();
            if (excKey != null)
            {
                foreach (var valName in excKey.GetValueNames())
                {
                    if (IsCheatOrBypassPath(valName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat/Bypass Path in Defender Exclusions",
                            Risk = Risk.Critical,
                            Location = @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                            FileName = "Registry",
                            Reason = $"Defender exclusion for suspicious path: {valName}",
                            Detail = $"Excluded path matches cheat/bypass pattern: {valName}"
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckKnownBypassDriverResidues(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var searchDirs = new[]
        {
            @"C:\Windows\System32\drivers",
            @"C:\Windows\SysWOW64\drivers",
            @"C:\Windows\Temp",
            @"C:\Temp",
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
        };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    foreach (var driverName in KnownBypassDriverNames)
                    {
                        if (fileName.Equals(driverName, StringComparison.OrdinalIgnoreCase) ||
                            fileName.Contains(driverName.Replace(".sys", "").Replace(".exe", ""), StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Known Bypass/Vulnerable Driver Found",
                                Risk = Risk.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason = $"Known vulnerable/bypass driver '{driverName}' found on disk — used by kernel-level cheats",
                                Detail = $"Full path: {file}"
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        try
        {
            using var driverKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (driverKey != null)
            {
                foreach (var subKeyName in driverKey.GetSubKeyNames())
                {
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var svcKey = driverKey.OpenSubKey(subKeyName);
                        var imagePath = svcKey?.GetValue("ImagePath")?.ToString() ?? "";
                        if (string.IsNullOrEmpty(imagePath)) continue;

                        foreach (var driverName in KnownBypassDriverNames)
                        {
                            if (imagePath.Contains(driverName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Bypass Driver Registered as Windows Service",
                                    Risk = Risk.Critical,
                                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{subKeyName}",
                                    FileName = "Registry",
                                    Reason = $"Service '{subKeyName}' uses known bypass driver: {driverName}",
                                    Detail = $"ImagePath: {imagePath}"
                                });
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
    }, ct);

    private Task CheckWmiSubscriptionArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var wmiPaths = new[]
        {
            @"SOFTWARE\Microsoft\WBEM\CIMOM",
            @"SOFTWARE\Microsoft\Wbem\Scripting",
            @"SYSTEM\CurrentControlSet\Services\winmgmt"
        };

        foreach (var path in wmiPaths)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                foreach (var valName in key.GetValueNames())
                {
                    var val = key.GetValue(valName)?.ToString() ?? "";
                    if (ContainsBypassKeywords(val))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "WMI Registry Entry with Bypass Keywords",
                            Risk = Risk.High,
                            Location = $@"HKLM\{path}\{valName}",
                            FileName = "Registry",
                            Reason = $"WMI registry value contains bypass-related content: {valName}",
                            Detail = $"Value: {(val.Length > 200 ? val[..200] + "..." : val)}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var wmiMofDir = @"C:\Windows\System32\wbem\Repository";
        if (Directory.Exists(wmiMofDir))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(wmiMofDir, "*.mof", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = sr.ReadToEnd();
                        if (ContainsBypassKeywords(content))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "WMI MOF File with Bypass Keywords",
                                Risk = Risk.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "WMI MOF file contains bypass-related content — possible persistence mechanism",
                                Detail = $"File: {file}"
                            });
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

    private Task CheckScheduledTaskBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var taskDirs = new[]
        {
            @"C:\Windows\System32\Tasks",
            @"C:\Windows\SysWOW64\Tasks"
        };

        foreach (var dir in taskDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        if (ContainsBypassKeywords(content))
                        {
                            var taskName = Path.GetFileName(file);
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Scheduled Task with Bypass/Cheat Keywords",
                                Risk = Risk.High,
                                Location = file,
                                FileName = taskName,
                                Reason = $"Scheduled task '{taskName}' contains bypass/cheat-related commands",
                                Detail = $"Task file: {file}"
                            });
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

    private Task CheckEventLogClearanceTraces(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var eventLogPaths = new[]
        {
            @"C:\Windows\System32\winevt\Logs\System.evtx",
            @"C:\Windows\System32\winevt\Logs\Security.evtx",
            @"C:\Windows\System32\winevt\Logs\Application.evtx",
            @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
            @"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx"
        };

        foreach (var logPath in eventLogPaths)
        {
            ctx.IncrementFiles();
            if (!File.Exists(logPath))
            {
                var logName = Path.GetFileNameWithoutExtension(logPath);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Windows Event Log File Missing",
                    Risk = Risk.High,
                    Location = logPath,
                    FileName = Path.GetFileName(logPath),
                    Reason = $"Event log file absent — may have been wiped by cleaner/bypass: {logName}",
                    Detail = $"Expected path: {logPath}"
                });
                continue;
            }

            try
            {
                var fi = new FileInfo(logPath);
                if (fi.Length < 69632)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Windows Event Log Suspiciously Small",
                        Risk = Risk.Medium,
                        Location = logPath,
                        FileName = Path.GetFileName(logPath),
                        Reason = $"Event log file is unusually small ({fi.Length} bytes) — may have been cleared by bypass tool",
                        Detail = $"File size: {fi.Length} bytes (min expected ~69KB for active log)"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        try
        {
            using var auditKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\EventLog");
            ctx.IncrementRegistryKeys();
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckVssCopyDeletionArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
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

                    foreach (var pattern in ShadowCopyDeletePatterns)
                    {
                        if (Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Volume Shadow Copy Deletion Command in History",
                                Risk = Risk.Critical,
                                Location = fullPath,
                                FileName = Path.GetFileName(fullPath),
                                Reason = $"PowerShell/CMD history contains VSS deletion command matching pattern: '{pattern}'",
                                Detail = "Shadow copy deletion often used to prevent recovery of deleted cheat files/logs"
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
            using var vssKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\VSS");
            ctx.IncrementRegistryKeys();
            if (vssKey != null)
            {
                var startVal = vssKey.GetValue("Start");
                if (startVal != null && (int)startVal == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Volume Shadow Copy Service Disabled",
                        Risk = Risk.High,
                        Location = @"HKLM\SYSTEM\CurrentControlSet\Services\VSS",
                        FileName = "Registry",
                        Reason = "VSS service disabled — prevents shadow copy backups, used by bypass/ransomware tools",
                        Detail = "Start=4 (SERVICE_DISABLED)"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckCleanerToolResidues(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var searchDirs = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            @"C:\Temp",
            @"C:\Users\Public\Downloads",
            @"C:\Users\Public"
        };

        var userDirs = new List<string>();
        try { userDirs.AddRange(Directory.GetDirectories(@"C:\Users")); }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        foreach (var u in userDirs)
        {
            searchDirs.Add(Path.Combine(u, "Downloads"));
            searchDirs.Add(Path.Combine(u, "Desktop"));
        }

        foreach (var dir in searchDirs.Distinct())
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                    foreach (var sig in CleanerToolSignatures)
                    {
                        if (fileName.Contains(sig.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cleaner/Spoofer Tool Found",
                                Risk = Risk.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"File matches known cleaner/spoofer signature: '{sig}'",
                                Detail = $"Full path: {file}"
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckPrefetchForBypassTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir)) return;
        try
        {
            foreach (var file in Directory.EnumerateFiles(prefetchDir, "*.pf"))
            {
                ctx.IncrementFiles();
                var name = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
                foreach (var sig in CleanerToolSignatures)
                {
                    if (name.Contains(sig.ToLowerInvariant()))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cleaner/Bypass Tool in Prefetch",
                            Risk = Risk.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Prefetch entry for cleaner/bypass tool: '{sig}'",
                            Detail = $"Prefetch: {Path.GetFileName(file)}"
                        });
                    }
                }

                foreach (var acProc in AcProcessNames)
                {
                    if (name.Contains(acProc.ToLowerInvariant()))
                    {
                        try
                        {
                            var fi = new FileInfo(file);
                            if ((DateTime.UtcNow - fi.LastWriteTimeUtc).TotalDays <= 30)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Anti-Cheat Process in Prefetch (Recent)",
                                    Risk = Risk.Low,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"AC process '{acProc}' ran recently (prefetch age ≤30 days) — confirms AC was active before bypass",
                                    Detail = $"Last modified: {fi.LastWriteTimeUtc:u}"
                                });
                            }
                        }
                        catch (IOException) { }
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        await Task.CompletedTask;
    }, ct);

    private Task CheckRecentFilesForBypassActions(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var recentDir = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
        if (!Directory.Exists(recentDir)) return;
        try
        {
            foreach (var lnk in Directory.EnumerateFiles(recentDir, "*.lnk"))
            {
                ctx.IncrementFiles();
                var name = Path.GetFileNameWithoutExtension(lnk).ToLowerInvariant();
                foreach (var sig in CleanerToolSignatures)
                {
                    if (name.Contains(sig.ToLowerInvariant()))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cleaner/Bypass Tool in Recent Files",
                            Risk = Risk.High,
                            Location = lnk,
                            FileName = Path.GetFileName(lnk),
                            Reason = $"Recent file link references cleaner/bypass tool: '{sig}'",
                            Detail = $"LNK: {Path.GetFileName(lnk)}"
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckMuiCacheForBypassPrograms(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var muiCachePaths = new[]
        {
            @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
        };

        foreach (var muiPath in muiCachePaths)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(muiPath);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                foreach (var valName in key.GetValueNames())
                {
                    var lowerName = valName.ToLowerInvariant();
                    foreach (var sig in CleanerToolSignatures)
                    {
                        if (lowerName.Contains(sig.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cleaner/Bypass Program in MUI Cache",
                                Risk = Risk.High,
                                Location = $@"HKCU\{muiPath}\{valName}",
                                FileName = "Registry",
                                Reason = $"MUI cache records execution of known cleaner/bypass tool: '{sig}'",
                                Detail = $"Entry: {valName}"
                            });
                        }
                    }

                    foreach (var driverName in KnownBypassDriverNames)
                    {
                        if (lowerName.Contains(driverName.Replace(".sys", "").ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Bypass Driver Tool in MUI Cache",
                                Risk = Risk.Critical,
                                Location = $@"HKCU\{muiPath}\{valName}",
                                FileName = "Registry",
                                Reason = $"MUI cache records execution of bypass driver loader: '{driverName}'",
                                Detail = $"Entry: {valName}"
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckUserAssistForBypassActivity(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var guids = new[]
        {
            @"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            @"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"
        };

        foreach (var guid in guids)
        {
            var path = $@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count";
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(path);
                ctx.IncrementRegistryKeys();
                if (key == null) continue;

                foreach (var valName in key.GetValueNames())
                {
                    var decoded = Rot13Decode(valName).ToLowerInvariant();
                    foreach (var sig in CleanerToolSignatures)
                    {
                        if (decoded.Contains(sig.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cleaner/Bypass Tool in UserAssist",
                                Risk = Risk.High,
                                Location = $@"HKCU\{path}\{valName}",
                                FileName = "Registry",
                                Reason = $"UserAssist records execution of cleaner/bypass tool: '{sig}'",
                                Detail = $"Decoded: {decoded}"
                            });
                        }
                    }

                    foreach (var driverTool in KnownBypassDriverNames)
                    {
                        var dName = driverTool.Replace(".sys", "").Replace(".exe", "").ToLowerInvariant();
                        if (decoded.Contains(dName))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Bypass Driver Tool Executed (UserAssist)",
                                Risk = Risk.Critical,
                                Location = $@"HKCU\{path}\{valName}",
                                FileName = "Registry",
                                Reason = $"UserAssist confirms execution of bypass driver tool: '{driverTool}'",
                                Detail = $"Decoded entry: {decoded}"
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckTempDirsForBypassArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var tempDirs = new List<string>
        {
            @"C:\Windows\Temp",
            @"C:\Temp",
            Path.GetTempPath()
        };

        var userDirs = new List<string>();
        try { userDirs.AddRange(Directory.GetDirectories(@"C:\Users")); }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        foreach (var u in userDirs)
        {
            tempDirs.Add(Path.Combine(u, "AppData", "Local", "Temp"));
        }

        foreach (var dir in tempDirs.Distinct())
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file).ToLowerInvariant();
                    foreach (var driverName in KnownBypassDriverNames)
                    {
                        if (fileName.Contains(driverName.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Bypass Driver Found in Temp Directory",
                                Risk = Risk.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Known bypass/vulnerable driver found in temp: '{driverName}'",
                                Detail = $"Path: {file}"
                            });
                        }
                    }

                    foreach (var sig in CleanerToolSignatures)
                    {
                        if (fileName.Contains(sig.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cleaner Tool Artifact in Temp Directory",
                                Risk = Risk.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Cleaner/bypass tool artifact in temp directory: '{sig}'",
                                Detail = $"Path: {file}"
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckStartupForBypassPersistence(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var startupKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
        };

        foreach (var keyPath in startupKeys)
        {
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                try
                {
                    using var key = hive.OpenSubKey(keyPath);
                    ctx.IncrementRegistryKeys();
                    if (key == null) continue;

                    foreach (var valName in key.GetValueNames())
                    {
                        var valData = key.GetValue(valName)?.ToString() ?? "";
                        var lowerVal = valData.ToLowerInvariant();
                        var lowerName = valName.ToLowerInvariant();

                        foreach (var sig in CleanerToolSignatures)
                        {
                            if (lowerVal.Contains(sig.ToLowerInvariant()) || lowerName.Contains(sig.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Cleaner/Bypass Tool in Startup Registry",
                                    Risk = Risk.Critical,
                                    Location = $@"{(hive == Registry.LocalMachine ? "HKLM" : "HKCU")}\{keyPath}\{valName}",
                                    FileName = "Registry",
                                    Reason = $"Startup entry for cleaner/bypass tool: '{sig}'",
                                    Detail = $"Value: {(valData.Length > 150 ? valData[..150] + "..." : valData)}"
                                });
                            }
                        }

                        foreach (var driverName in KnownBypassDriverNames)
                        {
                            var dName = driverName.Replace(".sys", "").Replace(".exe", "").ToLowerInvariant();
                            if (lowerVal.Contains(dName) || lowerName.Contains(dName))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Bypass Driver Loader in Startup",
                                    Risk = Risk.Critical,
                                    Location = $@"{(hive == Registry.LocalMachine ? "HKLM" : "HKCU")}\{keyPath}\{valName}",
                                    FileName = "Registry",
                                    Reason = $"Startup entry points to bypass driver loader: '{driverName}'",
                                    Detail = $"Value: {(valData.Length > 150 ? valData[..150] + "..." : valData)}"
                                });
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private static bool IsKnownBypassImage(string imagePath)
    {
        var lower = imagePath.ToLowerInvariant();
        foreach (var name in KnownBypassDriverNames)
        {
            if (lower.Contains(name.ToLowerInvariant())) return true;
        }
        return false;
    }

    private static bool IsCheatOrBypassPath(string path)
    {
        var lower = path.ToLowerInvariant();
        var keywords = new[] { "cheat", "hack", "bypass", "inject", "spoof", "loader", "cleaner", "eac_bypass", "be_bypass", "vac_bypass", "fivem_bypass", "rage_bypass", "altv_bypass", "hwid" };
        return keywords.Any(k => lower.Contains(k));
    }

    private static bool ContainsBypassKeywords(string content)
    {
        if (string.IsNullOrEmpty(content)) return false;
        var lower = content.ToLowerInvariant();
        var keywords = new[] { "bypass", "inject", "cheat", "hack", "spoof", "loader", "eac_bypass", "be_bypass", "vac_bypass", "kdmapper", "manualmapper", "disable.*defender", "kill.*anticheat", "sc stop", "taskkill.*eac", "taskkill.*battleye" };
        return keywords.Any(k => Regex.IsMatch(lower, k));
    }

    private static Risk DetermineRisk(string pattern)
    {
        var lower = pattern.ToLowerInvariant();
        if (lower.Contains("vssadmin") || lower.Contains("shadowcopy") || lower.Contains("bcdedit") ||
            lower.Contains("kdmapper") || lower.Contains("manualmapper") || lower.Contains("kernel"))
            return Risk.Critical;
        if (lower.Contains("sc stop") || lower.Contains("sc delete") || lower.Contains("net stop") ||
            lower.Contains("taskkill") || lower.Contains("defender") || lower.Contains("bypass") ||
            lower.Contains("inject") || lower.Contains("wevtutil"))
            return Risk.High;
        if (lower.Contains("reg delete") || lower.Contains("powershell") || lower.Contains("certutil") ||
            lower.Contains("bitsadmin") || lower.Contains("wmic"))
            return Risk.Medium;
        return Risk.Low;
    }

    private static string Rot13Decode(string s)
    {
        return new string(s.Select(c =>
            c >= 'a' && c <= 'z' ? (char)('a' + (c - 'a' + 13) % 26) :
            c >= 'A' && c <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) : c).ToArray());
    }
}
