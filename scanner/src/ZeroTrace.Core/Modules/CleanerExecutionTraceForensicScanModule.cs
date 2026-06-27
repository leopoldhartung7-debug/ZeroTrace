using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class CleanerExecutionTraceForensicScanModule : IScanModule
{
    public string Name => "Cleaner Execution Trace & Command-Line Action Detection";
    public double Weight => 4.6;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.WhenAll(
            CheckPowerShellHistoryForCleaning(ctx, ct),
            CheckCmdAutoRunHijacks(ctx, ct),
            CheckBatchScriptsInTemp(ctx, ct),
            CheckRecentRegistryCleaning(ctx, ct),
            CheckRecentEventLogClearing(ctx, ct),
            CheckRecentlyModifiedSystemFiles(ctx, ct),
            CheckPagefileCleared(ctx, ct),
            CheckSwapfileCleared(ctx, ct),
            CheckHiberfileCleared(ctx, ct),
            CheckRecentSdeleteUsage(ctx, ct),
            CheckRecentCipherUsage(ctx, ct),
            CheckBleachBitTraces(ctx, ct),
            CheckCcleanerTraces(ctx, ct),
            CheckPrivazerTraces(ctx, ct),
            CheckTakeOwnAndIcaclsUsage(ctx, ct),
            CheckRecentFsutilUsage(ctx, ct),
            CheckRecentWevtutilUsage(ctx, ct),
            CheckRecentNetshUsage(ctx, ct),
            CheckRecentlyClearedDnsCache(ctx, ct),
            CheckArpCacheCleared(ctx, ct),
            CheckRecentlyCreatedSpooferKeys(ctx, ct),
            CheckTimestompUtilityArtifacts(ctx, ct)
        );
    }

    private static readonly string[] PsCleaningCommands =
    {
        "Remove-Item -Recurse", "Remove-Item -Force",
        "Get-ChildItem -Recurse | Remove-Item", "Clear-Content",
        "Clear-EventLog", "Clear-RecycleBin",
        "Remove-ItemProperty", "Remove-Item HKCU:",
        "Remove-Item HKLM:", "Reset-Computer", "Restart-Service",
        "Stop-Service EasyAntiCheat", "Stop-Service BEService",
        "Stop-Service BEDaisy", "Stop-Service vgc", "Stop-Service vgk",
        "Set-Service EasyAntiCheat -StartupType Disabled",
        "Set-Service BEService -StartupType Disabled",
        "Set-Service vgc -StartupType Disabled",
        "Remove-Item C:\\Windows\\Prefetch\\* -Force",
        "Remove-Item C:\\Windows\\System32\\winevt\\Logs\\* -Force",
        "Remove-Item -Path 'C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*'",
        "Remove-Item -Path 'C:\\Users\\*\\AppData\\Local\\FiveM' -Recurse -Force",
        "Remove-Item -Path 'C:\\Users\\*\\AppData\\Local\\RAGEMP' -Recurse -Force",
        "Remove-Item -Path 'C:\\Users\\*\\AppData\\Local\\altv' -Recurse -Force",
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows Defender'",
        "Set-MpPreference -DisableRealtimeMonitoring $true",
        "Set-MpPreference -DisableScriptScanning $true",
        "Set-MpPreference -DisableBehaviorMonitoring $true",
        "Set-MpPreference -DisableIOAVProtection $true",
        "Add-MpPreference -ExclusionPath",
        "Get-Item HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
        "Remove-Item HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
        "Remove-Item HKCU:\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
        "Stop-Process -Name EasyAntiCheat", "Stop-Process -Name BEService",
        "Stop-Process -Name vgc", "Stop-Process -Name vgk",
        "Stop-Process -Name MsMpEng", "Stop-Process -Name NisSrv",
        "Set-ExecutionPolicy Bypass", "Set-ExecutionPolicy Unrestricted",
        "Invoke-Expression", "iex (New-Object Net.WebClient).DownloadString",
        "DownloadFile", "Invoke-WebRequest", "iwr -outf",
        "[System.Net.WebClient]::new().DownloadFile",
    };

    private static readonly string[] CmdCleaningCommands =
    {
        "del C:\\Windows\\Prefetch\\*", "del /F /Q C:\\Windows\\Prefetch",
        "rmdir /S /Q C:\\Windows\\Prefetch", "rd /S /Q C:\\Windows\\Prefetch",
        "del C:\\Windows\\System32\\winevt\\Logs\\*",
        "wevtutil cl Security", "wevtutil cl System",
        "wevtutil cl Application", "wevtutil cl Setup",
        "wevtutil el", "wevtutil cl",
        "fsutil usn deletejournal", "fsutil resource",
        "sc stop EasyAntiCheat", "sc stop BEService", "sc stop vgc",
        "sc stop vgk", "sc stop BEDaisy", "sc stop FACEIT",
        "sc config EasyAntiCheat start= disabled",
        "sc config BEService start= disabled",
        "sc config vgc start= disabled", "sc config vgk start= disabled",
        "sc delete EasyAntiCheat", "sc delete BEService",
        "sc delete vgc", "sc delete vgk", "sc delete BEDaisy",
        "taskkill /f /im EasyAntiCheat", "taskkill /f /im BEService",
        "taskkill /f /im vgc.exe", "taskkill /f /im vgk.exe",
        "taskkill /f /im MsMpEng", "taskkill /f /im NisSrv",
        "reg delete HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
        "reg delete HKCU\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
        "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Services\\EasyAntiCheat",
        "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Services\\BEService",
        "reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI",
        "bcdedit /set testsigning on", "bcdedit /set nointegritychecks on",
        "bcdedit /set hypervisorlaunchtype off",
        "bcdedit /set loadoptions DISABLE_INTEGRITY_CHECKS",
        "cipher /w:", "sdelete -p", "sdelete -z",
        "sdelete64 -p", "sdelete64 -z", "kdmapper.exe",
        "kdu.exe -map", "rundll32.exe shell32.dll,Control_RunDLL",
        "netsh wlan delete profile", "netsh advfirewall set allprofiles state off",
        "ipconfig /flushdns", "arp -d", "route delete",
        "fltMC.exe unload", "manage-bde -off", "Disable-WindowsOptionalFeature",
        "Dism /online /Disable-Feature", "BCDEDIT /TIMEOUT 0",
        "schtasks /delete /tn", "schtasks /create /tn",
        "vssadmin delete shadows", "wbadmin delete catalog",
        "wbadmin delete systemstatebackup",
    };

    private Task CheckPowerShellHistoryForCleaning(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string psHistory = Path.Combine(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
            if (!File.Exists(psHistory)) return;
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(psHistory, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            foreach (var cmd in PsCleaningCommands)
            {
                if (!content.Contains(cmd, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Cleaner Action in PowerShell History",
                    Risk = RiskLevel.Critical,
                    Location = psHistory,
                    FileName = "ConsoleHost_history.txt",
                    Reason = $"PowerShell history contains cleaner command: '{cmd}'",
                    Detail = "User executed a trace-wipe / anti-cheat-disable command via PowerShell.",
                });
            }
        }, ct);

    private Task CheckCmdAutoRunHijacks(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] paths =
            {
                @"SOFTWARE\Microsoft\Command Processor",
                @"SOFTWARE\WOW6432Node\Microsoft\Command Processor",
            };

            foreach (var p in paths)
            {
                ct.ThrowIfCancellationRequested();
                foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    RegistryKey? k;
                    try { k = hive.OpenSubKey(p); }
                    catch (System.Security.SecurityException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }
                    if (k == null) continue;

                    using (k)
                    {
                        ctx.IncrementRegistryKeys();
                        object? ar;
                        try { ar = k.GetValue("AutoRun"); }
                        catch (System.Security.SecurityException) { continue; }

                        if (ar != null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "CMD AutoRun Hijack",
                                Risk = RiskLevel.High,
                                Location = $"{hive.Name}\\{p}\\AutoRun",
                                Reason = "cmd.exe AutoRun value is set.",
                                Detail = $"AutoRun executes on every cmd start: {ar}\nCommonly abused by cleaners to re-run trace-wiping on each shell.",
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckBatchScriptsInTemp(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var temp = Environment.GetEnvironmentVariable("TEMP");
            if (string.IsNullOrEmpty(temp) || !Directory.Exists(temp)) return;

            string[] exts = { ".bat", ".cmd", ".ps1", ".psm1", ".vbs" };

            foreach (var ext in exts)
            {
                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(temp, "*" + ext, SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var cmd in CmdCleaningCommands.Concat(PsCleaningCommands))
                    {
                        if (!content.Contains(cmd, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cleaner Script in TEMP",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Temp script contains cleaner action: '{cmd}'",
                            Detail = "Cleaner / bypass batch / PowerShell script staged in TEMP — direct execution evidence.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckRecentRegistryCleaning(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] watched =
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
                @"SOFTWARE\Microsoft\Windows\Shell\BagMRU",
                @"SOFTWARE\Microsoft\Windows\Shell\Bags",
            };

            foreach (var w in watched)
            {
                ct.ThrowIfCancellationRequested();
                RegistryKey? k;
                try { k = Registry.CurrentUser.OpenSubKey(w); }
                catch (System.Security.SecurityException) { continue; }
                catch (UnauthorizedAccessException) { continue; }
                if (k == null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Forensic Registry Key Removed",
                        Risk = RiskLevel.Critical,
                        Location = $"HKCU\\{w}",
                        Reason = "Key normally populated by Windows is missing.",
                        Detail = "Hard delete via reg.exe / cleaner.",
                    });
                    continue;
                }

                using (k)
                {
                    ctx.IncrementRegistryKeys();
                    if (k.ValueCount == 0 && k.SubKeyCount == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Forensic Registry Key Empty",
                            Risk = RiskLevel.Critical,
                            Location = $"HKCU\\{w}",
                            Reason = "Key exists but has zero values and zero subkeys.",
                            Detail = "Cleaner emptied the key while leaving its skeleton.",
                        });
                    }
                }
            }
        }, ct);

    private Task CheckRecentEventLogClearing(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string logsDir = Path.Combine(Environment.SystemDirectory, "winevt", "Logs");
            if (!Directory.Exists(logsDir)) return;

            DateTime now = DateTime.UtcNow;
            string[] high = { "Security.evtx", "System.evtx", "Application.evtx" };

            foreach (var f in high)
            {
                ct.ThrowIfCancellationRequested();
                string p = Path.Combine(logsDir, f);
                if (!File.Exists(p)) continue;
                ctx.IncrementFiles();

                DateTime mod;
                long len;
                try
                {
                    var info = new FileInfo(p);
                    mod = info.LastWriteTimeUtc;
                    len = info.Length;
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                bool tiny = len < 70000;
                bool freshMod = (now - mod).TotalDays < 7;

                if (tiny && freshMod)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Event Log Recently Cleared",
                        Risk = RiskLevel.Critical,
                        Location = p,
                        FileName = f,
                        Reason = $"{f} is {len} bytes and was last written {(now - mod).TotalHours:F1} hours ago.",
                        Detail = "Empty + fresh modification = `wevtutil cl` was run recently.",
                    });
                }
            }
        }, ct);

    private Task CheckRecentlyModifiedSystemFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            DateTime now = DateTime.UtcNow;

            string[] watched =
            {
                @"C:\Windows\System32\drivers\etc\hosts",
                @"C:\Windows\System32\drivers\MsftDriverBlockList.sys",
                @"C:\Windows\System32\Tasks",
            };

            foreach (var w in watched)
            {
                ct.ThrowIfCancellationRequested();
                if (!File.Exists(w) && !Directory.Exists(w)) continue;

                DateTime mod;
                try
                {
                    mod = File.Exists(w)
                        ? File.GetLastWriteTimeUtc(w)
                        : Directory.GetLastWriteTimeUtc(w);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                if ((now - mod).TotalDays >= 7) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Sensitive System File / Folder Recently Modified",
                    Risk = RiskLevel.High,
                    Location = w,
                    FileName = Path.GetFileName(w),
                    Reason = $"Modified {(now - mod).TotalHours:F1} hours ago.",
                    Detail = "Recent edits to security-relevant paths suggest active bypass / cleaning workflow.",
                });
            }
        }, ct);

    private Task CheckPagefileCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
            RegistryKey? k;
            try { k = Registry.LocalMachine.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                object? clr;
                try { clr = k.GetValue("ClearPageFileAtShutdown"); }
                catch (System.Security.SecurityException) { return; }

                if (clr is int i && i == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Pagefile Wipe-on-Shutdown ACTIVE",
                        Risk = RiskLevel.High,
                        Location = $"HKLM\\{p}\\ClearPageFileAtShutdown",
                        Reason = "ClearPageFileAtShutdown = 1.",
                        Detail = "Windows wipes pagefile on every shutdown — disables memory forensics.",
                    });
                }
            }
        }, ct);

    private Task CheckSwapfileCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string swap = @"C:\swapfile.sys";
            if (!File.Exists(swap)) return;
            ctx.IncrementFiles();

            try
            {
                var info = new FileInfo(swap);
                if (info.Length == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Swapfile Empty",
                        Risk = RiskLevel.Medium,
                        Location = swap,
                        Reason = "swapfile.sys exists but is 0 bytes.",
                        Detail = "Swapfile cleared — anti-forensic memory wipe.",
                    });
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckHiberfileCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string hiber = @"C:\hiberfil.sys";
            if (!File.Exists(hiber)) return;
            ctx.IncrementFiles();

            try
            {
                var info = new FileInfo(hiber);
                if (info.Length == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Hiberfile Empty",
                        Risk = RiskLevel.High,
                        Location = hiber,
                        Reason = "hiberfil.sys exists but is 0 bytes.",
                        Detail = "Hibernation file emptied — destroys post-hibernation memory forensics.",
                    });
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }, ct);

    private Task CheckRecentSdeleteUsage(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SOFTWARE\Sysinternals\SDelete";
            RegistryKey? k;
            try { k = Registry.CurrentUser.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "SDelete EULA Accepted — Secure-Delete Was Run",
                    Risk = RiskLevel.High,
                    Location = $"HKCU\\{p}",
                    Reason = "Sysinternals SDelete registry key present.",
                    Detail = "SDelete securely overwrites files — eliminates forensic recoverability.",
                });
            }
        }, ct);

    private Task CheckRecentCipherUsage(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string psHistory = Path.Combine(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
            if (!File.Exists(psHistory)) return;
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(psHistory, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            if (content.Contains("cipher /w", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "cipher.exe /w Free-Space Wipe Detected",
                    Risk = RiskLevel.Critical,
                    Location = psHistory,
                    Reason = "PS history contains `cipher /w`.",
                    Detail = "Wipes free disk space — destroys recently-deleted file recovery evidence.",
                });
            }
        }, ct);

    private Task CheckBleachBitTraces(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] roots =
            {
                Environment.GetEnvironmentVariable("PROGRAMFILES") ?? string.Empty,
                Environment.GetEnvironmentVariable("PROGRAMFILES(X86)") ?? string.Empty,
                Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? string.Empty,
                Environment.GetEnvironmentVariable("APPDATA") ?? string.Empty,
            };

            foreach (var r in roots)
            {
                if (string.IsNullOrEmpty(r)) continue;
                string p = Path.Combine(r, "BleachBit");
                if (!Directory.Exists(p)) continue;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "BleachBit Installed",
                    Risk = RiskLevel.High,
                    Location = p,
                    Reason = "BleachBit installation directory found.",
                    Detail = "Open-source cleaner used for log/cache/freespace wiping.",
                });
            }
        }, ct);

    private Task CheckCcleanerTraces(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] paths =
            {
                @"SOFTWARE\Piriform\CCleaner",
                @"SOFTWARE\WOW6432Node\Piriform\CCleaner",
            };

            foreach (var p in paths)
            {
                foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    ct.ThrowIfCancellationRequested();
                    RegistryKey? k;
                    try { k = hive.OpenSubKey(p); }
                    catch (System.Security.SecurityException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }
                    if (k == null) continue;

                    using (k)
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "CCleaner Installed / Used",
                            Risk = RiskLevel.High,
                            Location = $"{hive.Name}\\{p}",
                            Reason = "CCleaner registry key present.",
                            Detail = "Piriform CCleaner used for log/cache wiping.",
                        });
                    }
                }
            }
        }, ct);

    private Task CheckPrivazerTraces(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] paths =
            {
                @"SOFTWARE\Privazer",
                @"SOFTWARE\WOW6432Node\Privazer",
                @"SOFTWARE\Goversoft\Privazer",
            };

            foreach (var p in paths)
            {
                foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    ct.ThrowIfCancellationRequested();
                    RegistryKey? k;
                    try { k = hive.OpenSubKey(p); }
                    catch (System.Security.SecurityException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }
                    if (k == null) continue;

                    using (k)
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "PrivaZer Installed / Used",
                            Risk = RiskLevel.High,
                            Location = $"{hive.Name}\\{p}",
                            Reason = "PrivaZer registry key present.",
                            Detail = "PrivaZer is a privacy cleaner — wipes traces, USN, MFT, browser history.",
                        });
                    }
                }
            }
        }, ct);

    private Task CheckTakeOwnAndIcaclsUsage(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string ps = Path.Combine(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
            if (!File.Exists(ps)) return;
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(ps, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            string[] cmds = { "takeown /f", "icacls", "attrib -h", "attrib -s" };
            foreach (var c in cmds)
            {
                if (!content.Contains(c, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Privilege-Escalation Command in PS History: {c}",
                    Risk = RiskLevel.High,
                    Location = ps,
                    Reason = $"PS history contains '{c}'.",
                    Detail = "Cleaners use takeown/icacls to unlock protected files before deletion.",
                });
            }
        }, ct);

    private Task CheckRecentFsutilUsage(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string ps = Path.Combine(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
            if (!File.Exists(ps)) return;
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(ps, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            if (content.Contains("fsutil usn deletejournal", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "USN Journal Deletion Command",
                    Risk = RiskLevel.Critical,
                    Location = ps,
                    Reason = "PS history contains `fsutil usn deletejournal`.",
                    Detail = "Deletes the NTFS USN journal — destroys file-change forensic timeline.",
                });
            }
        }, ct);

    private Task CheckRecentWevtutilUsage(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string ps = Path.Combine(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
            if (!File.Exists(ps)) return;
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(ps, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            if (content.Contains("wevtutil cl", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Event Log Clear Command Executed",
                    Risk = RiskLevel.Critical,
                    Location = ps,
                    Reason = "PS history contains `wevtutil cl`.",
                    Detail = "Clears Windows event logs — destroys system/security event forensics.",
                });
            }
        }, ct);

    private Task CheckRecentNetshUsage(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string ps = Path.Combine(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
            if (!File.Exists(ps)) return;
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(ps, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            string[] cmds =
            {
                "netsh wlan delete profile", "netsh advfirewall reset",
                "netsh int ip reset", "netsh winsock reset",
                "netsh advfirewall set allprofiles state off",
            };

            foreach (var c in cmds)
            {
                if (!content.Contains(c, StringComparison.OrdinalIgnoreCase)) continue;
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Network Cleanup / Reset Command: {c}",
                    Risk = RiskLevel.Medium,
                    Location = ps,
                    Reason = $"PS history contains '{c}'.",
                    Detail = "Resets network state — used to clear connection history / IP traces.",
                });
            }
        }, ct);

    private Task CheckRecentlyClearedDnsCache(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string ps = Path.Combine(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
            if (!File.Exists(ps)) return;
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(ps, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            if (content.Contains("ipconfig /flushdns", StringComparison.OrdinalIgnoreCase) ||
                content.Contains("Clear-DnsClientCache", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "DNS Cache Flushed",
                    Risk = RiskLevel.Low,
                    Location = ps,
                    Reason = "PS history shows DNS flush command.",
                    Detail = "Clears resolved domain history — minor anti-forensic step.",
                });
            }
        }, ct);

    private Task CheckArpCacheCleared(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string ps = Path.Combine(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt");
            if (!File.Exists(ps)) return;
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(ps, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            if (content.Contains("arp -d", StringComparison.OrdinalIgnoreCase))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "ARP Cache Cleared",
                    Risk = RiskLevel.Low,
                    Location = ps,
                    Reason = "PS history shows `arp -d`.",
                    Detail = "Clears recent network neighbors — minor anti-forensic step.",
                });
            }
        }, ct);

    private Task CheckRecentlyCreatedSpooferKeys(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] watched =
            {
                @"HARDWARE\DESCRIPTION\System\BIOS",
                @"HARDWARE\DESCRIPTION\System",
            };

            foreach (var w in watched)
            {
                ct.ThrowIfCancellationRequested();
                RegistryKey? k;
                try { k = Registry.LocalMachine.OpenSubKey(w); }
                catch (System.Security.SecurityException) { continue; }
                catch (UnauthorizedAccessException) { continue; }
                if (k == null) continue;

                using (k)
                {
                    ctx.IncrementRegistryKeys();
                    string[] vals;
                    try { vals = k.GetValueNames(); }
                    catch (System.Security.SecurityException) { continue; }

                    foreach (var v in vals)
                    {
                        ct.ThrowIfCancellationRequested();
                        object? data;
                        try { data = k.GetValue(v); }
                        catch (System.Security.SecurityException) { continue; }

                        if (data is string s)
                        {
                            if (s.Equals("0", StringComparison.OrdinalIgnoreCase) ||
                                s.Equals("00000000-0000-0000-0000-000000000000", StringComparison.OrdinalIgnoreCase) ||
                                s.Equals("To Be Filled By O.E.M.", StringComparison.OrdinalIgnoreCase) ||
                                s.Equals("Default string", StringComparison.OrdinalIgnoreCase) ||
                                s.Equals("System Serial Number", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Spoofed / Default BIOS Identifier",
                                    Risk = RiskLevel.High,
                                    Location = $"HKLM\\{w}\\{v}",
                                    Reason = $"BIOS value '{v}' is set to default / placeholder: '{s}'",
                                    Detail = "SMBIOS spoofer typically resets values to OEM placeholders.",
                                });
                            }
                        }
                    }
                }
            }
        }, ct);

    private Task CheckTimestompUtilityArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var dirs = new List<string>();
            string[] envs = { "TEMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE" };
            foreach (var e in envs)
            {
                var v = Environment.GetEnvironmentVariable(e);
                if (!string.IsNullOrEmpty(v)) dirs.Add(v);
            }

            string[] tools = { "timestomp.exe", "setmace.exe", "nt_timestomp.exe", "fileinsight.exe", "robocopy.exe" };

            foreach (var dir in dirs.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var f in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    string name = Path.GetFileName(f);
                    foreach (var t in tools)
                    {
                        if (!name.Equals(t, StringComparison.OrdinalIgnoreCase)) continue;
                        if (t.Equals("robocopy.exe", StringComparison.OrdinalIgnoreCase) &&
                            f.StartsWith(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Timestomp / Timestamp Utility Present",
                            Risk = RiskLevel.High,
                            Location = f,
                            FileName = name,
                            Reason = $"Timestamp manipulation utility found: {name}",
                            Detail = "Used to forge file MAC times — destroys timeline forensics.",
                        });
                        break;
                    }
                }
            }
        }, ct);
}
