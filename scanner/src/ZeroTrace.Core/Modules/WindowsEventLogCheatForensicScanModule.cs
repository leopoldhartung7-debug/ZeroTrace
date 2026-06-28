using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

public sealed class WindowsEventLogCheatForensicScanModule : IScanModule
{
    public string Name => "Windows Event Log Cheat Forensic Scan";
    public double Weight => 4.0;
    public int ParallelGroup => 5;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] CheatProcessNames =
    [
        "cheat", "hack", "aimbot", "wallhack", "esp", "bypass", "inject",
        "godmode", "noclip", "speedhack", "trainer", "modmenu", "exploiter",
        "fivem_cheat", "fivem_hack", "fivem_bypass", "cfx_cheat", "cfx_bypass",
        "altv_cheat", "altv_hack", "altv_bypass", "ragemp_cheat", "ragemp_hack",
        "gta5_cheat", "gta5_hack", "gta5_bypass", "gta_cheat", "gta_hack",
        "cs2_cheat", "cs2_aimbot", "vac_bypass", "apex_cheat", "apex_aimbot",
        "valorant_cheat", "valorant_bypass", "vanguard_bypass", "vgc_kill",
        "warzone_cheat", "wz_cheat", "pubg_cheat", "pubg_aimbot",
        "dayz_cheat", "rust_cheat", "ark_cheat", "minecraft_cheat",
        "eft_cheat", "tarkov_cheat", "r6_cheat", "siege_cheat",
        "maphack", "triggerbot", "bunnyhop", "bhop", "recoil_script",
        "kdmapper", "turla", "dsefix", "eac_bypass", "be_bypass",
        "scyllahide", "x64dbg_bypass", "hexrays_patch", "themida_bypass",
        "lmaobox", "skeet", "neverlose", "gamesense", "fatality", "hvh",
        "cheater", "chts", "exploit", "scriptkiddie",
    ];

    private static readonly string[] CheatServiceNames =
    [
        "fivem_cheat", "fivem_bypass", "cfx_bypass", "altv_cheat", "ragemp_cheat",
        "vac_bypass", "eac_bypass", "be_bypass", "vgc_kill", "vanguard_kill",
        "kdmapper_svc", "byovd_driver", "cheat_loader", "hack_driver",
        "bypass_driver", "inject_driver", "rootkit_svc", "kernel_bypass",
    ];

    private static readonly string[] KnownCheatFileHashes =
    [
        "lmaobox", "skeet.cc", "neverlose.cc", "aimware", "gamesense", "fatality.win",
        "interwebz", "hvh.ru", "csgocheat", "cs2hack", "fivemhack", "altvcheats",
        "ragempcheat", "fivembypass", "cfxbypass",
    ];

    private static readonly string[] SuspiciousAppCompatNames =
    [
        "cheat", "hack", "aimbot", "bypass", "inject", "exploit",
        "godmode", "noclip", "speedhack", "trainer", "modmenu",
        "fivem_cheat", "altv_cheat", "ragemp_cheat", "gta5_cheat",
        "eac_bypass", "be_bypass", "vac_bypass", "vanguard_bypass",
        "kdmapper", "dsefix", "bsod_bypass", "ci_bypass",
        "lmaobox", "skeet", "gamesense", "neverlose", "fatality",
    ];

    private static readonly string[] SuspiciousScheduledTaskKeywords =
    [
        "cheat", "hack", "aimbot", "bypass", "inject", "exploit", "godmode",
        "noclip", "speedhack", "trainer", "fivem_cheat", "altv_cheat",
        "ragemp_cheat", "gta5_cheat", "eac_bypass", "be_bypass", "vac_bypass",
        "lmaobox", "skeet", "gamesense", "cheat_loader", "hack_loader",
    ];

    private static readonly string[] PrefetchCheatNames =
    [
        "FIVEM_CHEAT.EXE", "FIVEM_HACK.EXE", "FIVEM_BYPASS.EXE", "CFX_CHEAT.EXE",
        "ALTV_CHEAT.EXE", "ALTV_HACK.EXE", "RAGEMP_CHEAT.EXE", "RAGEMP_HACK.EXE",
        "GTA5_CHEAT.EXE", "GTA5_HACK.EXE", "AIMBOT.EXE", "WALLHACK.EXE",
        "ESP.EXE", "GODMODE.EXE", "NOCLIP.EXE", "SPEEDHACK.EXE",
        "VAC_BYPASS.EXE", "EAC_BYPASS.EXE", "BE_BYPASS.EXE", "VANGUARD_BYPASS.EXE",
        "KDMAPPER.EXE", "DSEFIX.EXE", "TURLA.EXE", "BYPASS.EXE",
        "INJECT.EXE", "INJECTOR.EXE", "DLL_INJECT.EXE", "MODMENU.EXE",
        "TRAINER.EXE", "CHEATER.EXE", "EXPLOIT.EXE", "EXPLOITER.EXE",
        "LMAOBOX.EXE", "SKEET.EXE", "GAMESENSE.EXE", "NEVERLOSE.EXE", "FATALITY.EXE",
        "CS2_CHEAT.EXE", "APEX_CHEAT.EXE", "VALORANT_CHEAT.EXE", "WARZONE_CHEAT.EXE",
        "PUBG_CHEAT.EXE", "RUST_CHEAT.EXE", "EFT_CHEAT.EXE", "TARKOV_CHEAT.EXE",
    ];

    private static readonly string[] AppCompatCachePaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "AppCompat", "Programs", "Amcache.hve"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "AppCompat", "Programs", "Amcache.hve"),
    ];

    private static readonly string[] PrefetchFolderPaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "..", "Prefetch"),
    ];

    private static readonly string[] ScheduledTaskXmlPaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "SysWOW64", "Tasks"),
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckSecurityEventLogProcessCreation(ctx, ct),
            CheckSystemEventLogForCheatServices(ctx, ct),
            CheckApplicationEventLogForCheatErrors(ctx, ct),
            CheckPrefetchForCheatExecutables(ctx, ct),
            CheckScheduledTasksForCheats(ctx, ct),
            CheckAppCompatShimsForCheats(ctx, ct),
            CheckWindowsFirewallLogForCheatTraffic(ctx, ct),
            CheckPowerShellEventLogForCheatCommands(ctx, ct),
            CheckWindowsDefenderEventLogForCheatDetections(ctx, ct),
            CheckDriverLoadEventLogForBypassDrivers(ctx, ct),
            CheckSrumDatabaseForCheatApps(ctx, ct),
            CheckEventLogTamperingArtifacts(ctx, ct),
            CheckUserAssistForCheatTools(ctx, ct),
            CheckMuiCacheForCheatTools(ctx, ct)
        );
    }

    private Task CheckSecurityEventLogProcessCreation(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName,
                "*[System[(EventID=4688)]]"));
            EventRecord record;
            int evtCount = 0;
            while ((record = reader.ReadEvent()) != null && evtCount < 5000 && !ct.IsCancellationRequested)
            {
                evtCount++;
                try
                {
                    var desc = record.FormatDescription() ?? string.Empty;
                    var lower = desc.ToLowerInvariant();
                    foreach (var name in CheatProcessNames)
                    {
                        if (lower.Contains(name.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Process creation event for cheat tool",
                                Risk = Risk.High,
                                Location = "Windows Security Event Log (Event ID 4688)",
                                FileName = name,
                                Reason = $"Security audit log recorded creation of process matching cheat name: '{name}'",
                                Detail = $"Event Time: {record.TimeCreated}, Description snippet recorded"
                            });
                            break;
                        }
                    }
                }
                catch (Exception) { }
                finally { record.Dispose(); }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckSystemEventLogForCheatServices(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var reader = new EventLogReader(new EventLogQuery("System", PathType.LogName,
                "*[System[(EventID=7045 or EventID=7040 or EventID=7036)]]"));
            EventRecord record;
            int evtCount = 0;
            while ((record = reader.ReadEvent()) != null && evtCount < 3000 && !ct.IsCancellationRequested)
            {
                evtCount++;
                try
                {
                    var desc = record.FormatDescription() ?? string.Empty;
                    var lower = desc.ToLowerInvariant();
                    foreach (var svcName in CheatServiceNames)
                    {
                        if (lower.Contains(svcName.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat service installation event",
                                Risk = Risk.Critical,
                                Location = "Windows System Event Log (Event ID 7045/7040/7036)",
                                FileName = svcName,
                                Reason = $"System log recorded installation or state change of cheat service: '{svcName}'",
                                Detail = $"Event ID: {record.Id}, Time: {record.TimeCreated}"
                            });
                            break;
                        }
                    }
                    // Also check for kernel driver loading via event 7045
                    if (record.Id == 7045)
                    {
                        foreach (var driverKw in new[] { "bypass.sys", "cheat.sys", "hack.sys", "exploit.sys", "inject.sys", "bypass_drv", "cheat_drv" })
                        {
                            if (lower.Contains(driverKw.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Cheat kernel driver service installation",
                                    Risk = Risk.Critical,
                                    Location = "Windows System Event Log (Event ID 7045)",
                                    FileName = driverKw,
                                    Reason = $"System log recorded kernel driver service installation with cheat keyword: '{driverKw}'",
                                    Detail = $"Time: {record.TimeCreated}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (Exception) { }
                finally { record.Dispose(); }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckApplicationEventLogForCheatErrors(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var reader = new EventLogReader(new EventLogQuery("Application", PathType.LogName,
                "*[System[(EventID=1000 or EventID=1001 or EventID=1002)]]"));
            EventRecord record;
            int evtCount = 0;
            while ((record = reader.ReadEvent()) != null && evtCount < 3000 && !ct.IsCancellationRequested)
            {
                evtCount++;
                try
                {
                    var desc = record.FormatDescription() ?? string.Empty;
                    var lower = desc.ToLowerInvariant();
                    foreach (var name in CheatProcessNames)
                    {
                        if (lower.Contains(name.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat tool application crash event",
                                Risk = Risk.Medium,
                                Location = "Windows Application Event Log (Event ID 1000/1001/1002)",
                                FileName = name,
                                Reason = $"Application event log records crash or error from cheat process: '{name}'",
                                Detail = $"Event ID: {record.Id}, Time: {record.TimeCreated}"
                            });
                            break;
                        }
                    }
                }
                catch (Exception) { }
                finally { record.Dispose(); }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckPrefetchForCheatExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var prefetchDir in PrefetchFolderPaths)
        {
            if (!Directory.Exists(prefetchDir)) continue;
            try
            {
                foreach (var pf in Directory.EnumerateFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
                {
                    ctx.IncrementFiles();
                    var fn = Path.GetFileNameWithoutExtension(pf).ToUpperInvariant();
                    if (PrefetchCheatNames.Any(k => fn.StartsWith(k.Replace(".EXE", ""), StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat executable prefetch record",
                            Risk = Risk.High,
                            Location = prefetchDir,
                            FileName = Path.GetFileName(pf),
                            Reason = $"Windows Prefetch records execution of cheat executable: {fn}",
                            Detail = $"Prefetch file: {pf}"
                        });
                    }
                    else
                    {
                        // Heuristic: check for common cheat keywords in prefetch filename
                        var lower = fn.ToLowerInvariant();
                        if ((lower.Contains("cheat") || lower.Contains("hack") || lower.Contains("bypass") ||
                             lower.Contains("aimbot") || lower.Contains("wallhack") || lower.Contains("godmode") ||
                             lower.Contains("exploit") || lower.Contains("inject") || lower.Contains("noclip") ||
                             lower.Contains("speedhack") || lower.Contains("trainer") || lower.Contains("modmenu") ||
                             lower.Contains("eac_bypass") || lower.Contains("be_bypass") || lower.Contains("vac_bypass") ||
                             lower.Contains("lmaobox") || lower.Contains("skeet") || lower.Contains("gamesense")) &&
                            fn.EndsWith(".EXE", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Suspicious prefetch entry (cheat keyword)",
                                Risk = Risk.High,
                                Location = prefetchDir,
                                FileName = Path.GetFileName(pf),
                                Reason = $"Prefetch record contains cheat-related keyword: {fn}",
                                Detail = $"Prefetch file: {pf}"
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckScheduledTasksForCheats(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var taskDir in ScheduledTaskXmlPaths)
        {
            if (!Directory.Exists(taskDir)) continue;
            try
            {
                foreach (var taskFile in Directory.EnumerateFiles(taskDir, "*", SearchOption.AllDirectories))
                {
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(taskFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        foreach (var kw in SuspiciousScheduledTaskKeywords)
                        {
                            if (lower.Contains(kw.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Cheat-related scheduled task",
                                    Risk = Risk.High,
                                    Location = Path.GetDirectoryName(taskFile) ?? taskDir,
                                    FileName = Path.GetFileName(taskFile),
                                    Reason = $"Scheduled task XML references cheat keyword: '{kw}'",
                                    Detail = $"Task: {taskFile}"
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
    }, ct);

    private Task CheckAppCompatShimsForCheats(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string shimsPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(shimsPath);
            if (key != null)
            {
                foreach (var valName in key.GetValueNames())
                {
                    ctx.IncrementRegistryKeys();
                    var lower = valName.ToLowerInvariant();
                    if (CheatProcessNames.Any(k => lower.Contains(k.ToLowerInvariant())))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "AppCompat shim for cheat process",
                            Risk = Risk.High,
                            Location = @"HKCU\" + shimsPath,
                            FileName = Path.GetFileName(valName),
                            Reason = "Application compatibility shim (Layers) registered for process with cheat name",
                            Detail = $"Value: {valName}"
                        });
                    }
                }
            }
        }
        catch (Exception) { }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(shimsPath);
            if (key != null)
            {
                foreach (var valName in key.GetValueNames())
                {
                    ctx.IncrementRegistryKeys();
                    var lower = valName.ToLowerInvariant();
                    if (CheatProcessNames.Any(k => lower.Contains(k.ToLowerInvariant())))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "AppCompat shim for cheat process (HKLM)",
                            Risk = Risk.High,
                            Location = @"HKLM\" + shimsPath,
                            FileName = Path.GetFileName(valName),
                            Reason = "System-level AppCompat shim registered for process with cheat name",
                            Detail = $"Value: {valName}"
                        });
                    }
                }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckWindowsFirewallLogForCheatTraffic(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var firewallLogPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "LogFiles", "Firewall", "pfirewall.log");
        if (!File.Exists(firewallLogPath)) return;
        try
        {
            ctx.IncrementFiles();
            using var fs = new FileStream(firewallLogPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sr = new StreamReader(fs);
            string content = await sr.ReadToEndAsync(ct);
            var lower = content.ToLowerInvariant();
            // Check for known cheat cloud service ports
            var cheatPorts = new[] { "28003", "28004", "7777", "12345", "54321", "31415", "9999", "8888" };
            foreach (var port in cheatPorts)
            {
                if (lower.Contains($" {port} ") || lower.Contains($"\t{port}\t"))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Firewall log: known cheat cloud port",
                        Risk = Risk.Medium,
                        Location = firewallLogPath,
                        FileName = "pfirewall.log",
                        Reason = $"Windows Firewall log shows traffic on known cheat cloud service port: {port}",
                        Detail = $"Port {port} seen in firewall log"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckPowerShellEventLogForCheatCommands(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var reader = new EventLogReader(new EventLogQuery("Microsoft-Windows-PowerShell/Operational",
                PathType.LogName, "*[System[(EventID=4103 or EventID=4104)]]"));
            EventRecord record;
            int evtCount = 0;
            while ((record = reader.ReadEvent()) != null && evtCount < 2000 && !ct.IsCancellationRequested)
            {
                evtCount++;
                try
                {
                    var desc = record.FormatDescription() ?? string.Empty;
                    var lower = desc.ToLowerInvariant();
                    bool isCheat = CheatProcessNames.Any(k => lower.Contains(k.ToLowerInvariant()))
                        || lower.Contains("sc create") && lower.Contains("kernel")
                        || lower.Contains("bcdedit") && lower.Contains("testsigning")
                        || lower.Contains("disable driver signature")
                        || lower.Contains("bypass anticheat") || lower.Contains("disable eac")
                        || lower.Contains("disable battleye") || lower.Contains("stop vanguard");
                    if (isCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "PowerShell event log: cheat-related command",
                            Risk = Risk.High,
                            Location = "Microsoft-Windows-PowerShell/Operational Event Log",
                            FileName = string.Empty,
                            Reason = "PowerShell script block or command execution log references cheat tool or bypass technique",
                            Detail = $"Event ID: {record.Id}, Time: {record.TimeCreated}"
                        });
                    }
                }
                catch (Exception) { }
                finally { record.Dispose(); }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckWindowsDefenderEventLogForCheatDetections(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var reader = new EventLogReader(new EventLogQuery("Microsoft-Windows-Windows Defender/Operational",
                PathType.LogName, "*[System[(EventID=1116 or EventID=1117 or EventID=1006 or EventID=1007)]]"));
            EventRecord record;
            int evtCount = 0;
            while ((record = reader.ReadEvent()) != null && evtCount < 2000 && !ct.IsCancellationRequested)
            {
                evtCount++;
                try
                {
                    var desc = record.FormatDescription() ?? string.Empty;
                    var lower = desc.ToLowerInvariant();
                    bool isCheat = lower.Contains("cheat") || lower.Contains("hack") || lower.Contains("aimbot")
                        || lower.Contains("bypass") || lower.Contains("inject") || lower.Contains("exploit")
                        || lower.Contains("trainer") || lower.Contains("lmaobox") || lower.Contains("skeet")
                        || lower.Contains("gamesense") || lower.Contains("neverlose") || lower.Contains("fatality")
                        || lower.Contains("hvh") || lower.Contains("cheater")
                        || CheatProcessNames.Any(k => lower.Contains(k.ToLowerInvariant()));
                    if (isCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Windows Defender detected cheat-related threat",
                            Risk = Risk.High,
                            Location = "Microsoft-Windows-Windows Defender/Operational Event Log",
                            FileName = string.Empty,
                            Reason = "Windows Defender event log records detection or quarantine of cheat-related threat",
                            Detail = $"Event ID: {record.Id}, Time: {record.TimeCreated}"
                        });
                    }
                }
                catch (Exception) { }
                finally { record.Dispose(); }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckDriverLoadEventLogForBypassDrivers(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        try
        {
            using var reader = new EventLogReader(new EventLogQuery("System", PathType.LogName,
                "*[System[(EventID=219)]]"));
            EventRecord record;
            int evtCount = 0;
            while ((record = reader.ReadEvent()) != null && evtCount < 2000 && !ct.IsCancellationRequested)
            {
                evtCount++;
                try
                {
                    var desc = record.FormatDescription() ?? string.Empty;
                    var lower = desc.ToLowerInvariant();
                    var bypassDriverNames = new[] {
                        "gdrv.sys", "winring0", "dbutil", "rtcore64", "mhyprot", "iqvw64e",
                        "kdmapper", "bypass.sys", "cheat.sys", "hack.sys", "exploit.sys",
                        "fivem_km", "cfx_bypass", "altv_bypass", "ragemp_bypass",
                        "dsefix", "turla", "capcom.sys", "unknowncheats.sys"
                    };
                    foreach (var drv in bypassDriverNames)
                    {
                        if (lower.Contains(drv.ToLowerInvariant()))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Bypass/cheat driver load event",
                                Risk = Risk.Critical,
                                Location = "Windows System Event Log (Event ID 219 - Driver Load Failed/Blocked)",
                                FileName = drv,
                                Reason = $"System event log records loading (or blocked load) of bypass/cheat driver: '{drv}'",
                                Detail = $"Time: {record.TimeCreated}"
                            });
                            break;
                        }
                    }
                }
                catch (Exception) { }
                finally { record.Dispose(); }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckSrumDatabaseForCheatApps(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var srumPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "sru", "SRUDB.dat");
        if (!File.Exists(srumPath)) return;
        // SRUM database (System Resource Usage Monitor) — can't directly parse ESE format
        // but we check if the file exists and note it for forensic value
        ctx.IncrementFiles();
        // We can check if any common cheat .exe names appear in the registry SRUM entries
        const string srumPath2 = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions\{5C8CF1C7-7257-4F13-B223-970EF5939312}";
        try
        {
            using var srum = Registry.LocalMachine.OpenSubKey(srumPath2);
            if (srum != null)
            {
                foreach (var valName in srum.GetValueNames())
                {
                    ctx.IncrementRegistryKeys();
                    var lower = valName.ToLowerInvariant();
                    if (CheatProcessNames.Any(k => lower.Contains(k.ToLowerInvariant())))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "SRUM database cheat app reference",
                            Risk = Risk.Medium,
                            Location = @"HKLM\" + srumPath2,
                            FileName = valName,
                            Reason = "System Resource Usage Monitor (SRUM) contains reference to cheat application",
                            Detail = $"SRUM entry: {valName}"
                        });
                    }
                }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckEventLogTamperingArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        // Check if Security event log has been cleared (Event ID 1102)
        try
        {
            using var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName,
                "*[System[(EventID=1102)]]"));
            EventRecord record;
            while ((record = reader.ReadEvent()) != null && !ct.IsCancellationRequested)
            {
                try
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Security event log was cleared",
                        Risk = Risk.High,
                        Location = "Windows Security Event Log (Event ID 1102)",
                        FileName = string.Empty,
                        Reason = "Security audit log was cleared — common technique to hide cheat tool activity",
                        Detail = $"Log clear event at: {record.TimeCreated}"
                    });
                }
                catch (Exception) { }
                finally { record.Dispose(); }
            }
        }
        catch (Exception) { }

        // Check if System log was cleared (Event ID 104)
        try
        {
            using var reader = new EventLogReader(new EventLogQuery("System", PathType.LogName,
                "*[System[(EventID=104)]]"));
            EventRecord record;
            while ((record = reader.ReadEvent()) != null && !ct.IsCancellationRequested)
            {
                try
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "System event log was cleared",
                        Risk = Risk.Medium,
                        Location = "Windows System Event Log (Event ID 104)",
                        FileName = string.Empty,
                        Reason = "System event log was cleared — may indicate attempt to hide cheat driver installation",
                        Detail = $"Log clear event at: {record.TimeCreated}"
                    });
                }
                catch (Exception) { }
                finally { record.Dispose(); }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckUserAssistForCheatTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string uaPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        try
        {
            using var ua = Registry.CurrentUser.OpenSubKey(uaPath);
            if (ua == null) return;
            foreach (var guidName in ua.GetSubKeyNames())
            {
                try
                {
                    using var count = Registry.CurrentUser.OpenSubKey($@"{uaPath}\{guidName}\Count");
                    if (count == null) continue;
                    foreach (var valName in count.GetValueNames())
                    {
                        ctx.IncrementRegistryKeys();
                        var decoded = Rot13Decode(valName).ToLowerInvariant();
                        bool isCheat = CheatProcessNames.Any(k => decoded.Contains(k.ToLowerInvariant()));
                        if (isCheat)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat tool execution (UserAssist)",
                                Risk = Risk.High,
                                Location = $@"HKCU\{uaPath}\{guidName}\Count",
                                FileName = decoded,
                                Reason = "UserAssist registry records execution of cheat/bypass tool",
                                Detail = $"Decoded: {decoded}"
                            });
                        }
                    }
                }
                catch (Exception) { }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckMuiCacheForCheatTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var muiPaths = new[]
        {
            @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            @"SOFTWARE\Microsoft\Windows\ShellNoRoam\MUICache",
        };
        foreach (var muiPath in muiPaths)
        {
            try
            {
                using var mui = Registry.CurrentUser.OpenSubKey(muiPath);
                if (mui == null) continue;
                foreach (var valName in mui.GetValueNames())
                {
                    ctx.IncrementRegistryKeys();
                    var lower = valName.ToLowerInvariant();
                    bool isCheat = CheatProcessNames.Any(k => lower.Contains(k.ToLowerInvariant()));
                    if (isCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cheat tool execution (MUICache)",
                            Risk = Risk.High,
                            Location = @"HKCU\" + muiPath,
                            FileName = Path.GetFileName(valName),
                            Reason = "MUICache records execution of cheat/bypass tool",
                            Detail = $"Entry: {valName}"
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private static string Rot13Decode(string s)
    {
        return new string(s.Select(c =>
            c >= 'a' && c <= 'z' ? (char)('a' + (c - 'a' + 13) % 26) :
            c >= 'A' && c <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) : c).ToArray());
    }
}
