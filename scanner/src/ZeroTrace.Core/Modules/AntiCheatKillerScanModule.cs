using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AntiCheatKillerScanModule : IScanModule
{
    public string Name => "Anti-Cheat Killer/Disabler Detection";
    public double Weight => 4.8;
    public int ParallelGroup => 3;

    private static readonly string[] KnownKillerExeNames =
    [
        "ac_killer.exe", "anticheat_killer.exe", "anti_cheat_killer.exe",
        "ac_kill.exe", "kill_ac.exe", "kill_anticheat.exe",
        "kill_eac.exe", "kill_be.exe", "kill_vac.exe", "kill_vanguard.exe",
        "kill_battleye.exe", "eac_kill.exe", "be_kill.exe",
        "vac_kill.exe", "vanguard_kill.exe", "ricochet_kill.exe",
        "xigncode_kill.exe", "gameguard_kill.exe", "nprotect_kill.exe",
        "hackshield_kill.exe", "ahnlab_kill.exe", "frost_kill.exe",
        "mhyprot_kill.exe", "mhyprot2_kill.exe",
        "ac_terminator.exe", "ac_suspend.exe", "ac_freeze.exe",
        "ac_blocker.exe", "anticheat_blocker.exe", "ac_bypass_kill.exe",
        "process_killer.exe", "proc_killer.exe", "service_killer.exe",
        "driver_killer.exe", "kill_driver.exe", "kill_service.exe",
        "kill_process.exe", "terminate_ac.exe", "terminate_anticheat.exe",
        "task_killer.exe", "force_kill.exe", "process_terminate.exe",
        "bypass_kill.exe", "kill_bypass.exe", "remove_ac.exe",
        "unload_ac.exe", "ac_unload.exe", "ac_disable.exe",
        "disable_ac.exe", "disable_eac.exe", "disable_be.exe",
        "disable_vac.exe", "disable_vanguard.exe",
        "ac_killer_v2.exe", "ac_killer_pro.exe", "ac_killer_plus.exe",
        "stealth_killer.exe", "hidden_killer.exe", "ghost_killer.exe",
        "phantom_killer.exe", "shadow_killer.exe",
        "eac_suspend.exe", "be_suspend.exe", "vac_suspend.exe",
        "ac_suspend_tool.exe", "anticheat_suspend.exe",
    ];

    private static readonly string[] KnownKillerDllNames =
    [
        "ac_killer.dll", "anticheat_killer.dll", "kill_ac.dll",
        "ac_kill.dll", "eac_kill.dll", "be_kill.dll", "vac_kill.dll",
        "ac_terminator.dll", "ac_blocker.dll", "ac_bypass_kill.dll",
        "process_killer.dll", "service_killer.dll", "driver_killer.dll",
        "kill_driver.dll", "kill_service.dll", "kill_process.dll",
        "terminate_ac.dll", "bypass_kill.dll", "remove_ac.dll",
        "unload_ac.dll", "ac_unload.dll", "ac_disable.dll",
        "disable_ac.dll",
    ];

    private static readonly string[] KillerConfigKeywords =
    [
        "kill_anticheat", "kill_ac", "terminate_eac", "terminate_battleye",
        "terminate_vanguard", "terminate_vac", "kill_eac", "kill_be",
        "kill_vac", "kill_vanguard", "kill_ricochet", "kill_xigncode",
        "kill_gameguard", "kill_nprotect", "ac_killer", "anticheat_killer",
        "suspend_anticheat", "suspend_eac", "suspend_be", "suspend_vac",
        "block_anticheat", "block_eac", "block_be", "block_vac",
        "disable_anticheat", "disable_eac", "disable_be", "disable_vac",
        "remove_anticheat", "unload_anticheat", "unload_eac",
        "process_to_kill", "process_kill_list", "kill_list",
        "service_to_kill", "service_kill_list", "driver_to_kill",
        "anticheat_process_name", "ac_process", "eac_process",
        "be_process", "vac_process", "vanguard_process",
        "force_terminate", "force_kill", "hard_kill",
        "inject_killer", "kernel_killer", "ring0_killer",
    ];

    private static readonly string[] AntiCheatProcessNames =
    [
        "EasyAntiCheat.exe", "EasyAntiCheat_EOS.exe",
        "BEService.exe", "BEService64.exe",
        "vgc.exe", "vgk.exe",
        "EAC.exe", "EACService.exe",
        "xigncode.exe", "xhunter1.exe",
        "GameMon.des", "GameGuard.des", "npggNT.des",
        "RiotClientServices.exe", "RiotClientCrashHandler.exe",
        "mhyprot.sys", "mhyprot2.sys",
    ];

    private static readonly string[] KillerScheduledTaskKeywords =
    [
        "ac_killer", "anticheat_killer", "kill_anticheat", "kill_eac",
        "kill_battleye", "kill_vanguard", "terminate_anticheat",
        "disable_anticheat", "block_anticheat", "remove_anticheat",
        "suspend_anticheat", "ac_disable", "ac_block", "ac_remove",
    ];

    private static readonly string[] WfpFilterBypassIndicators =
    [
        "block_eac_network", "block_be_network", "block_vac_network",
        "block_anticheat_network", "filter_eac", "filter_be", "filter_vac",
        "drop_anticheat", "drop_eac_packets", "drop_be_packets",
        "intercept_anticheat", "intercept_eac", "wfp_bypass_ac",
        "firewall_block_eac", "firewall_block_be", "hosts_block_eac",
    ];

    private static readonly string[] UserDirs;

    static AntiCheatKillerScanModule()
    {
        var dirs = new List<string>();
        string? profile = Environment.GetEnvironmentVariable("USERPROFILE");
        string? appData = Environment.GetEnvironmentVariable("APPDATA");
        string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        string? temp = Environment.GetEnvironmentVariable("TEMP");
        string? desktop = profile != null ? Path.Combine(profile, "Desktop") : null;
        string? downloads = profile != null ? Path.Combine(profile, "Downloads") : null;
        string? documents = profile != null ? Path.Combine(profile, "Documents") : null;

        foreach (var d in new[] { appData, localAppData, temp, desktop, downloads, documents })
            if (d != null) dirs.Add(d);

        UserDirs = [.. dirs];
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            ScanForKillerExes(ctx, ct),
            ScanForKillerDlls(ctx, ct),
            ScanConfigsForKillerKeywords(ctx, ct),
            CheckIfeoHijackOfAntiCheatProcesses(ctx, ct),
            CheckAntiCheatServicesDisabled(ctx, ct),
            ScanScheduledTasksForKillerKeywords(ctx, ct),
            CheckHostsFileForAntiCheatBlocks(ctx, ct),
            CheckWindowsFirewallRulesForAcBlocks(ctx, ct),
            CheckRegistryForKillerArtifacts(ctx, ct),
            ScanMuiCacheForKillerTools(ctx, ct)
        ).ConfigureAwait(false);
    }

    private Task ScanForKillerExes(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.exe", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string killerExe in KnownKillerExeNames)
                        {
                            if (fn.Equals(killerExe, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Anti-Cheat Killer Executable Found",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known anti-cheat killer/terminator/disabler tool detected",
                                    Detail = $"AC killer tool '{fn}' found at: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanForKillerDlls(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.dll", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string killerDll in KnownKillerDllNames)
                        {
                            if (fn.Equals(killerDll, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Anti-Cheat Killer DLL Found",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known anti-cheat killer DLL detected in user directory",
                                    Detail = $"AC killer DLL '{fn}' found at: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanConfigsForKillerKeywords(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string ext = Path.GetExtension(file).ToLowerInvariant();
                        if (ext != ".json" && ext != ".cfg" && ext != ".ini" && ext != ".txt"
                            && ext != ".yaml" && ext != ".bat" && ext != ".ps1") continue;
                        if (new FileInfo(file).Length > 500_000) continue;

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            foreach (string kw in KillerConfigKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Anti-Cheat Killer Config/Script Keyword Found",
                                        Risk = Risk.Critical,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"File contains anti-cheat kill/disable keyword: '{kw}'",
                                        Detail = $"AC killer config/script: {file}"
                                    });
                                    ctx.IncrementFiles();
                                    break;
                                }
                            }
                        }
                        catch (IOException) { }
                        catch (UnauthorizedAccessException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckIfeoHijackOfAntiCheatProcesses(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using RegistryKey? ifeoKey = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
                if (ifeoKey == null) return;

                foreach (string acProcess in AntiCheatProcessNames)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using RegistryKey? procKey = ifeoKey.OpenSubKey(acProcess);
                        if (procKey == null) continue;

                        object? debugger = procKey.GetValue("Debugger");
                        if (debugger is string debuggerStr && !string.IsNullOrWhiteSpace(debuggerStr))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Anti-Cheat Process Hijacked via IFEO",
                                Risk = Risk.Critical,
                                Location = $@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{acProcess}",
                                FileName = acProcess,
                                Reason = $"IFEO Debugger set for '{acProcess}' — prevents anti-cheat from launching",
                                Detail = $"IFEO hijack: '{acProcess}' → Debugger = '{debuggerStr}'"
                            });
                            ctx.IncrementRegistryKeys();
                        }

                        object? globalFlag = procKey.GetValue("GlobalFlag");
                        if (globalFlag != null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Anti-Cheat Process GlobalFlag Set via IFEO",
                                Risk = Risk.High,
                                Location = $@"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{acProcess}",
                                FileName = acProcess,
                                Reason = $"IFEO GlobalFlag set for '{acProcess}' — crash/behavior manipulation",
                                Detail = $"IFEO GlobalFlag for anti-cheat: '{acProcess}'"
                            });
                            ctx.IncrementRegistryKeys();
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task CheckAntiCheatServicesDisabled(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string[] acServiceNames =
            [
                "EasyAntiCheat", "EasyAntiCheat_EOS",
                "BEService", "vgc", "vgk",
                "BEDaisy", "ESRV_SVC",
            ];

            foreach (string svcName in acServiceNames)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using RegistryKey? svcKey = Registry.LocalMachine.OpenSubKey(
                        $@"SYSTEM\CurrentControlSet\Services\{svcName}");
                    if (svcKey == null) continue;

                    object? startVal = svcKey.GetValue("Start");
                    if (startVal is int startInt && startInt == 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Anti-Cheat Service '{svcName}' Disabled",
                            Risk = Risk.Critical,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = "registry",
                            Reason = $"Service '{svcName}' has Start=4 (disabled) — anti-cheat killer technique",
                            Detail = $"Anti-cheat service '{svcName}' was forcibly disabled"
                        });
                        ctx.IncrementRegistryKeys();
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanScheduledTasksForKillerKeywords(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            string taskDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "Tasks");

            if (!Directory.Exists(taskDir)) return;

            try
            {
                foreach (string taskFile in Directory.EnumerateFiles(taskDir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var fs = new FileStream(taskFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                        foreach (string kw in KillerScheduledTaskKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Anti-Cheat Killer Scheduled Task Found",
                                    Risk = Risk.Critical,
                                    Location = taskFile,
                                    FileName = Path.GetFileName(taskFile),
                                    Reason = $"Scheduled task XML contains AC killer keyword: '{kw}'",
                                    Detail = $"AC killer task: {taskFile}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task CheckHostsFileForAntiCheatBlocks(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            string hostsFile = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "drivers", "etc", "hosts");

            if (!File.Exists(hostsFile)) return;

            string[] acHostnames =
            [
                "easyanticheat.net", "battleye.com", "easy.ac",
                "auth.easyanticheat.net", "eac.battleye.com",
                "pub.dev.battleye.com", "eac-cdn.net",
                "vanguard.riotgames.com", "anti-cheat.riotgames.com",
                "anticheat.riotgames.com", "eac-server.net",
                "be-server.net", "anticheat.valve.com",
            ];

            try
            {
                using var fs = new FileStream(hostsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                foreach (string acHost in acHostnames)
                {
                    if (content.Contains(acHost, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Anti-Cheat Server Blocked in Hosts File",
                            Risk = Risk.Critical,
                            Location = hostsFile,
                            FileName = "hosts",
                            Reason = $"hosts file blocks anti-cheat server: '{acHost}' — prevents AC reporting",
                            Detail = $"Anti-cheat hostname '{acHost}' blocked via hosts file"
                        });
                        ctx.IncrementFiles();
                    }
                }
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task CheckWindowsFirewallRulesForAcBlocks(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using RegistryKey? fwRules = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
                if (fwRules == null) return;

                string[] acAppNames =
                [
                    "EasyAntiCheat", "BEService", "vgc", "vgk",
                    "BattlEye", "Vanguard",
                ];

                foreach (string ruleName in fwRules.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    string? ruleData = fwRules.GetValue(ruleName) as string;
                    if (ruleData == null) continue;

                    foreach (string acApp in acAppNames)
                    {
                        if (ruleData.Contains(acApp, StringComparison.OrdinalIgnoreCase) &&
                            (ruleData.Contains("Block", StringComparison.OrdinalIgnoreCase) ||
                             ruleData.Contains("Action=Block", StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Anti-Cheat Application Blocked by Firewall Rule",
                                Risk = Risk.Critical,
                                Location = @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
                                FileName = "registry",
                                Reason = $"Firewall rule blocks anti-cheat '{acApp}' from network access",
                                Detail = $"Firewall rule '{ruleName}' blocks: {acApp}"
                            });
                            ctx.IncrementRegistryKeys();
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task CheckRegistryForKillerArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string[] killerRegKeys =
            [
                @"SOFTWARE\ACKiller",
                @"SOFTWARE\AntiCheatKiller",
                @"SOFTWARE\KillAC",
                @"SOFTWARE\ACTerminator",
                @"SOFTWARE\ACBlocker",
                @"SOFTWARE\ACDisabler",
                @"SOFTWARE\KillEAC",
                @"SOFTWARE\KillBE",
                @"SOFTWARE\KillVAC",
                @"SOFTWARE\KillVanguard",
            ];

            foreach (string regKey in killerRegKeys)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using RegistryKey? key = Registry.LocalMachine.OpenSubKey(regKey)
                                          ?? Registry.CurrentUser.OpenSubKey(regKey);
                    if (key != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Anti-Cheat Killer Registry Artifact Found",
                            Risk = Risk.Critical,
                            Location = regKey,
                            FileName = "registry",
                            Reason = "Known anti-cheat killer tool left a registry artifact",
                            Detail = $"AC killer registry key: {regKey}"
                        });
                        ctx.IncrementRegistryKeys();
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanMuiCacheForKillerTools(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using RegistryKey? muiCache = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
                if (muiCache == null) return;

                foreach (string valName in muiCache.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (string killerExe in KnownKillerExeNames)
                    {
                        if (valName.Contains(killerExe, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Anti-Cheat Killer Tool Execution Evidence in MUICache",
                                Risk = Risk.Critical,
                                Location = @"HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                                FileName = "registry",
                                Reason = "MUICache records previous execution of anti-cheat killer tool",
                                Detail = $"MUICache entry: {valName}"
                            });
                            ctx.IncrementRegistryKeys();
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }
}
