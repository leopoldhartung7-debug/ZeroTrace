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

public sealed class BypassRuntimeActionForensicScanModule : IScanModule
{
    public string Name => "Bypass Runtime Action & System-State Forensic Detection";
    public double Weight => 4.6;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.WhenAll(
            CheckTestSigningMode(ctx, ct),
            CheckDriverSignatureEnforcement(ctx, ct),
            CheckSecureBootState(ctx, ct),
            CheckHvciState(ctx, ct),
            CheckCiPolicyState(ctx, ct),
            CheckVulnerableDriverBlocklist(ctx, ct),
            CheckLoadedVulnerableDriverServices(ctx, ct),
            CheckRunningBypassDriverServices(ctx, ct),
            CheckPagingExecuteEnabled(ctx, ct),
            CheckDefenderDisabled(ctx, ct),
            CheckSmartScreenDisabled(ctx, ct),
            CheckUacDisabled(ctx, ct),
            CheckAntiCheatServicesStopped(ctx, ct),
            CheckHostsFileModification(ctx, ct),
            CheckBcdEditTraces(ctx, ct),
            CheckBootConfigDisabledChecks(ctx, ct),
            CheckIfeoHijacks(ctx, ct),
            CheckSuspiciousScheduledTasksRunning(ctx, ct),
            CheckRecentDriverLoads(ctx, ct),
            CheckWmiProviderTampering(ctx, ct),
            CheckProcessExplorerArtifacts(ctx, ct)
        );
    }

    private static readonly string[] VulnerableDriverServiceNames =
    {
        "iqvw64e", "rtcore64", "rtcore32", "winring0x64", "winring0",
        "speedfan", "ezbypass", "kbypass", "kernelbypass",
        "anticheatbypass", "acbypass", "eacbypass", "bebypass",
        "vanguardbypass", "vacbypass", "ricochetbypass", "fairfightbypass",
        "msio64", "msio32", "asusprov64", "atillk64", "atillk32",
        "dbutil_2_3", "dbutil", "pcdsrvc_x64", "pcdsrvc",
        "amdmsrtweaker", "ene", "enedrv", "physmem", "physmem64",
        "directio64", "directio32", "phymem64", "phymem32", "phymemx64",
        "gdrv", "gigabyte", "cpuz", "cpuz_x64", "cpuz_x86",
        "rwdrv", "rwread", "rwwrite", "razerdrv", "kkdrv",
        "vboxdrv", "vboxnetadp", "vboxnetflt", "vboxusbmon",
    };

    private static readonly string[] AntiCheatServiceNames =
    {
        "EasyAntiCheat", "EasyAntiCheat_EOS", "EasyAntiCheatSvc",
        "BEService", "BEDaisy", "BattlEye", "vgc", "vgk",
        "VanguardSvc", "Vanguard", "FACEIT", "FACEITService",
        "ESEAService", "ESEADriver", "Sentry",
    };

    private Task CheckTestSigningMode(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string ci = @"SYSTEM\CurrentControlSet\Control\CI";
            RegistryKey? k;
            try { k = Registry.LocalMachine.OpenSubKey(ci); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                object? ts;
                try { ts = k.GetValue("TestSigning"); }
                catch (System.Security.SecurityException) { return; }

                if (ts is int i && i == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Test-Signing ACTIVE",
                        Risk = RiskLevel.Critical,
                        Location = $"HKLM\\{ci}\\TestSigning",
                        Reason = "Test-Signing is ON — Windows is currently accepting unsigned kernel drivers.",
                        Detail = "Direct effect of `bcdedit /set testsigning on`. Required step for loading BYOVD bypass drivers.",
                    });
                }
            }
        }, ct);

    private Task CheckDriverSignatureEnforcement(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string ci = @"SYSTEM\CurrentControlSet\Control\CI\Config";
            RegistryKey? k;
            try { k = Registry.LocalMachine.OpenSubKey(ci); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                object? policy;
                try { policy = k.GetValue("VulnerableDriverBlocklistEnable"); }
                catch (System.Security.SecurityException) { return; }

                if (policy is int i && i == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Vulnerable-Driver Blocklist Turned OFF",
                        Risk = RiskLevel.Critical,
                        Location = $"HKLM\\{ci}\\VulnerableDriverBlocklistEnable",
                        Reason = "Microsoft Vulnerable Driver Blocklist is currently disabled.",
                        Detail = "Was active by default since Win10 22H2 — disabling enables BYOVD bypass workflow.",
                    });
                }
            }
        }, ct);

    private Task CheckSecureBootState(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string sb = @"SYSTEM\CurrentControlSet\Control\SecureBoot\State";
            RegistryKey? k;
            try { k = Registry.LocalMachine.OpenSubKey(sb); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                object? state;
                try { state = k.GetValue("UEFISecureBootEnabled"); }
                catch (System.Security.SecurityException) { return; }

                if (state is int i && i == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Secure Boot Disabled",
                        Risk = RiskLevel.High,
                        Location = $"HKLM\\{sb}\\UEFISecureBootEnabled",
                        Reason = "UEFI Secure Boot is OFF.",
                        Detail = "Required disabled state for loading unsigned bootkit-style drivers.",
                    });
                }
            }
        }, ct);

    private Task CheckHvciState(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string dg = @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";
            RegistryKey? k;
            try { k = Registry.LocalMachine.OpenSubKey(dg); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                object? enabled;
                try { enabled = k.GetValue("Enabled"); }
                catch (System.Security.SecurityException) { return; }

                if (enabled is int i && i == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "HVCI (Hypervisor-Enforced Code Integrity) Disabled",
                        Risk = RiskLevel.High,
                        Location = $"HKLM\\{dg}\\Enabled",
                        Reason = "HVCI is OFF — kernel memory not protected against unsigned/altered code.",
                        Detail = "HVCI being explicitly disabled is uncommon and aligns with BYOVD bypass requirements.",
                    });
                }
            }
        }, ct);

    private Task CheckCiPolicyState(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SOFTWARE\Microsoft\Windows\CurrentVersion\CI\Policy";
            RegistryKey? k;
            try { k = Registry.LocalMachine.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                object? unsigned;
                try { unsigned = k.GetValue("AllowUnsignedDrivers"); }
                catch (System.Security.SecurityException) { return; }

                if (unsigned is int i && i == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Unsigned Drivers Explicitly Allowed",
                        Risk = RiskLevel.Critical,
                        Location = $"HKLM\\{p}\\AllowUnsignedDrivers",
                        Reason = "Code Integrity policy permits unsigned drivers.",
                        Detail = "Required setting for kernel-mode anti-cheat bypass.",
                    });
                }
            }
        }, ct);

    private Task CheckVulnerableDriverBlocklist(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string ms = Path.Combine(Environment.SystemDirectory, "drivers", "MsftDriverBlockList.sys");
            if (!File.Exists(ms))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "MS Driver Blocklist File Missing",
                    Risk = RiskLevel.High,
                    Location = ms,
                    Reason = "Microsoft's vulnerable-driver blocklist binary is absent.",
                    Detail = "Direct removal of this file disables protection against known BYOVD.",
                });
            }
            else
            {
                ctx.IncrementFiles();
                try
                {
                    var info = new FileInfo(ms);
                    if (info.Length < 16384)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Driver Blocklist Truncated",
                            Risk = RiskLevel.High,
                            Location = ms,
                            FileName = "MsftDriverBlockList.sys",
                            Reason = $"Blocklist file is only {info.Length} bytes.",
                            Detail = "File replaced with stub to defeat BYOVD enforcement.",
                        });
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckLoadedVulnerableDriverServices(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string svcRoot = @"SYSTEM\CurrentControlSet\Services";
            RegistryKey? root;
            try { root = Registry.LocalMachine.OpenSubKey(svcRoot); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (root == null) return;

            using (root)
            {
                foreach (var svc in VulnerableDriverServiceNames)
                {
                    ct.ThrowIfCancellationRequested();
                    RegistryKey? sk;
                    try { sk = root.OpenSubKey(svc); }
                    catch (System.Security.SecurityException) { continue; }
                    if (sk == null) continue;

                    using (sk)
                    {
                        ctx.IncrementRegistryKeys();
                        object? start;
                        try { start = sk.GetValue("Start"); }
                        catch (System.Security.SecurityException) { continue; }

                        int s = start is int x ? x : -1;
                        string startMode = s switch
                        {
                            0 => "Boot",
                            1 => "System",
                            2 => "Automatic",
                            3 => "Manual",
                            4 => "Disabled",
                            _ => "Unknown",
                        };

                        object? path;
                        try { path = sk.GetValue("ImagePath"); }
                        catch (System.Security.SecurityException) { path = null; }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "BYOVD Driver Service Registered",
                            Risk = RiskLevel.Critical,
                            Location = $"HKLM\\{svcRoot}\\{svc}",
                            Reason = $"Vulnerable BYOVD driver service '{svc}' is registered (Start mode: {startMode}).",
                            Detail = $"ImagePath: {path}\nKnown abuse vector for kernel-mode anti-cheat bypass.",
                        });
                    }
                }
            }
        }, ct);

    private Task CheckRunningBypassDriverServices(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string svcRoot = @"SYSTEM\CurrentControlSet\Services";
            RegistryKey? root;
            try { root = Registry.LocalMachine.OpenSubKey(svcRoot); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (root == null) return;

            using (root)
            {
                string[] names;
                try { names = root.GetSubKeyNames(); }
                catch (System.Security.SecurityException) { return; }

                foreach (var name in names)
                {
                    ct.ThrowIfCancellationRequested();

                    bool nameSusBypass = name.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                         name.Contains("anticheat_bypass", StringComparison.OrdinalIgnoreCase) ||
                                         name.Contains("ac_bypass", StringComparison.OrdinalIgnoreCase);
                    if (!nameSusBypass) continue;

                    RegistryKey? sk;
                    try { sk = root.OpenSubKey(name); }
                    catch (System.Security.SecurityException) { continue; }
                    if (sk == null) continue;

                    using (sk)
                    {
                        ctx.IncrementRegistryKeys();
                        object? path;
                        try { path = sk.GetValue("ImagePath"); }
                        catch (System.Security.SecurityException) { continue; }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Anti-Cheat Bypass Driver Service Active",
                            Risk = RiskLevel.Critical,
                            Location = $"HKLM\\{svcRoot}\\{name}",
                            Reason = $"Service name contains bypass-keyword: '{name}'.",
                            Detail = $"ImagePath: {path}",
                        });
                    }
                }
            }
        }, ct);

    private Task CheckPagingExecuteEnabled(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string mm = @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
            RegistryKey? k;
            try { k = Registry.LocalMachine.OpenSubKey(mm); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                object? noExec;
                try { noExec = k.GetValue("DisablePagingExecutive"); }
                catch (System.Security.SecurityException) { return; }

                if (noExec is int i && i == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "DisablePagingExecutive Set",
                        Risk = RiskLevel.Medium,
                        Location = $"HKLM\\{mm}\\DisablePagingExecutive",
                        Reason = "Kernel modules kept in non-paged memory.",
                        Detail = "Common pre-condition for kernel-mode cheats hooking system services.",
                    });
                }
            }
        }, ct);

    private Task CheckDefenderDisabled(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] paths =
            {
                @"SOFTWARE\Policies\Microsoft\Windows Defender",
                @"SOFTWARE\Microsoft\Windows Defender",
                @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
                @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
            };

            foreach (var p in paths)
            {
                ct.ThrowIfCancellationRequested();
                RegistryKey? k;
                try { k = Registry.LocalMachine.OpenSubKey(p); }
                catch (System.Security.SecurityException) { continue; }
                catch (UnauthorizedAccessException) { continue; }
                if (k == null) continue;

                using (k)
                {
                    ctx.IncrementRegistryKeys();
                    string[] flags = { "DisableAntiSpyware", "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableScanOnRealtimeEnable" };

                    foreach (var f in flags)
                    {
                        object? val;
                        try { val = k.GetValue(f); }
                        catch (System.Security.SecurityException) { continue; }

                        if (val is int i && i == 1)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Windows Defender Flag '{f}' Enabled",
                                Risk = RiskLevel.High,
                                Location = $"HKLM\\{p}\\{f}",
                                Reason = $"Defender protection feature '{f}' is OFF.",
                                Detail = "Bypass routine commonly disables Defender before loading cheat.",
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckSmartScreenDisabled(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer";
            RegistryKey? k;
            try { k = Registry.LocalMachine.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                object? v;
                try { v = k.GetValue("SmartScreenEnabled"); }
                catch (System.Security.SecurityException) { return; }

                if (v is string s && s.Equals("Off", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "SmartScreen Turned Off",
                        Risk = RiskLevel.Medium,
                        Location = $"HKLM\\{p}\\SmartScreenEnabled",
                        Reason = "SmartScreen reputation filter is disabled.",
                        Detail = "Bypass routines disable SmartScreen to download unflagged binaries.",
                    });
                }
            }
        }, ct);

    private Task CheckUacDisabled(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string p = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
            RegistryKey? k;
            try { k = Registry.LocalMachine.OpenSubKey(p); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                object? lua;
                try { lua = k.GetValue("EnableLUA"); }
                catch (System.Security.SecurityException) { return; }

                if (lua is int i && i == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "UAC Disabled",
                        Risk = RiskLevel.High,
                        Location = $"HKLM\\{p}\\EnableLUA",
                        Reason = "User Account Control is OFF.",
                        Detail = "Bypass routines disable UAC so injectors can run elevated without prompts.",
                    });
                }
            }
        }, ct);

    private Task CheckAntiCheatServicesStopped(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string svcRoot = @"SYSTEM\CurrentControlSet\Services";
            RegistryKey? root;
            try { root = Registry.LocalMachine.OpenSubKey(svcRoot); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (root == null) return;

            using (root)
            {
                foreach (var svc in AntiCheatServiceNames)
                {
                    ct.ThrowIfCancellationRequested();
                    RegistryKey? sk;
                    try { sk = root.OpenSubKey(svc); }
                    catch (System.Security.SecurityException) { continue; }
                    if (sk == null) continue;

                    using (sk)
                    {
                        ctx.IncrementRegistryKeys();
                        object? start;
                        try { start = sk.GetValue("Start"); }
                        catch (System.Security.SecurityException) { continue; }

                        if (start is int s && s == 4)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Anti-Cheat Service '{svc}' DISABLED",
                                Risk = RiskLevel.Critical,
                                Location = $"HKLM\\{svcRoot}\\{svc}\\Start",
                                Reason = $"Anti-cheat service '{svc}' is set to Start=4 (Disabled).",
                                Detail = "Anti-cheat was deliberately neutralized — clear bypass action.",
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckHostsFileModification(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            const string hosts = @"C:\Windows\System32\drivers\etc\hosts";
            if (!File.Exists(hosts)) return;
            ctx.IncrementFiles();

            DateTime mod;
            try { mod = File.GetLastWriteTimeUtc(hosts); }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            string content;
            try
            {
                using var fs = new FileStream(hosts, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            string[] blockedTargets =
            {
                "easyanticheat", "battleye", "vac.steampowered",
                "ricochet.activision", "vanguard.riotgames",
                "telemetry.fivem.net", "fivem.net", "cfx.re",
                "ragemp.com", "altv.mp", "rage.mp",
            };

            int blocks = 0;
            foreach (var line in content.Split('\n'))
            {
                string trimmed = line.Trim();
                if (trimmed.StartsWith("#") || string.IsNullOrWhiteSpace(trimmed)) continue;
                bool isBlocker = trimmed.StartsWith("0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
                                 trimmed.StartsWith("127.0.0.1", StringComparison.OrdinalIgnoreCase);
                if (!isBlocker) continue;

                foreach (var t in blockedTargets)
                {
                    if (!trimmed.Contains(t, StringComparison.OrdinalIgnoreCase)) continue;
                    blocks++;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Hosts File Actively Blocks Anti-Cheat / Multiplayer",
                        Risk = RiskLevel.Critical,
                        Location = hosts,
                        FileName = "hosts",
                        Reason = $"hosts file has live block for: '{t}' (last modified UTC {mod})",
                        Detail = $"Line: {trimmed}\nBlocking these endpoints kills telemetry / ban delivery — bypass action.",
                    });
                    break;
                }
            }
        }, ct);

    private Task CheckBcdEditTraces(ScanContext ctx, CancellationToken ct) =>
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

            string[] suspiciousCommands =
            {
                "bcdedit /set testsigning on", "bcdedit /set nointegritychecks on",
                "bcdedit /set loadoptions DISABLE_INTEGRITY_CHECKS",
                "bcdedit /set hypervisorlaunchtype off",
                "bcdedit /debug on", "bcdedit /set disableintegritychecks yes",
                "fltmc unload", "sc stop easyanticheat", "sc stop beservice",
                "sc stop bedaisy", "sc stop vgc", "sc stop vgk",
                "sc config easyanticheat start= disabled",
                "sc config beservice start= disabled",
                "sc config vgc start= disabled",
                "taskkill /im easyanticheat", "taskkill /im beservice",
                "taskkill /im vgc", "taskkill /im vgk",
                "stop-service easyanticheat", "stop-service beservice",
                "stop-service vgc", "stop-service vgk",
                "wevtutil cl security", "wevtutil cl system",
                "wevtutil cl application", "wevtutil cl",
                "fsutil usn deletejournal", "fsutil resource",
                "cipher /w", "sdelete -p", "sdelete64 -p",
                "kdmapper", "kdu.exe", "kdrv.exe", "kduload",
                "Get-ItemPropertyValue -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI' -Name TestSigning",
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI' -Name TestSigning",
            };

            foreach (var cmd in suspiciousCommands)
            {
                if (!content.Contains(cmd, StringComparison.OrdinalIgnoreCase)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Bypass Command in PowerShell History",
                    Risk = RiskLevel.Critical,
                    Location = psHistory,
                    FileName = "ConsoleHost_history.txt",
                    Reason = $"PowerShell history contains bypass command: '{cmd}'",
                    Detail = "Direct evidence that the user executed a bypass / cleaner command.",
                });
            }
        }, ct);

    private Task CheckBootConfigDisabledChecks(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string bcdRoot = @"BCD00000000";
            RegistryKey? k;
            try { k = Registry.Users.OpenSubKey(@"S-1-5-21\BCD00000000"); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k == null) return;

            using (k)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "BCD Hive Open Indicator",
                    Risk = RiskLevel.Low,
                    Location = $"HKU\\S-1-5-21\\{bcdRoot}",
                    Reason = "BCD configuration in user hive — non-default state.",
                    Detail = "BCD has been edited interactively.",
                });
            }
        }, ct);

    private Task CheckIfeoHijacks(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string ifeo = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            RegistryKey? key;
            try { key = Registry.LocalMachine.OpenSubKey(ifeo); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (key == null) return;

            string[] watchedTargets =
            {
                "EasyAntiCheat.exe", "EasyAntiCheat_EOS.exe",
                "BEService.exe", "BEDaisy.exe", "BattlEye.exe",
                "vgc.exe", "vgk.sys", "FACEIT.exe", "ESEA.exe",
                "FiveM.exe", "FiveM_b2802.exe", "RAGEMP_v.exe",
                "ragemp_v.exe", "altv-client.exe", "altv.exe",
            };

            using (key)
            {
                string[] subs;
                try { subs = key.GetSubKeyNames(); }
                catch (System.Security.SecurityException) { return; }

                foreach (var sub in subs)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    bool matched = watchedTargets.Any(t =>
                        sub.Equals(t, StringComparison.OrdinalIgnoreCase));
                    if (!matched) continue;

                    RegistryKey? sk;
                    try { sk = key.OpenSubKey(sub); }
                    catch (System.Security.SecurityException) { continue; }
                    if (sk == null) continue;

                    using (sk)
                    {
                        object? debugger;
                        try { debugger = sk.GetValue("Debugger"); }
                        catch (System.Security.SecurityException) { debugger = null; }

                        if (debugger != null)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "IFEO Hijack on Anti-Cheat / Game Target",
                                Risk = RiskLevel.Critical,
                                Location = $"HKLM\\{ifeo}\\{sub}\\Debugger",
                                Reason = $"IFEO Debugger registered for '{sub}'.",
                                Detail = $"Debugger: {debugger}\nIFEO Debugger hijack redirects the anti-cheat / game launch.",
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckSuspiciousScheduledTasksRunning(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            const string tasks = @"C:\Windows\System32\Tasks";
            if (!Directory.Exists(tasks)) return;

            string[] suspiciousNames =
            {
                "bypass", "cleaner", "wiper", "spoofer", "hwid", "fud",
                "evader", "trace_wipe", "antiforensic", "anti-forensic",
                "scanner_bypass", "anticheat_bypass", "ac_bypass",
            };

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(tasks, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string name = Path.GetFileName(file);
                bool nameMatch = suspiciousNames.Any(s =>
                    name.Contains(s, StringComparison.OrdinalIgnoreCase));

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                bool contentMatch = suspiciousNames.Any(s =>
                    content.Contains(s, StringComparison.OrdinalIgnoreCase));

                if (!nameMatch && !contentMatch) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Scheduled Task with Bypass / Cleaner Keywords",
                    Risk = RiskLevel.Critical,
                    Location = file,
                    FileName = name,
                    Reason = nameMatch
                        ? $"Scheduled task filename contains bypass keyword: '{name}'"
                        : "Scheduled task XML body contains bypass / cleaner action commands.",
                    Detail = "Automated execution of bypass/cleaner — persistence-level anti-forensic configuration.",
                });
            }
        }, ct);

    private Task CheckRecentDriverLoads(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string mini = @"SYSTEM\CurrentControlSet\Control\MiniNT";
            RegistryKey? k;
            try { k = Registry.LocalMachine.OpenSubKey(mini); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (k != null)
            {
                using (k)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "MiniNT Registry Indicator Present",
                        Risk = RiskLevel.Medium,
                        Location = $"HKLM\\{mini}",
                        Reason = "MiniNT key exists — Windows is or was running in PE / cleaner-recovery mode.",
                        Detail = "Cleaner workflows boot into WinPE to wipe files unreachable from normal session.",
                    });
                }
            }
        }, ct);

    private Task CheckWmiProviderTampering(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string wbem = Path.Combine(Environment.SystemDirectory, "wbem", "Repository");
            if (!Directory.Exists(wbem)) return;

            string[] expected = { "OBJECTS.DATA", "INDEX.BTR", "MAPPING1.MAP", "MAPPING2.MAP" };
            int missing = 0;
            foreach (var e in expected)
            {
                ct.ThrowIfCancellationRequested();
                if (!File.Exists(Path.Combine(wbem, e))) missing++;
            }

            if (missing > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "WMI Repository Files Missing",
                    Risk = RiskLevel.High,
                    Location = wbem,
                    Reason = $"{missing}/{expected.Length} WMI repository files are absent.",
                    Detail = "WMI repository wiped — cleaner removes WMI persistence and history.",
                });
            }
        }, ct);

    private Task CheckProcessExplorerArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] artifactPaths =
            {
                @"SOFTWARE\Sysinternals\Process Explorer",
                @"SOFTWARE\Sysinternals\PsTools",
                @"SOFTWARE\Sysinternals\Handle",
                @"SOFTWARE\Sysinternals\Autoruns",
            };

            foreach (var p in artifactPaths)
            {
                ct.ThrowIfCancellationRequested();
                RegistryKey? k;
                try { k = Registry.CurrentUser.OpenSubKey(p); }
                catch (System.Security.SecurityException) { continue; }
                catch (UnauthorizedAccessException) { continue; }
                if (k == null) continue;

                using (k)
                {
                    object? eula;
                    try { eula = k.GetValue("EulaAccepted"); }
                    catch (System.Security.SecurityException) { continue; }
                    ctx.IncrementRegistryKeys();

                    if (eula != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Sysinternals Bypass-Toolkit Used",
                            Risk = RiskLevel.Medium,
                            Location = $"HKCU\\{p}",
                            Reason = "Sysinternals tool EULA accepted — tool was launched.",
                            Detail = "Process Explorer / Handle / Autoruns are common pre-bypass reconnaissance utilities.",
                        });
                    }
                }
            }
        }, ct);
}
