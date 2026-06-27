using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMRageMPAltVBypassForensicScanModule : IScanModule
{
    public string Name => "FiveM / RageMP / alt:V Anti-Cheat Bypass Forensic Scan";
    public double Weight => 4.3;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] BypassExecutables =
    {
        "fivem-bypass.exe", "fivembypass.exe", "fivem_bypass.exe",
        "fivem-anticheat-bypass.exe", "fivem_anticheat_bypass.exe",
        "fivem-ac-bypass.exe", "fivem_ac_bypass.exe",
        "fivem-screenshot-bypass.exe", "fivem_screenshot_bypass.exe",
        "fivem-tx-bypass.exe", "fivem_tx_bypass.exe",
        "fivem-txadmin-bypass.exe", "fivem_txadmin_bypass.exe",
        "fivem-shutdown-bypass.exe", "fivem_shutdown_bypass.exe",
        "fivem-kick-bypass.exe", "fivem_kick_bypass.exe",
        "fivem-ban-bypass.exe", "fivem_ban_bypass.exe",
        "fivem-license-bypass.exe", "fivem_license_bypass.exe",
        "fivem-integrity-bypass.exe", "fivem_integrity_bypass.exe",
        "fivem-nui-bypass.exe", "fivem_nui_bypass.exe",
        "fivem-cef-bypass.exe", "fivem_cef_bypass.exe",
        "fivem-eulen-bypass.exe", "fivem_eulen_bypass.exe",
        "fivem-redengine-bypass.exe", "fivem_redengine_bypass.exe",
        "fivem-skript-bypass.exe", "fivem_skript_bypass.exe",
        "fivem-zap-bypass.exe", "fivem_zap_bypass.exe",
        "fivem-onesync-bypass.exe", "fivem_onesync_bypass.exe",
        "fivem-server-bypass.exe", "fivem_server_bypass.exe",
        "fivem-token-bypass.exe", "fivem_token_bypass.exe",
        "fivem-script-bypass.exe", "fivem_script_bypass.exe",
        "ragemp-bypass.exe", "ragempbypass.exe", "ragemp_bypass.exe",
        "ragemp-anticheat-bypass.exe", "ragemp_anticheat_bypass.exe",
        "ragemp-ac-bypass.exe", "ragemp_ac_bypass.exe",
        "ragemp-screenshot-bypass.exe", "ragemp_screenshot_bypass.exe",
        "ragemp-kick-bypass.exe", "ragemp_kick_bypass.exe",
        "ragemp-ban-bypass.exe", "ragemp_ban_bypass.exe",
        "ragemp-serial-bypass.exe", "ragemp_serial_bypass.exe",
        "ragemp-integrity-bypass.exe", "ragemp_integrity_bypass.exe",
        "ragemp-token-bypass.exe", "ragemp_token_bypass.exe",
        "ragemp-script-bypass.exe", "ragemp_script_bypass.exe",
        "ragemp-cef-bypass.exe", "ragemp_cef_bypass.exe",
        "ragemp-rakhmaylov-bypass.exe", "ragemp_rakhmaylov_bypass.exe",
        "altv-bypass.exe", "altvbypass.exe", "altv_bypass.exe",
        "altv-anticheat-bypass.exe", "altv_anticheat_bypass.exe",
        "altv-ac-bypass.exe", "altv_ac_bypass.exe",
        "altv-screenshot-bypass.exe", "altv_screenshot_bypass.exe",
        "altv-kick-bypass.exe", "altv_kick_bypass.exe",
        "altv-ban-bypass.exe", "altv_ban_bypass.exe",
        "altv-license-bypass.exe", "altv_license_bypass.exe",
        "altv-integrity-bypass.exe", "altv_integrity_bypass.exe",
        "altv-token-bypass.exe", "altv_token_bypass.exe",
        "altv-script-bypass.exe", "altv_script_bypass.exe",
        "altv-cef-bypass.exe", "altv_cef_bypass.exe",
        "altv-resource-bypass.exe", "altv_resource_bypass.exe",
        "eac-bypass.exe", "eacbypass.exe", "eac_bypass.exe",
        "easyanticheat-bypass.exe", "easyanticheat_bypass.exe",
        "battleye-bypass.exe", "battleye_bypass.exe", "be-bypass.exe",
        "be_bypass.exe", "vanguard-bypass.exe", "vanguard_bypass.exe",
        "vac-bypass.exe", "vac_bypass.exe", "ricochet-bypass.exe",
        "ricochet_bypass.exe", "fairfight-bypass.exe", "fairfight_bypass.exe",
        "anticheat-bypass.exe", "anticheatbypass.exe", "anti-cheat-bypass.exe",
        "anti_cheat_bypass.exe", "ac-bypass.exe", "acbypass.exe",
        "ac_bypass.exe", "kernel-bypass.exe", "kernelbypass.exe",
        "kernel_bypass.exe", "kmode-bypass.exe", "kmode_bypass.exe",
        "byovd.exe", "byovd-loader.exe", "byovd_loader.exe",
        "vulnerable-driver-loader.exe", "vulnerable_driver_loader.exe",
        "iqvw64e.sys.exe", "iqvw64e-loader.exe", "rtcore64.exe",
        "rtcore64-loader.exe", "kdmapper.exe", "kdmapper-loader.exe",
    };

    private static readonly string[] BypassDlls =
    {
        "fivem-bypass.dll", "fivem_bypass.dll", "fivem-ac-bypass.dll",
        "fivem_ac_bypass.dll", "fivem-screenshot-bypass.dll",
        "fivem_screenshot_bypass.dll", "fivem-integrity-bypass.dll",
        "fivem_integrity_bypass.dll", "fivem-nui-bypass.dll",
        "fivem_nui_bypass.dll", "fivem-cef-bypass.dll",
        "fivem_cef_bypass.dll", "ragemp-bypass.dll", "ragemp_bypass.dll",
        "ragemp-ac-bypass.dll", "ragemp_ac_bypass.dll",
        "ragemp-screenshot-bypass.dll", "ragemp_screenshot_bypass.dll",
        "ragemp-integrity-bypass.dll", "ragemp_integrity_bypass.dll",
        "altv-bypass.dll", "altv_bypass.dll", "altv-ac-bypass.dll",
        "altv_ac_bypass.dll", "altv-screenshot-bypass.dll",
        "altv_screenshot_bypass.dll", "altv-integrity-bypass.dll",
        "altv_integrity_bypass.dll",
        "eac-bypass.dll", "eac_bypass.dll", "easyanticheat-bypass.dll",
        "easyanticheat_bypass.dll", "battleye-bypass.dll",
        "battleye_bypass.dll", "be-bypass.dll", "be_bypass.dll",
        "vanguard-bypass.dll", "vanguard_bypass.dll", "vac-bypass.dll",
        "vac_bypass.dll", "ricochet-bypass.dll", "ricochet_bypass.dll",
        "fairfight-bypass.dll", "fairfight_bypass.dll",
        "anticheat-bypass.dll", "anticheatbypass.dll",
        "ac-bypass.dll", "acbypass.dll", "ac_bypass.dll",
        "kernel-bypass.dll", "kernelbypass.dll", "kernel_bypass.dll",
        "kmode-bypass.dll", "kmode_bypass.dll",
    };

    private static readonly string[] BypassDrivers =
    {
        "iqvw64e.sys", "rtcore64.sys", "rtcore32.sys",
        "winring0x64.sys", "winring0.sys", "speedfan.sys",
        "ntoskrnl_bypass.sys", "kerneltool.sys", "kerneldrv.sys",
        "ezcheat.sys", "ezbypass.sys", "ez_bypass.sys",
        "kbypass.sys", "k_bypass.sys", "kernelbypass.sys",
        "kernel_bypass.sys", "anticheat_bypass.sys",
        "anticheatbypass.sys", "ac_bypass.sys", "acbypass.sys",
        "eac_bypass.sys", "be_bypass.sys", "vanguard_bypass.sys",
        "vac_bypass.sys", "ricochet_bypass.sys", "fairfight_bypass.sys",
        "msio64.sys", "msio32.sys", "asusprov64.sys", "atillk64.sys",
        "atillk32.sys", "dbutil_2_3.sys", "dbutil.sys",
        "pcdsrvc_x64.sys", "pcdsrvc.sys", "amdmsrtweaker.sys",
        "ene.sys", "enedrv.sys", "physmem.sys", "physmem64.sys",
        "directio64.sys", "directio32.sys", "phymem64.sys",
        "phymem32.sys", "phymemx64.sys", "gdrv.sys", "gigabyte.sys",
        "cpuz.sys", "cpuz_x64.sys", "cpuz_x86.sys",
    };

    private static readonly string[] BypassLogKeywords =
    {
        "anticheat bypassed", "anti-cheat bypassed", "ac bypassed",
        "eac bypassed", "easy anti-cheat bypassed", "battleye bypassed",
        "be bypassed", "vanguard bypassed", "vac bypassed",
        "ricochet bypassed", "fairfight bypassed",
        "kernel bypass loaded", "kmode bypass loaded",
        "vulnerable driver loaded", "byovd loaded", "byovd success",
        "kdmapper success", "kdmapper loaded", "manual map success",
        "manual mapping success", "rdi loaded", "rdi success",
        "fivem ac bypassed", "fivem bypass loaded", "fivem ac evaded",
        "ragemp ac bypassed", "ragemp bypass loaded", "ragemp ac evaded",
        "altv ac bypassed", "altv bypass loaded", "altv ac evaded",
        "screenshot blocked", "screenshot disabled", "screenshot intercepted",
        "kick prevented", "kick blocked", "kick intercepted",
        "ban prevented", "ban blocked", "ban intercepted",
        "integrity check bypassed", "integrity verification bypassed",
        "license check bypassed", "license verification bypassed",
        "txadmin bypassed", "tx admin bypassed", "tx bypassed",
        "onesync bypassed", "one sync bypassed", "one-sync bypassed",
        "nui injection success", "nui bypass success", "cef bypass success",
        "rakhmaylov bypassed", "ragemp anticheat killed",
        "altv anticheat killed", "fivem anticheat killed",
        "anticheat process killed", "anticheat service stopped",
        "anticheat driver unloaded", "ac driver unloaded",
        "ac service stopped", "ac process killed",
    };

    private static readonly string[] BypassBrowserUrlPatterns =
    {
        "fivem-bypass.com", "fivem-bypass.cc", "fivem-bypass.gg",
        "fivembypass.com", "fivembypass.cc",
        "ragemp-bypass.com", "ragemp-bypass.cc", "ragemp-bypass.gg",
        "ragempbypass.com", "ragempbypass.cc",
        "altv-bypass.com", "altv-bypass.cc", "altv-bypass.gg",
        "altvbypass.com", "altvbypass.cc",
        "eac-bypass.com", "eac-bypass.cc", "eac-bypass.gg",
        "eacbypass.com", "eacbypass.cc",
        "battleye-bypass.com", "battleye-bypass.cc",
        "battleyebypass.com", "battleyebypass.cc",
        "vanguard-bypass.com", "vanguard-bypass.cc",
        "vanguardbypass.com", "vanguardbypass.cc",
        "vac-bypass.com", "vac-bypass.cc", "vacbypass.com",
        "vacbypass.cc", "ricochet-bypass.com", "ricochet-bypass.cc",
        "ricochetbypass.com", "fairfight-bypass.com",
        "fairfight-bypass.cc", "fairfightbypass.com",
        "ac-bypass.com", "ac-bypass.cc", "acbypass.com", "acbypass.cc",
        "anticheat-bypass.com", "anticheat-bypass.cc",
        "anticheatbypass.com", "anticheatbypass.cc",
        "kernel-bypass.com", "kernel-bypass.cc", "kernelbypass.com",
        "kernelbypass.cc", "kmode-bypass.com", "byovd.gg", "byovd.cc",
        "kdmapper.com", "kdmapper.cc", "kdmapper.gg",
    };

    private static readonly string[] BypassRegistryKeyNames =
    {
        "FiveMBypass", "FiveMACBypass", "FiveMAnticheatBypass",
        "FiveMScreenshotBypass", "FiveMTXAdminBypass",
        "FiveMShutdownBypass", "FiveMKickBypass", "FiveMBanBypass",
        "FiveMLicenseBypass", "FiveMIntegrityBypass",
        "FiveMNUIBypass", "FiveMCEFBypass", "RageMPBypass",
        "RageMPACBypass", "RageMPAnticheatBypass",
        "RageMPScreenshotBypass", "RageMPKickBypass",
        "RageMPBanBypass", "RageMPSerialBypass",
        "RageMPIntegrityBypass", "AltVBypass", "AltVACBypass",
        "AltVAnticheatBypass", "AltVScreenshotBypass",
        "AltVKickBypass", "AltVBanBypass", "AltVLicenseBypass",
        "AltVIntegrityBypass", "EACBypass", "EasyAntiCheatBypass",
        "BattlEyeBypass", "BEBypass", "VanguardBypass", "VACBypass",
        "RicochetBypass", "FairFightBypass", "AntiCheatBypass",
        "ACBypass", "KernelBypass", "KModeBypass", "BYOVD",
        "BYOVDLoader", "VulnerableDriverLoader", "KDMapper",
        "KDMapperLoader",
    };

    private static readonly string[] BypassServiceNames =
    {
        "iqvw64e", "rtcore64", "rtcore32", "winring0x64",
        "winring0", "ezcheat", "ezbypass", "kbypass",
        "kernelbypass", "anticheatbypass", "acbypass",
        "eacbypass", "bebypass", "vanguardbypass", "vacbypass",
        "ricochetbypass", "fairfightbypass", "msio64", "msio32",
        "asusprov64", "atillk64", "atillk32", "dbutil_2_3",
        "dbutil", "pcdsrvc_x64", "pcdsrvc", "amdmsrtweaker",
        "ene", "enedrv", "physmem", "physmem64", "directio64",
        "directio32", "phymem64", "phymem32", "phymemx64",
        "gdrv", "gigabyte", "cpuz", "cpuz_x64", "cpuz_x86",
    };

    private static readonly string[] ArchivePatterns =
    {
        "fivem-bypass", "fivem_bypass", "fivem-ac-bypass",
        "fivem_ac_bypass", "fivem-screenshot-bypass",
        "fivem-integrity-bypass", "fivem-nui-bypass",
        "fivem-cef-bypass", "ragemp-bypass", "ragemp_bypass",
        "ragemp-ac-bypass", "ragemp_ac_bypass",
        "ragemp-screenshot-bypass", "ragemp-integrity-bypass",
        "ragemp-rakhmaylov-bypass", "altv-bypass", "altv_bypass",
        "altv-ac-bypass", "altv_ac_bypass", "altv-screenshot-bypass",
        "altv-integrity-bypass", "eac-bypass", "eac_bypass",
        "easyanticheat-bypass", "battleye-bypass", "battleye_bypass",
        "be-bypass", "be_bypass", "vanguard-bypass",
        "vanguard_bypass", "vac-bypass", "vac_bypass",
        "ricochet-bypass", "ricochet_bypass", "fairfight-bypass",
        "fairfight_bypass", "anticheat-bypass", "anticheatbypass",
        "ac-bypass", "acbypass", "ac_bypass", "kernel-bypass",
        "kernel_bypass", "kmode-bypass", "kmode_bypass",
        "byovd", "byovd-loader", "byovd_loader", "kdmapper",
        "kdmapper-loader", "vulnerable-driver-loader",
        "vulnerable_driver_loader",
    };

    private static readonly string[] ArchiveExtensions =
        { ".zip", ".rar", ".7z", ".gz", ".cab", ".tar", ".iso" };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.WhenAll(
            CheckExecutables(ctx, ct),
            CheckDlls(ctx, ct),
            CheckDrivers(ctx, ct),
            CheckServiceRegistry(ctx, ct),
            CheckLogFiles(ctx, ct),
            CheckBrowserHistory(ctx, ct),
            CheckRegistry(ctx, ct),
            CheckUserAssist(ctx, ct),
            CheckDownloadArchives(ctx, ct),
            CheckMuiCache(ctx, ct),
            CheckPrefetch(ctx, ct),
            CheckDiscordCache(ctx, ct),
            CheckTestSigningPolicy(ctx, ct)
        );
    }

    private static IEnumerable<string> BuildSearchDirectories()
    {
        var dirs = new List<string>();
        string[] envVars = { "TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "PUBLIC", "PROGRAMDATA" };

        foreach (var env in envVars)
        {
            var v = Environment.GetEnvironmentVariable(env);
            if (!string.IsNullOrEmpty(v)) dirs.Add(v);
        }

        var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
        if (!string.IsNullOrEmpty(userProfile))
        {
            dirs.Add(Path.Combine(userProfile, "Downloads"));
            dirs.Add(Path.Combine(userProfile, "Desktop"));
            dirs.Add(Path.Combine(userProfile, "Documents"));
        }

        return dirs.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private Task CheckExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var dir in BuildSearchDirectories())
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string name = Path.GetFileName(file);
                    bool matched = BypassExecutables.Any(n =>
                        name.Equals(n, StringComparison.OrdinalIgnoreCase));
                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Anti-Cheat Bypass Executable",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = name,
                        Reason = $"Filename matches known FiveM/RageMP/alt:V or anti-cheat bypass: {name}",
                        Detail = "Bypass tool designed to neutralize anti-cheat detections, integrity checks, or screenshot capture.",
                    });
                }
            }
        }, ct);

    private Task CheckDlls(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var dir in BuildSearchDirectories())
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string name = Path.GetFileName(file);
                    bool matched = BypassDlls.Any(n =>
                        name.Equals(n, StringComparison.OrdinalIgnoreCase));
                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Anti-Cheat Bypass DLL",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = name,
                        Reason = $"DLL matches bypass payload name: {name}",
                        Detail = "DLL associated with anti-cheat bypass injection.",
                    });
                }
            }
        }, ct);

    private Task CheckDrivers(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var dirs = BuildSearchDirectories().ToList();
            string sys32 = Path.Combine(Environment.SystemDirectory, "drivers");
            if (Directory.Exists(sys32)) dirs.Add(sys32);

            foreach (var dir in dirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, "*.sys", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string name = Path.GetFileName(file);
                    bool matched = BypassDrivers.Any(n =>
                        name.Equals(n, StringComparison.OrdinalIgnoreCase));
                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Vulnerable / Bypass Kernel Driver",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = name,
                        Reason = $"Kernel driver matches known BYOVD or bypass driver: {name}",
                        Detail = "Vulnerable driver historically used for kernel-mode anti-cheat bypass (BYOVD: bring-your-own-vulnerable-driver).",
                    });
                }
            }
        }, ct);

    private Task CheckServiceRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string services = @"SYSTEM\CurrentControlSet\Services";
            RegistryKey? key;
            try { key = Registry.LocalMachine.OpenSubKey(services); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (key == null) return;

            using (key)
            {
                string[] subs;
                try { subs = key.GetSubKeyNames(); }
                catch (System.Security.SecurityException) { return; }

                foreach (var sub in subs)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    bool matched = BypassServiceNames.Any(n =>
                        sub.Equals(n, StringComparison.OrdinalIgnoreCase));
                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Bypass Driver Service Registry Entry",
                        Risk = RiskLevel.Critical,
                        Location = $"HKLM\\{services}\\{sub}",
                        Reason = $"Service registry entry matches known bypass driver: '{sub}'",
                        Detail = "Service entry for a vulnerable / bypass kernel driver.",
                    });
                }
            }
        }, ct);

    private Task CheckLogFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var dirs = BuildSearchDirectories().ToList();
            string[] exts = { ".log", ".txt", ".json", ".cfg" };

            foreach (var dir in dirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                foreach (var ext in exts)
                {
                    IEnumerable<string> files;
                    try { files = Directory.EnumerateFiles(dir, "*" + ext, SearchOption.AllDirectories); }
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

                        foreach (var kw in BypassLogKeywords)
                        {
                            if (!content.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Anti-Cheat Bypass Log Trace",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Log contains anti-cheat bypass pattern: '{kw}'",
                                Detail = "Log indicates an anti-cheat bypass was performed.",
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    private Task CheckBrowserHistory(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string[] paths =
            {
                Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "History"),
                Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "History"),
                Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History"),
                Path.Combine(localAppData, "Vivaldi", "User Data", "Default", "History"),
                Path.Combine(localAppData, "Opera Software", "Opera Stable", "History"),
            };

            foreach (var p in paths)
            {
                if (!File.Exists(p)) continue;
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(p, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var u in BypassBrowserUrlPatterns)
                {
                    if (!content.Contains(u, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Bypass Domain in Browser History",
                        Risk = RiskLevel.High,
                        Location = p,
                        FileName = Path.GetFileName(p),
                        Reason = $"Browser visited bypass marketplace: '{u}'",
                        Detail = "Visit to known anti-cheat bypass distribution site.",
                    });
                    break;
                }
            }
        }, ct);

    private Task CheckRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            string[] rootPaths =
            {
                @"SOFTWARE", @"SOFTWARE\WOW6432Node",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            };

            foreach (var root in rootPaths)
            {
                foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    ct.ThrowIfCancellationRequested();
                    RegistryKey? key;
                    try { key = hive.OpenSubKey(root); }
                    catch (System.Security.SecurityException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }
                    if (key == null) continue;

                    using (key)
                    {
                        string[] subs;
                        try { subs = key.GetSubKeyNames(); }
                        catch (System.Security.SecurityException) { continue; }

                        foreach (var sub in subs)
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();

                            bool matched = BypassRegistryKeyNames.Any(k =>
                                sub.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (!matched) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Anti-Cheat Bypass Registry Key",
                                Risk = RiskLevel.Critical,
                                Location = $"{hive.Name}\\{root}\\{sub}",
                                Reason = $"Registry key named after bypass tool: '{sub}'",
                                Detail = "Persistence/installer record for anti-cheat bypass.",
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckUserAssist(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string root = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
            RegistryKey? ua;
            try { ua = Registry.CurrentUser.OpenSubKey(root); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (ua == null) return;

            using (ua)
            {
                string[] guids;
                try { guids = ua.GetSubKeyNames(); }
                catch (System.Security.SecurityException) { return; }

                foreach (var guid in guids)
                {
                    ct.ThrowIfCancellationRequested();
                    RegistryKey? count;
                    try { count = ua.OpenSubKey(guid + @"\Count"); }
                    catch (System.Security.SecurityException) { continue; }
                    if (count == null) continue;

                    using (count)
                    {
                        string[] vals;
                        try { vals = count.GetValueNames(); }
                        catch (System.Security.SecurityException) { continue; }

                        foreach (var v in vals)
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();

                            string decoded = Rot13Decode(v).ToLowerInvariant();
                            foreach (var exe in BypassExecutables)
                            {
                                string exeBase = Path.GetFileNameWithoutExtension(exe).ToLowerInvariant();
                                if (!decoded.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Bypass Execution Trace (UserAssist)",
                                    Risk = RiskLevel.Critical,
                                    Location = $"HKCU\\{root}\\{guid}\\Count\\{v}",
                                    FileName = decoded,
                                    Reason = $"UserAssist execution record for bypass: '{exeBase}'",
                                    Detail = "Bypass binary was launched interactively by the user.",
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }, ct);

    private Task CheckDownloadArchives(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
            if (string.IsNullOrEmpty(userProfile)) return;

            string[] dirs =
            {
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Desktop"),
                Path.Combine(userProfile, "Documents"),
            };

            foreach (var dir in dirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string ext = Path.GetExtension(file);
                    if (!ArchiveExtensions.Any(e => ext.Equals(e, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    string name = Path.GetFileName(file);
                    foreach (var pat in ArchivePatterns)
                    {
                        if (!name.Contains(pat, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Bypass Download Archive",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = name,
                            Reason = $"Archive named for bypass tool: '{pat}'",
                            Detail = "Archive contains anti-cheat bypass distribution.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckMuiCache(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string mui = @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
            RegistryKey? key;
            try { key = Registry.CurrentUser.OpenSubKey(mui); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (key == null) return;

            using (key)
            {
                string[] vals;
                try { vals = key.GetValueNames(); }
                catch (System.Security.SecurityException) { return; }

                foreach (var v in vals)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    string vlow = v.ToLowerInvariant();
                    foreach (var exe in BypassExecutables)
                    {
                        string exeBase = Path.GetFileNameWithoutExtension(exe).ToLowerInvariant();
                        if (!vlow.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Bypass in MuiCache",
                            Risk = RiskLevel.Critical,
                            Location = $"HKCU\\{mui}\\{v}",
                            Reason = $"MuiCache references bypass: '{exeBase}'",
                            Detail = "Execution record for bypass binary.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckPrefetch(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string prefetch = @"C:\Windows\Prefetch";
            if (!Directory.Exists(prefetch)) return;

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(prefetch, "*.pf"); }
            catch (UnauthorizedAccessException) { return; }
            catch (IOException) { return; }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string fileName = Path.GetFileName(file).ToLowerInvariant();
                foreach (var exe in BypassExecutables)
                {
                    string exeBase = Path.GetFileNameWithoutExtension(exe).ToLowerInvariant();
                    if (!fileName.Contains(exeBase, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Bypass in Prefetch",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Prefetch records bypass execution: '{exeBase}'",
                        Detail = "Prefetch confirms execution of bypass binary.",
                    });
                    break;
                }
            }
        }, ct);

    private Task CheckDiscordCache(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string[] discords =
            {
                Path.Combine(appData, "discord"),
                Path.Combine(appData, "discordptb"),
                Path.Combine(appData, "discordcanary"),
            };

            foreach (var d in discords)
            {
                if (!Directory.Exists(d)) continue;
                ct.ThrowIfCancellationRequested();

                string cache = Path.Combine(d, "Cache");
                if (!Directory.Exists(cache)) continue;

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(cache, "*", SearchOption.AllDirectories); }
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

                    foreach (var u in BypassBrowserUrlPatterns)
                    {
                        if (!content.Contains(u, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Bypass URL in Discord Cache",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Discord cache contains bypass URL: '{u}'",
                            Detail = "Bypass marketplace link shared or received via Discord.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckTestSigningPolicy(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string control = @"SYSTEM\CurrentControlSet\Control\CI";
            RegistryKey? key;
            try { key = Registry.LocalMachine.OpenSubKey(control); }
            catch (System.Security.SecurityException) { return; }
            catch (UnauthorizedAccessException) { return; }
            if (key == null) return;

            using (key)
            {
                object? policy;
                try { policy = key.GetValue("TestSigning"); }
                catch (System.Security.SecurityException) { return; }

                if (policy is int i && i == 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Test-Signing Policy Enabled",
                        Risk = RiskLevel.Critical,
                        Location = $"HKLM\\{control}\\TestSigning",
                        Reason = "Test-Signing is ON — Windows accepts unsigned kernel drivers.",
                        Detail = "Common pre-condition for loading vulnerable/BYOVD bypass drivers.",
                    });
                }

                object? dse;
                try { dse = key.GetValue("VulnerableDriverBlocklistEnable"); }
                catch (System.Security.SecurityException) { return; }

                if (dse is int v && v == 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Vulnerable Driver Blocklist Disabled",
                        Risk = RiskLevel.High,
                        Location = $"HKLM\\{control}\\VulnerableDriverBlocklistEnable",
                        Reason = "Microsoft's vulnerable driver blocklist is OFF.",
                        Detail = "Disables protection against well-known BYOVD bypass drivers.",
                    });
                }
            }
        }, ct);

    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else if (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
