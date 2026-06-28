using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

public sealed class KernelCallbackHijackScanModule : IScanModule
{
    public string Name => "Kernel Callback Hijack Detection";
    public double Weight => 4.7;
    public int ParallelGroup => 3;

    private static readonly string[] KnownKernelHijackDriverNames =
    [
        "callback_hijack.sys", "kernel_hook.sys", "notify_hijack.sys",
        "process_notify.sys", "thread_notify.sys", "image_notify.sys",
        "registry_notify.sys", "object_hijack.sys", "ssdt_hook.sys",
        "idt_hook.sys", "shadow_ssdt.sys", "shadow_hook.sys",
        "dkom.sys", "dkom_hide.sys", "eprocess_hide.sys",
        "pid_hide.sys", "pid_spoof.sys", "proc_hide.sys",
        "token_steal.sys", "token_spoof.sys", "privilege_esc.sys",
        "kernel_bypass.sys", "ac_bypass.sys", "anticheating_bypass.sys",
        "vac_bypass.sys", "be_bypass.sys", "eac_bypass.sys",
        "kernel_cheat.sys", "ring0_cheat.sys", "kernel_injector.sys",
        "kernel_patcher.sys", "kdmapper_payload.sys", "manual_map.sys",
        "turla_driver.sys", "ghost_driver.sys", "phantom_driver.sys",
        "hidden_driver.sys", "stealth_driver.sys", "cloak_driver.sys",
        "rdma_bypass.sys", "pci_bypass.sys", "iommu_bypass.sys",
        "hyperv_bypass.sys", "vt_bypass.sys", "smm_bypass.sys",
    ];

    private static readonly string[] KernelHijackToolExeNames =
    [
        "kdmapper.exe", "kdmapper64.exe", "dsemap.exe", "dsefix.exe",
        "dse_bypass.exe", "ztf_mapper.exe", "driver_mapper.exe",
        "kernel_mapper.exe", "ring0_mapper.exe", "driver_injector.exe",
        "kernel_injector.exe", "winload_patcher.exe", "bootkit.exe",
        "kdmapper_loader.exe", "physmem_loader.exe", "physmem.exe",
        "iqvw64e.exe", "iqvw64e_vuln.exe", "driver_loader.exe",
        "vulnerable_driver_loader.exe", "vuln_driver_exec.exe",
        "CapcomLib.exe", "capcom_rootkit.exe", "dbutil_bypass.exe",
        "rtcore64_exec.exe", "gdrv_exec.exe", "asmmap64_exec.exe",
        "process_hacker.exe", "procexp64.exe", "winobj.exe",
        "poolmonx.exe", "poolmon.exe", "notmyfault.exe",
        "ssdt_viewer.exe", "ssdt_hook_tool.exe", "idt_viewer.exe",
        "object_view.exe", "callback_view.exe", "driver_query.exe",
        "driverquery_bypass.exe", "kernel_explorer.exe",
        "kernel_tools.exe", "ring0_tools.exe", "anti_cheat_killer.exe",
    ];

    private static readonly string[] VulnerableDriverNames =
    [
        "iqvw64e.sys", "iqvw32e.sys", "dbutil_2_3.sys", "dbutil2_3.sys",
        "rtcore64.sys", "rtcore32.sys", "gdrv.sys", "asmmap64.sys",
        "asmmap.sys", "cpuz151_x64.sys", "cpuz151_x32.sys",
        "cpuz141_x64.sys", "cpuz141_x32.sys", "elam.sys",
        "amifldrv64.sys", "amifldrv32.sys", "aswArPot.sys",
        "AsIO.sys", "AsIO2.sys", "AsIO3.sys",
        "WinRing0.sys", "WinRing0x64.sys", "WinRing0_1_2_0.sys",
        "NTIOLib.sys", "NTIOLib_X64.sys", "LenovoDiagnosticsDriver.sys",
        "stdcdrv64.sys", "GLCKIO2.sys", "GVCIDrv64.sys",
        "iQVW64.SYS", "HWiNFO64A.SYS", "HWiNFO32A.SYS",
        "physmem.sys", "msio64.sys", "msio32.sys",
        "MsIo64.sys", "MsIo.sys", "RamMapNT64.sys",
        "FairplaySys.sys", "GLCKIO2.sys", "GVCIDrv64.sys",
        "AsUpIO.sys", "ATSZIO64.sys", "ATSZIO.sys",
        "KProcessHacker3.sys", "KProcessHacker2.sys",
        "procexp152.sys", "procexp.sys",
        "dbk64.sys", "dbk32.sys",
    ];

    private static readonly string[] KernelHijackRegistryKeys =
    [
        @"SOFTWARE\KdMapper",
        @"SOFTWARE\KernelHijack",
        @"SOFTWARE\CallbackHijack",
        @"SOFTWARE\SsdtHook",
        @"SOFTWARE\IdtHook",
        @"SOFTWARE\DkomHide",
        @"SOFTWARE\ProcessHide",
        @"SOFTWARE\KernelPatcher",
        @"SOFTWARE\RingZeroTools",
    ];

    private static readonly string[] KernelMapperConfigKeywords =
    [
        "kdmapper", "kernel_hook", "ssdt_hook", "idt_hook", "dkom",
        "callback_hijack", "notify_hijack", "process_callback",
        "thread_callback", "image_callback", "registry_callback",
        "object_callback", "kernel_patch", "ring0_patch", "ring0_hook",
        "kernel_bypass", "ac_bypass_kernel", "driver_map",
        "manual_map_kernel", "kernel_inject", "ring0_inject",
        "physical_memory", "physmem_access", "mmap_driver",
        "vulnerable_driver", "vuln_driver", "bring_your_own_driver",
        "byod_exploit", "dse_bypass", "dse_disabled", "dse_off",
        "driver_signature_enforcement", "test_signing",
        "process_hide_kernel", "pid_spoof_kernel", "token_steal",
    ];

    private static readonly string[] UserDirs;

    static KernelCallbackHijackScanModule()
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
            ScanForKernelHijackDrivers(ctx, ct),
            ScanForKernelHijackTools(ctx, ct),
            ScanForVulnerableDriverFiles(ctx, ct),
            CheckVulnerableDriversInRegistry(ctx, ct),
            CheckKernelHijackRegistryKeys(ctx, ct),
            CheckTestSigningMode(ctx, ct),
            CheckDseBypassArtifacts(ctx, ct),
            ScanForKernelMapperConfigs(ctx, ct),
            CheckKdMapperRegistryArtifacts(ctx, ct),
            ScanForKernelHijackPayloads(ctx, ct)
        ).ConfigureAwait(false);
    }

    private Task ScanForKernelHijackDrivers(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
            string driversDir = Path.Combine(system32, "drivers");

            foreach (string driverDir in new[] { driversDir, system32 })
            {
                if (!Directory.Exists(driverDir)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(driverDir, "*.sys", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string hackDriver in KnownKernelHijackDriverNames)
                        {
                            if (fn.Equals(hackDriver, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Kernel Callback Hijack Driver in System32",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known kernel callback hijack/DKOM/hook driver found in system directory",
                                    Detail = $"Malicious kernel driver '{fn}' in {driverDir}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.sys", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string hackDriver in KnownKernelHijackDriverNames)
                        {
                            if (fn.Equals(hackDriver, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Kernel Hijack Driver Found in User Directory",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known kernel callback hijack driver file found staged in user directory",
                                    Detail = $"Kernel hijack driver '{fn}' staged at: {file}"
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

    private Task ScanForKernelHijackTools(ScanContext ctx, CancellationToken ct)
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
                        foreach (string toolName in KernelHijackToolExeNames)
                        {
                            if (fn.Equals(toolName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Kernel Hijack Tool Executable Found",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known kernel mapping/hooking tool detected",
                                    Detail = $"Kernel hijack tool '{fn}' found at: {file}"
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

    private Task ScanForVulnerableDriverFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*.sys", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string vulnDriver in VulnerableDriverNames)
                        {
                            if (fn.Equals(vulnDriver, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "BYOVD Vulnerable Driver Found in User Directory",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known Bring-Your-Own-Vulnerable-Driver file staged for kernel exploitation",
                                    Detail = $"Vulnerable driver '{fn}' staged at: {file} — used with kdmapper/dsemap for kernel-level cheat loading"
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

    private Task CheckVulnerableDriversInRegistry(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using RegistryKey? servicesKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services");
                if (servicesKey == null) return;

                foreach (string svcName in servicesKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using RegistryKey? svcKey = servicesKey.OpenSubKey(svcName);
                        if (svcKey == null) continue;

                        object? imgPath = svcKey.GetValue("ImagePath");
                        if (imgPath is not string imgPathStr) continue;

                        string imgFn = Path.GetFileName(imgPathStr.Trim('"', ' '));
                        foreach (string vulnDriver in VulnerableDriverNames)
                        {
                            if (imgFn.Equals(vulnDriver, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "BYOVD Vulnerable Driver Registered as Service",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                    FileName = vulnDriver,
                                    Reason = "Known vulnerable driver registered as a system service — BYOVD kernel exploit pattern",
                                    Detail = $"Service '{svcName}' uses vulnerable driver: {imgPathStr}"
                                });
                                ctx.IncrementRegistryKeys();
                                break;
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task CheckKernelHijackRegistryKeys(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string regKey in KernelHijackRegistryKeys)
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
                            Title = "Kernel Hijack Tool Registry Key Found",
                            Risk = RiskLevel.Critical,
                            Location = regKey,
                            FileName = "registry",
                            Reason = "Known kernel callback hijack tool created this registry key",
                            Detail = $"Kernel hijack registry artifact: {regKey}"
                        });
                        ctx.IncrementRegistryKeys();
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckTestSigningMode(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using RegistryKey? bcdKey = Registry.LocalMachine.OpenSubKey(
                    @"BCD00000000\Objects\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\Elements\16000049");
                if (bcdKey != null)
                {
                    object? val = bcdKey.GetValue("Element");
                    if (val is byte[] bytes && bytes.Length > 0 && bytes[0] == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Windows Test Signing Mode Enabled",
                            Risk = RiskLevel.High,
                            Location = @"HKLM\BCD00000000",
                            FileName = "registry",
                            Reason = "Test signing mode allows unsigned kernel drivers — required by some kernel cheats",
                            Detail = "BCD test signing flag is enabled (bcdedit /set testsigning on)"
                        });
                        ctx.IncrementRegistryKeys();
                    }
                }
            }
            catch (UnauthorizedAccessException) { }

            try
            {
                using RegistryKey? codeIntegrity = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\CI\Config");
                if (codeIntegrity != null)
                {
                    object? vuln = codeIntegrity.GetValue("VulnerableDriverBlocklistEnable");
                    if (vuln is int vulnInt && vulnInt == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Vulnerable Driver Blocklist Disabled",
                            Risk = RiskLevel.Critical,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config",
                            FileName = "registry",
                            Reason = "Microsoft vulnerable driver blocklist was disabled — allows BYOVD attacks",
                            Detail = "VulnerableDriverBlocklistEnable=0 allows known-vulnerable drivers to load"
                        });
                        ctx.IncrementRegistryKeys();
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task CheckDseBypassArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string[] dseBypassFiles =
            [
                "dsemap.exe", "dsefix.exe", "dse_bypass.exe", "dse_disable.exe",
                "dse_patch.exe", "dse_off.exe", "ci_bypass.exe", "ci_patch.exe",
                "signature_bypass.exe", "driver_sign_bypass.exe",
                "dsemap.sys", "dsefix.sys", "ci_hook.sys",
            ];

            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string dseFile in dseBypassFiles)
                        {
                            if (fn.Equals(dseFile, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Driver Signature Enforcement Bypass Tool Found",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "DSE/CI bypass tool disables kernel driver signature enforcement",
                                    Detail = $"DSE bypass tool '{fn}' found at: {file}"
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

    private Task ScanForKernelMapperConfigs(ScanContext ctx, CancellationToken ct)
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
                        if (ext != ".json" && ext != ".cfg" && ext != ".ini" && ext != ".txt" && ext != ".yaml") continue;
                        if (new FileInfo(file).Length > 1_000_000) continue;

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                            foreach (string kw in KernelMapperConfigKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Kernel Mapper/Hooker Config Keyword Found",
                                        Risk = RiskLevel.High,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Config file contains kernel hijack keyword: '{kw}'",
                                        Detail = $"Kernel hook configuration in: {file}"
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

    private Task CheckKdMapperRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string[] kdmapperServicePatterns =
            [
                "kdmapper", "kernel_map", "ring0_map", "driver_map",
                "manual_map", "physmem", "vulnerable_drv", "byovd",
                "ci_bypass", "dse_bypass", "dsemap", "dsefix",
            ];

            try
            {
                using RegistryKey? servicesKey = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services");
                if (servicesKey == null) return;

                foreach (string svcName in servicesKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    foreach (string pattern in kdmapperServicePatterns)
                    {
                        if (svcName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "KdMapper/BYOVD Service Name Found",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = "registry",
                                Reason = $"Service name matches known BYOVD/kernel mapper pattern: '{svcName}'",
                                Detail = $"Suspicious kernel service: {svcName}"
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

    private Task ScanForKernelHijackPayloads(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string? temp = Environment.GetEnvironmentVariable("TEMP");
            if (temp == null || !Directory.Exists(temp)) return;

            try
            {
                foreach (string file in Directory.EnumerateFiles(temp, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    string fn = Path.GetFileName(file);
                    string ext = Path.GetExtension(fn).ToLowerInvariant();

                    if (ext != ".sys" && ext != ".bin" && ext != ".dat" && ext != ".tmp") continue;

                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length < 1_000 || fi.Length > 10_000_000) continue;

                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        byte[] header = new byte[8];
                        int read = fs.Read(header, 0, 8);
                        if (read < 2) continue;

                        bool hasMzHeader = header[0] == 0x4D && header[1] == 0x5A;
                        bool hasPeHeader = read >= 4 && header[0] == 0x50 && header[1] == 0x45
                                         && header[2] == 0x00 && header[3] == 0x00;

                        if ((hasMzHeader || hasPeHeader) && (ext == ".bin" || ext == ".dat" || ext == ".tmp"))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Suspicious Executable Payload in Temp Directory",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = "File in %TEMP% has PE/MZ header but non-executable extension — kernel payload staging",
                                Detail = $"PE binary disguised as '{ext}' file: {file}"
                            });
                            ctx.IncrementFiles();
                        }
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }
}
