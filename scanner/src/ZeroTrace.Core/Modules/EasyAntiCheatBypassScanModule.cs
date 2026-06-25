using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class EasyAntiCheatBypassScanModule : IScanModule
{
    public string Name => "Easy Anti-Cheat Bypass Detection";
    public double Weight => 4.6;
    public int ParallelGroup => 4;

    private static readonly string[] KnownEacBypassExeNames =
    [
        "eac_bypass.exe", "eac_patch.exe", "eac_killer.exe", "eac_unloader.exe",
        "eac_spoofer.exe", "eac_remover.exe", "eac_hook.exe", "eac_disable.exe",
        "easyanticheat_bypass.exe", "easyanticheat_hook.exe", "easyanticheat_spoof.exe",
        "easyanticheat_kill.exe", "easyanticheat_patch.exe", "bypasseac.exe",
        "eac_bypass_loader.exe", "antieac.exe", "eac_dumper.exe", "eac_emu.exe",
        "eac_emulator.exe", "eac_fake.exe", "eac_patcher.exe", "eac_skipper.exe",
        "eac_suspend.exe", "eac_terminate.exe", "fakeeac.exe", "noeac.exe",
        "eac_blocker.exe", "eac_injector.exe", "eac_loader_patch.exe",
        "eac_offline.exe", "eac_workaround.exe", "eac_crack.exe",
        "easyac_bypass.exe", "eac2_bypass.exe", "easy_bypass.exe",
        "eac_v2_bypass.exe", "eac_cert_bypass.exe", "eac_tls_bypass.exe",
        "eac_network_bypass.exe", "eac_protocol_bypass.exe", "eac_sign_bypass.exe",
        "eac_stealth.exe", "eac_hide.exe", "eac_ghost.exe", "eac_cloak.exe",
        "eac_shadow.exe", "eac_phantom.exe", "eac_wraith.exe",
        "eac_offset_bypass.exe", "eac_scan_bypass.exe", "eac_memory_bypass.exe",
        "eac_driver_bypass.exe", "eac_kernel_bypass.exe", "eac_ring0_bypass.exe",
    ];

    private static readonly string[] KnownEacBypassDllNames =
    [
        "eac_bypass.dll", "eac_hook.dll", "eac_patch.dll", "eac_spoof.dll",
        "easyanticheat_bypass.dll", "easyanticheat_hook.dll", "antieac.dll",
        "eac_emu.dll", "eac_emulator.dll", "eac_fake.dll", "eac_stealth.dll",
        "eac_hide.dll", "eac_ghost.dll", "eac_cloak.dll", "eac_shadow.dll",
        "eac_phantom.dll", "eac_loader.dll", "fakeeac.dll", "noeac.dll",
        "eac_injector.dll", "eac_memory_bypass.dll", "eac_driver_bypass.dll",
        "eac_kernel_bypass.dll", "eac_ring0_bypass.dll", "eac_cert_bypass.dll",
        "eac_tls_bypass.dll", "eac_network_bypass.dll", "eac_protocol_bypass.dll",
        "eac_sign_bypass.dll", "eac_offset_bypass.dll", "eac_scan_bypass.dll",
    ];

    private static readonly string[] EacBypassDirNames =
    [
        "eac_bypass", "eac bypass", "easyanticheat_bypass", "eac_hack",
        "anti_eac", "eac_remover", "eac_killer", "eac_tools",
        "eac_patch", "eac_spoofer", "eac_crack", "eac_dumper",
        "eac_hooker", "eac_injector", "eac_patcher", "eac_stealth",
        "noeac", "fakeeac", "eac_workaround", "eac_offline",
        "eac_emulator", "eac_ghost", "eac_shadow", "eac_phantom",
        "eac_cloak", "eac_loader_bypass", "eac2bypass", "eac_v2_bypass",
    ];

    private static readonly string[] EacBypassConfigKeywords =
    [
        "eac_bypass", "eac_disabled", "eac_hooked", "eac_patched",
        "easyanticheat_bypass", "eac_spoofed", "eac_killed", "eac_removed",
        "eac_emulated", "eac_faked", "eac_hidden", "eac_ghosted",
        "bypass_eac", "disable_eac", "hook_eac", "patch_eac",
        "spoof_eac", "kill_eac", "remove_eac", "emulate_eac",
        "eac_cert_spoofed", "eac_tls_bypassed", "eac_network_bypassed",
        "eac_driver_bypassed", "eac_kernel_bypassed", "eac_ring0_bypassed",
        "eac_sign_bypassed", "eac_memory_bypassed", "eac_scan_bypassed",
        "eac_offline_mode", "eac_fake_response", "eac_block_service",
        "eac_block_connection", "eac_block_report", "eac_intercept",
    ];

    private static readonly string[] EacLegitServiceNames =
    [
        "EasyAntiCheat", "EasyAntiCheat_EOS",
    ];

    private static readonly string[] EacLegitExePaths =
    [
        @"EasyAntiCheat\EasyAntiCheat.exe",
        @"EasyAntiCheat\EasyAntiCheat_EOS.exe",
        @"EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe",
    ];

    private static readonly string[] KnownEacRegistryBypassKeys =
    [
        @"SOFTWARE\EasyAntiCheat_bypass",
        @"SOFTWARE\EAC_patch",
        @"SOFTWARE\EAC_hook",
        @"SOFTWARE\EAC_spoof",
        @"SOFTWARE\EAC_emulator",
        @"SOFTWARE\FakeEAC",
        @"SOFTWARE\AntiEAC",
    ];

    private static readonly string[] EacCertBypassFileNames =
    [
        "eac_cert_bypass.bin", "eac_cert_spoof.bin", "eac_cert.fake",
        "eac_ssl_bypass.dat", "eac_tls_bypass.dat", "eac_fake_cert.pem",
        "eac_cert_patch.bin", "eac_sign_bypass.bin", "eac_cert_kill.bin",
    ];

    private static readonly string[] UserDirs;

    static EasyAntiCheatBypassScanModule()
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
            ScanUserDirsForBypassExes(ctx, ct),
            ScanUserDirsForBypassDlls(ctx, ct),
            ScanUserDirsForBypassDirs(ctx, ct),
            ScanEacInstallIntegrity(ctx, ct),
            CheckEacServiceTampering(ctx, ct),
            CheckEacRegistryBypassKeys(ctx, ct),
            ScanConfigsForEacBypassKeywords(ctx, ct),
            ScanForEacCertBypassFiles(ctx, ct),
            CheckEacSystemFileReplacement(ctx, ct),
            ScanProgramFilesForEacTools(ctx, ct)
        ).ConfigureAwait(false);
    }

    private Task ScanUserDirsForBypassExes(ScanContext ctx, CancellationToken ct)
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
                        foreach (string bypassName in KnownEacBypassExeNames)
                        {
                            if (fn.Equals(bypassName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "EAC Bypass Executable Detected",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known Easy Anti-Cheat bypass tool found",
                                    Detail = $"File '{fn}' is a known EAC bypass/patch/killer tool: {file}"
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

    private Task ScanUserDirsForBypassDlls(ScanContext ctx, CancellationToken ct)
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
                        foreach (string bypassName in KnownEacBypassDllNames)
                        {
                            if (fn.Equals(bypassName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "EAC Bypass DLL Detected",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known EAC hook/bypass DLL found in user directory",
                                    Detail = $"EAC bypass library '{fn}' found at: {file}"
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

    private Task ScanUserDirsForBypassDirs(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string dir in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string dn = Path.GetFileName(dir);
                        foreach (string bypassDir in EacBypassDirNames)
                        {
                            if (dn.Equals(bypassDir, StringComparison.OrdinalIgnoreCase)
                                || dn.Contains(bypassDir, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "EAC Bypass Directory Found",
                                    Risk = Risk.High,
                                    Location = dir,
                                    FileName = dn,
                                    Reason = "Directory name matches known EAC bypass tool pattern",
                                    Detail = $"Suspicious EAC bypass directory: {dir}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanEacInstallIntegrity(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

            var eacRoots = new List<string>();

            foreach (string pf in new[] { progFiles, progFilesX86 })
            {
                if (!Directory.Exists(pf)) continue;
                try
                {
                    foreach (string dir in Directory.EnumerateDirectories(pf, "*", SearchOption.TopDirectoryOnly))
                    {
                        string dn = Path.GetFileName(dir);
                        if (dn.Contains("EasyAntiCheat", StringComparison.OrdinalIgnoreCase) ||
                            dn.Contains("EAC", StringComparison.OrdinalIgnoreCase))
                            eacRoots.Add(dir);
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            foreach (string eacRoot in eacRoots)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    foreach (string file in Directory.EnumerateFiles(eacRoot, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string bypassName in KnownEacBypassExeNames.Concat(KnownEacBypassDllNames))
                        {
                            if (fn.Equals(bypassName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "EAC Bypass Tool Planted in EAC Install Directory",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Bypass file placed inside EAC installation folder",
                                    Detail = $"Malicious file '{fn}' inside EAC install: {file}"
                                });
                                ctx.IncrementFiles();
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);
    }

    private Task CheckEacServiceTampering(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string svcName in EacLegitServiceNames)
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
                            Title = "EAC Service Disabled in Registry",
                            Risk = Risk.Critical,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = "registry",
                            Reason = $"Service '{svcName}' has Start=4 (disabled) — EAC bypass technique",
                            Detail = $"EAC service '{svcName}' was disabled via registry modification"
                        });
                        ctx.IncrementRegistryKeys();
                    }

                    object? imagePath = svcKey.GetValue("ImagePath");
                    if (imagePath is string imgStr)
                    {
                        if (imgStr.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            imgStr.Contains("hook", StringComparison.OrdinalIgnoreCase) ||
                            imgStr.Contains("patch", StringComparison.OrdinalIgnoreCase) ||
                            imgStr.Contains("fake", StringComparison.OrdinalIgnoreCase) ||
                            imgStr.Contains("spoof", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "EAC Service Binary Path Tampered",
                                Risk = Risk.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = "registry",
                                Reason = $"Service '{svcName}' ImagePath contains suspicious bypass keywords",
                                Detail = $"EAC service path tampered: {imgStr}"
                            });
                            ctx.IncrementRegistryKeys();
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckEacRegistryBypassKeys(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string regKey in KnownEacRegistryBypassKeys)
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
                            Title = "EAC Bypass Registry Key Found",
                            Risk = Risk.Critical,
                            Location = regKey,
                            FileName = "registry",
                            Reason = "Known EAC bypass tool created this registry key",
                            Detail = $"EAC bypass registry artifact found: {regKey}"
                        });
                        ctx.IncrementRegistryKeys();
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            try
            {
                using RegistryKey? muiKey = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
                if (muiKey != null)
                {
                    foreach (string sub in muiKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            using RegistryKey? countKey = muiKey.OpenSubKey($@"{sub}\Count");
                            if (countKey == null) continue;
                            foreach (string valName in countKey.GetValueNames())
                            {
                                string decoded = Rot13Decode(valName);
                                foreach (string bypassName in KnownEacBypassExeNames)
                                {
                                    if (decoded.Contains(bypassName, StringComparison.OrdinalIgnoreCase))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = Name,
                                            Title = "EAC Bypass Tool Execution Evidence in UserAssist",
                                            Risk = Risk.Critical,
                                            Location = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                                            FileName = "registry",
                                            Reason = "EAC bypass tool was previously launched (UserAssist execution log)",
                                            Detail = $"UserAssist entry: {decoded}"
                                        });
                                        ctx.IncrementRegistryKeys();
                                        break;
                                    }
                                }
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task ScanConfigsForEacBypassKeywords(ScanContext ctx, CancellationToken ct)
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

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
                            foreach (string keyword in EacBypassConfigKeywords)
                            {
                                if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "EAC Bypass Config Keyword Found",
                                        Risk = Risk.High,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Config file contains EAC bypass keyword: '{keyword}'",
                                        Detail = $"EAC bypass configuration in: {file}"
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

    private Task ScanForEacCertBypassFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string root in UserDirs)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        string fn = Path.GetFileName(file);
                        foreach (string certBypass in EacCertBypassFileNames)
                        {
                            if (fn.Equals(certBypass, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "EAC Certificate Bypass File Detected",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "EAC certificate/TLS bypass artifact file found",
                                    Detail = $"EAC cert bypass file: {file}"
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

    private Task CheckEacSystemFileReplacement(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            string driversDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers");
            string[] eacSysFiles = ["EasyAntiCheat.sys", "EasyAntiCheat_EOS.sys"];

            foreach (string sysFile in eacSysFiles)
            {
                ct.ThrowIfCancellationRequested();
                string sysPath = Path.Combine(driversDir, sysFile);
                if (!File.Exists(sysPath)) continue;
                try
                {
                    var fi = new FileInfo(sysPath);
                    if (fi.Length < 100_000)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "EAC Driver File Suspiciously Small",
                            Risk = Risk.High,
                            Location = sysPath,
                            FileName = sysFile,
                            Reason = "EAC driver file is abnormally small — may be replaced with stub",
                            Detail = $"'{sysFile}' size is {fi.Length} bytes (expected >100KB)"
                        });
                        ctx.IncrementFiles();
                    }
                }
                catch (IOException) { }
            }
        }, ct);
    }

    private Task ScanProgramFilesForEacTools(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using RegistryKey? uninst = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if (uninst == null) return;
                foreach (string sub in uninst.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using RegistryKey? app = uninst.OpenSubKey(sub);
                        if (app == null) continue;
                        string? displayName = app.GetValue("DisplayName") as string;
                        if (displayName == null) continue;
                        foreach (string bypassDir in EacBypassDirNames)
                        {
                            if (displayName.Contains(bypassDir, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "EAC Bypass Software in Installed Programs List",
                                    Risk = Risk.Critical,
                                    Location = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + sub,
                                    FileName = "registry",
                                    Reason = $"Installed program name matches EAC bypass pattern: '{displayName}'",
                                    Detail = $"Uninstall entry: '{displayName}'"
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

    private static string Rot13Decode(string input)
    {
        return new string(input.Select(c =>
            c >= 'a' && c <= 'z' ? (char)('a' + (c - 'a' + 13) % 26) :
            c >= 'A' && c <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) : c).ToArray());
    }
}
