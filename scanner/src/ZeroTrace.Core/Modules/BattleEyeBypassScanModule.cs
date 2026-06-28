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

public sealed class BattleEyeBypassScanModule : IScanModule
{
    public string Name => "BattleEye Bypass Detection";
    public double Weight => 4.6;
    public int ParallelGroup => 4;

    private static readonly string[] KnownBeBypassExeNames =
    [
        "be_bypass.exe", "battleye_bypass.exe", "battleye_killer.exe", "battleye_patch.exe",
        "battleye_hook.exe", "battleye_spoofer.exe", "battleye_remover.exe", "battleye_disable.exe",
        "battleye_unloader.exe", "battleye_crack.exe", "bypassbe.exe", "nobe.exe",
        "be_killer.exe", "be_hook.exe", "be_patch.exe", "be_spoof.exe",
        "be_injector.exe", "be_dumper.exe", "be_emu.exe", "be_emulator.exe",
        "be_fake.exe", "be_stealth.exe", "be_ghost.exe", "be_cloak.exe",
        "be_phantom.exe", "be_offline.exe", "be_remover.exe", "be_skipper.exe",
        "be_suspend.exe", "be_terminate.exe", "fakebe.exe", "antibe.exe",
        "anti_battleye.exe", "be_loader_patch.exe", "be_workaround.exe",
        "be_bypass_loader.exe", "be_cert_bypass.exe", "be_tls_bypass.exe",
        "be_network_bypass.exe", "be_driver_bypass.exe", "be_kernel_bypass.exe",
        "be_ring0_bypass.exe", "be_memory_bypass.exe", "be_scan_bypass.exe",
        "be_sign_bypass.exe", "be_v2_bypass.exe", "be2_bypass.exe",
        "battleeye_bypass.exe", "battl3eye_bypass.exe",
    ];

    private static readonly string[] KnownBeBypassDllNames =
    [
        "be_bypass.dll", "battleye_bypass.dll", "battleye_hook.dll", "battleye_patch.dll",
        "be_hook.dll", "be_patch.dll", "be_spoof.dll", "be_emu.dll",
        "be_emulator.dll", "be_fake.dll", "be_stealth.dll", "be_ghost.dll",
        "be_phantom.dll", "be_cloak.dll", "be_injector.dll", "be_loader.dll",
        "fakebe.dll", "antibe.dll", "be_memory_bypass.dll", "be_driver_bypass.dll",
        "be_kernel_bypass.dll", "be_ring0_bypass.dll", "be_cert_bypass.dll",
        "be_tls_bypass.dll", "be_network_bypass.dll", "be_sign_bypass.dll",
        "be_scan_bypass.dll", "be_offset_bypass.dll",
        "BEClient_bypass.dll", "BEService_bypass.dll",
    ];

    private static readonly string[] BeBypassDirNames =
    [
        "battleye_bypass", "be_bypass", "battleye_hack", "be_hack",
        "anti_battleye", "anti_be", "battleye_tools", "be_tools",
        "battleye_crack", "be_crack", "battleye_patch", "be_patch_dir",
        "battleye_spoofer", "be_spoofer", "battleye_killer", "be_killer",
        "battleye_remover", "be_remover", "battleye_hooker", "be_hooker",
        "battleye_injector", "be_injector", "battleye_stealth", "be_stealth",
        "nobe", "fakebe", "be_emulator", "battleye_emulator",
        "be_offline", "be_workaround", "be2bypass", "be_v2_bypass",
        "battleye_loader_bypass", "be_ghost", "be_shadow", "be_phantom",
    ];

    private static readonly string[] BeConfigBypassKeywords =
    [
        "be_bypass", "battleye_bypass", "be_disabled", "battleye_disabled",
        "be_hooked", "battleye_hooked", "be_patched", "battleye_patched",
        "be_spoofed", "battleye_spoofed", "be_killed", "battleye_killed",
        "be_removed", "battleye_removed", "be_emulated", "battleye_emulated",
        "be_faked", "battleye_faked", "be_hidden", "battleye_hidden",
        "bypass_be", "bypass_battleye", "disable_be", "disable_battleye",
        "hook_be", "hook_battleye", "patch_be", "patch_battleye",
        "kill_be", "kill_battleye", "remove_be", "remove_battleye",
        "be_cert_bypassed", "be_tls_bypassed", "be_network_bypassed",
        "be_driver_bypassed", "be_kernel_bypassed", "be_ring0_bypassed",
        "be_memory_bypassed", "be_scan_bypassed", "be_sign_bypassed",
        "battleye_offline_mode", "be_block_connection", "be_block_report",
        "BEClient_bypass", "BEService_bypass",
    ];

    private static readonly string[] BeServiceNames =
    [
        "BEService", "BattlEye Service",
    ];

    private static readonly string[] BeKnownRegistryBypassKeys =
    [
        @"SOFTWARE\BattlEye_bypass",
        @"SOFTWARE\BE_patch",
        @"SOFTWARE\BE_hook",
        @"SOFTWARE\BE_spoof",
        @"SOFTWARE\FakeBE",
        @"SOFTWARE\AntiBE",
        @"SOFTWARE\BattleEye_bypass",
    ];

    private static readonly string[] BeCoreFileNames =
    [
        "BEClient.dll", "BEClient_x64.dll", "BEService.exe",
        "BEDaisy.sys",
    ];

    private static readonly string[] UserDirs;

    static BattleEyeBypassScanModule()
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
            CheckBeServiceTampering(ctx, ct),
            CheckBeRegistryBypassKeys(ctx, ct),
            ScanConfigsForBeBypassKeywords(ctx, ct),
            CheckBeClientDllIntegrity(ctx, ct),
            ScanBattleEyeLogForBypassPatterns(ctx, ct),
            ScanUserAssistForBeBypassExecution(ctx, ct),
            ScanMuiCacheForBeBypass(ctx, ct)
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
                        foreach (string bypassName in KnownBeBypassExeNames)
                        {
                            if (fn.Equals(bypassName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "BattleEye Bypass Executable Detected",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known BattleEye bypass/kill/patch tool found",
                                    Detail = $"File '{fn}' is a known BattleEye bypass tool: {file}"
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
                        foreach (string bypassName in KnownBeBypassDllNames)
                        {
                            if (fn.Equals(bypassName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "BattleEye Bypass DLL Detected",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "Known BattleEye hook/bypass DLL found in user directory",
                                    Detail = $"BE bypass library '{fn}' found at: {file}"
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
                        foreach (string bypassDir in BeBypassDirNames)
                        {
                            if (dn.Equals(bypassDir, StringComparison.OrdinalIgnoreCase)
                                || dn.Contains(bypassDir, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "BattleEye Bypass Directory Found",
                                    Risk = Risk.High,
                                    Location = dir,
                                    FileName = dn,
                                    Reason = "Directory name matches known BattleEye bypass tool pattern",
                                    Detail = $"Suspicious BE bypass directory: {dir}"
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

    private Task CheckBeServiceTampering(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string svcName in BeServiceNames)
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
                            Title = "BattleEye Service Disabled in Registry",
                            Risk = Risk.Critical,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            FileName = "registry",
                            Reason = $"Service '{svcName}' has Start=4 (disabled) — BattleEye bypass technique",
                            Detail = $"BattleEye service '{svcName}' disabled via registry"
                        });
                        ctx.IncrementRegistryKeys();
                    }

                    object? imagePath = svcKey.GetValue("ImagePath");
                    if (imagePath is string imgStr)
                    {
                        if (imgStr.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                            imgStr.Contains("hook", StringComparison.OrdinalIgnoreCase) ||
                            imgStr.Contains("fake", StringComparison.OrdinalIgnoreCase) ||
                            imgStr.Contains("spoof", StringComparison.OrdinalIgnoreCase) ||
                            imgStr.Contains("patch", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "BattleEye Service Binary Path Tampered",
                                Risk = Risk.Critical,
                                Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                                FileName = "registry",
                                Reason = $"BE service '{svcName}' ImagePath contains bypass keywords",
                                Detail = $"BattleEye service path tampered: {imgStr}"
                            });
                            ctx.IncrementRegistryKeys();
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task CheckBeRegistryBypassKeys(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            foreach (string regKey in BeKnownRegistryBypassKeys)
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
                            Title = "BattleEye Bypass Registry Key Found",
                            Risk = Risk.Critical,
                            Location = regKey,
                            FileName = "registry",
                            Reason = "Known BattleEye bypass tool created this registry key",
                            Detail = $"BE bypass registry artifact: {regKey}"
                        });
                        ctx.IncrementRegistryKeys();
                    }
                }
                catch (UnauthorizedAccessException) { }
            }

            try
            {
                using RegistryKey? runKey = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
                if (runKey != null)
                {
                    foreach (string valName in runKey.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        string? valData = runKey.GetValue(valName) as string;
                        if (valData == null) continue;
                        foreach (string bypassName in KnownBeBypassExeNames)
                        {
                            if (valData.Contains(bypassName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "BattleEye Bypass Tool in Startup Registry",
                                    Risk = Risk.Critical,
                                    Location = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                    FileName = "registry",
                                    Reason = $"Startup entry '{valName}' launches known BattleEye bypass tool",
                                    Detail = $"Startup command: {valData}"
                                });
                                ctx.IncrementRegistryKeys();
                                break;
                            }
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task ScanConfigsForBeBypassKeywords(ScanContext ctx, CancellationToken ct)
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
                        if (new FileInfo(file).Length > 2_000_000) continue;

                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);
                            foreach (string keyword in BeConfigBypassKeywords)
                            {
                                if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "BattleEye Bypass Config Keyword Found",
                                        Risk = Risk.High,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"Config file contains BattleEye bypass keyword: '{keyword}'",
                                        Detail = $"BE bypass configuration found in: {file}"
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

    private Task CheckBeClientDllIntegrity(ScanContext ctx, CancellationToken ct)
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
                        bool isBeClient = fn.Equals("BEClient.dll", StringComparison.OrdinalIgnoreCase)
                                       || fn.Equals("BEClient_x64.dll", StringComparison.OrdinalIgnoreCase);
                        if (!isBeClient) continue;

                        try
                        {
                            var fi = new FileInfo(file);
                            if (fi.Length < 50_000)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "BattleEye Client DLL Replaced with Small Stub",
                                    Risk = Risk.Critical,
                                    Location = file,
                                    FileName = fn,
                                    Reason = "BEClient DLL found outside game dir with suspiciously small size",
                                    Detail = $"'{fn}' at '{file}' is only {fi.Length} bytes — genuine BEClient is much larger"
                                });
                                ctx.IncrementFiles();
                            }
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);
    }

    private Task ScanBattleEyeLogForBypassPatterns(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            string? localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (localAppData == null) return;

            string beLogDir = Path.Combine(localAppData, "BattlEye");
            if (!Directory.Exists(beLogDir)) return;

            try
            {
                foreach (string logFile in Directory.EnumerateFiles(beLogDir, "*.log", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct).ConfigureAwait(false);

                        string[] bypassLogPatterns =
                        [
                            "bypass", "hook detected", "anti-cheat disabled", "injection detected",
                            "patch applied", "driver blocked", "service terminated", "cheat engine",
                            "memory manipulation", "signature bypass",
                        ];

                        foreach (string pattern in bypassLogPatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "BattleEye Log Contains Bypass/Detection Pattern",
                                    Risk = Risk.High,
                                    Location = logFile,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"BattleEye log contains suspicious keyword: '{pattern}'",
                                    Detail = $"Log file at '{logFile}' shows possible bypass activity"
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

    private Task ScanUserAssistForBeBypassExecution(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                using RegistryKey? muiKey = Registry.CurrentUser.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
                if (muiKey == null) return;
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
                            foreach (string bypassName in KnownBeBypassExeNames)
                            {
                                if (decoded.Contains(bypassName, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "BattleEye Bypass Tool Execution in UserAssist",
                                        Risk = Risk.Critical,
                                        Location = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                                        FileName = "registry",
                                        Reason = "BattleEye bypass tool was previously launched (UserAssist log)",
                                        Detail = $"UserAssist execution record: {decoded}"
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
            catch (UnauthorizedAccessException) { }
        }, ct);
    }

    private Task ScanMuiCacheForBeBypass(ScanContext ctx, CancellationToken ct)
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
                    foreach (string bypassName in KnownBeBypassExeNames)
                    {
                        if (valName.Contains(bypassName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "BattleEye Bypass Tool Execution in MUICache",
                                Risk = Risk.Critical,
                                Location = @"HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                                FileName = "registry",
                                Reason = "MUICache records previous execution of BattleEye bypass tool",
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

    private static string Rot13Decode(string input)
    {
        return new string(input.Select(c =>
            c >= 'a' && c <= 'z' ? (char)('a' + (c - 'a' + 13) % 26) :
            c >= 'A' && c <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) : c).ToArray());
    }
}
