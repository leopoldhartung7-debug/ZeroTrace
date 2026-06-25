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

public sealed class RageMPScriptInjectionScanModule : IScanModule
{
    public string Name => "RageMP Script Injection & Native Hook Forensic Scan";
    public double Weight => 4.2;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string LocalApp =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string Desktop = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop");
    private static readonly string Downloads = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
    private static readonly string TempDir = Path.GetTempPath();

    private static readonly string RageMPAppData = Path.Combine(AppData, "RAGEMP");
    private static readonly string RageMPLocalApp = Path.Combine(LocalApp, "RAGEMP");
    private static readonly string RageMPCache = Path.Combine(AppData, "RAGEMP", "cache");
    private static readonly string RageMPLocalCache = Path.Combine(LocalApp, "RAGEMP", "cache");
    private static readonly string RageMPPackages = Path.Combine(AppData, "RAGEMP", "packages");
    private static readonly string RageMPClientPackages = Path.Combine(AppData, "RAGEMP", "client_packages");
    private static readonly string RageMPLogs = Path.Combine(AppData, "RAGEMP", "logs");

    private static readonly string[] RageMPRootPaths =
    {
        Path.Combine(AppData, "RAGEMP"),
        Path.Combine(LocalApp, "RAGEMP"),
        Path.Combine(AppData, "RAGE Multiplayer"),
        Path.Combine(LocalApp, "RAGE Multiplayer"),
        @"C:\RAGEMP",
        @"C:\Program Files\RAGE Multiplayer",
        @"C:\Program Files (x86)\RAGE Multiplayer",
    };

    private static readonly HashSet<string> InjectExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "ragemp_inject.exe",
        "ragemp_hook.exe",
        "ragemp_native_hook.exe",
        "ragemp_script_inject.exe",
        "ragemp_bypass.exe",
        "ragemp_loader.exe",
        "ragemp_injector.exe",
        "ragemp_native.exe",
        "ragemp_menu.exe",
        "ragemp_trainer.exe",
        "ragemp_mod.exe",
        "ragemp_cheat.exe",
        "ragemp_hack.exe",
        "ragemp_exploit.exe",
        "rage_inject.exe",
        "rage_hook.exe",
        "rage_bypass.exe",
        "rage_loader.exe",
        "rage_native.exe",
        "rage_menu.exe",
        "rage_trainer.exe",
        "rage_mod.exe",
        "inject_ragemp.exe",
        "hook_ragemp.exe",
        "bypass_ragemp.exe",
        "native_ragemp.exe",
        "ragemp_internal.exe",
        "ragemp_external.exe",
        "ragemp_sdk.exe",
        "ragemp_dev.exe",
        "node_inject.exe",
        "node_hook.exe",
        "node_bypass.exe",
        "cef_inject.exe",
        "cef_hook.exe",
        "cef_bypass.exe",
        "v8_inject.exe",
        "v8_hook.exe",
        "js_inject.exe",
        "js_hook.exe",
        "js_bypass.exe",
        "script_inject_rage.exe",
        "script_hook_rage.exe",
        "script_bypass_rage.exe",
        "native_inject_rage.exe",
        "native_hook_rage.exe",
        "native_bypass_rage.exe",
        "ragemp_dll_inject.exe",
        "ragemp_code_inject.exe",
        "ragemp_mem_inject.exe",
        "ragemp_pe_inject.exe",
        "mem_inject_rage.exe",
        "pe_inject_rage.exe",
        "code_inject_rage.exe",
        "dll_inject_rage.exe",
        "ragemp_hook_v2.exe",
        "ragemp_inject_v2.exe",
        "ragemp_bypass_v2.exe",
        "rage_cheat_v2.exe",
        "rage_hack_v2.exe",
        "rage_exploit_v2.exe",
        "rage_menu_v2.exe",
        "rage_trainer_v2.exe",
    };

    private static readonly HashSet<string> InjectDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "ragemp_inject.dll",
        "ragemp_hook.dll",
        "ragemp_native_hook.dll",
        "ragemp_bypass.dll",
        "ragemp_loader.dll",
        "ragemp_native.dll",
        "ragemp_menu.dll",
        "ragemp_trainer.dll",
        "ragemp_mod.dll",
        "ragemp_cheat.dll",
        "ragemp_hack.dll",
        "rage_inject.dll",
        "rage_hook.dll",
        "rage_bypass.dll",
        "rage_native.dll",
        "inject_ragemp.dll",
        "hook_ragemp.dll",
        "bypass_ragemp.dll",
        "node_inject.dll",
        "node_hook.dll",
        "cef_inject.dll",
        "cef_hook.dll",
        "v8_inject.dll",
        "js_inject.dll",
        "js_hook.dll",
        "script_inject.dll",
        "script_hook.dll",
        "native_inject.dll",
        "native_hook.dll",
        "ragemp_internal.dll",
        "ragemp_external.dll",
        "ragemp_dll.dll",
        "ragemp_lib.dll",
        "rage_dll.dll",
        "rage_lib.dll",
        "inject_dll_rage.dll",
        "hook_dll_rage.dll",
        "bypass_dll_rage.dll",
        "ragemp_hook_v2.dll",
        "ragemp_inject_v2.dll",
        "ragemp_bypass_v2.dll",
        "rage_cheat.dll",
        "rage_hack.dll",
        "rage_exploit.dll",
        "native_bypass.dll",
        "code_bypass.dll",
        "memory_bypass.dll",
        "process_bypass.dll",
        "hook_bypass.dll",
        "inject_bypass.dll",
    };

    private static readonly string[] ScriptCheatKeywords =
    {
        "mp.events.addProc",
        "mp.players.forEachFast",
        "NativeHook",
        "InlineHook",
        "InvokeNative",
        "native.invoke",
        "hook_native",
        "inject_native",
        "bypass_check",
        "bypass_anticheat",
        "bypass_detection",
        "exploit",
        "overwrite_native",
        "overwrite_function",
        "hook_function",
        "inject_code",
        "write_memory",
        "patch_bytes",
        "jmp_hook",
        "call_hook",
        "detour",
        "iat_hook",
        "vtable_hook",
    };

    private static readonly HashSet<string> OffsetFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "offsets.txt",
        "offsets.json",
        "ragemp_offsets.txt",
        "rage_offsets.txt",
        "addresses.txt",
        "addresses.json",
        "native_offsets.txt",
        "patterns.txt",
        "signatures.txt",
        "hook_offsets.txt",
        "inject_offsets.txt",
    };

    private static readonly string[] OffsetFileKeywords =
    {
        "GTA5",
        "RageMP",
        "native",
        "hook",
        "inject",
        "bypass",
    };

    private static readonly string[] ClientLogPatterns =
    {
        "native hook detected",
        "script inject detected",
        "code injection",
        "hook detected",
        "inject detected",
        "bypass detected",
        "dll inject",
        "hook attempt",
        "native override",
        "function hook",
        "memory patch",
        "byte patch",
        "anti-cheat: hook",
        "ac: inject",
        "cheat: hook",
        "cheat: inject",
        "ban for hook",
        "ban for inject",
        "ban for bypass",
        "kick for hook",
        "kick for inject",
        "kick for bypass",
        "suspicious native",
        "suspicious function",
        "suspicious memory",
        "resource hook",
        "resource inject",
        "resource bypass",
        "package hook",
        "package inject",
        "package bypass",
        "cef exploit",
        "v8 exploit",
        "node exploit",
        "js inject",
        "js hook",
        "script bypass",
        "native integrity check failed",
        "memory write detected",
        "inline hook detected",
        "vtable corruption",
        "iat hook detected",
        "export hook detected",
        "detour detected",
        "trampoline hook",
    };

    private static readonly string[] ServerLogPatterns =
    {
        "client hook detected",
        "client inject detected",
        "client bypass detected",
        "native hook detected",
        "script injection",
        "code injection",
        "dll injection",
        "memory patch",
        "byte patch",
        "hook attempt",
        "inject attempt",
        "bypass attempt",
        "client modified natives",
        "client patched function",
        "client bypassed check",
        "anti-cheat triggered: hook",
        "anti-cheat triggered: inject",
        "ban for native hook",
        "ban for script inject",
        "kick for native hook",
        "kick for script inject",
        "suspicious native call",
        "suspicious function call",
        "suspicious package",
        "resource banned: hook",
        "resource banned: inject",
        "package banned: hook",
        "package banned: inject",
        "cef exploit detected",
        "v8 exploit detected",
        "node injection detected",
        "js hook detected",
        "js inject detected",
        "client integrity failed",
        "ragemp bypass detected",
        "native return spoof",
        "exec native blocked",
        "memory access violation",
        "function address tampered",
        "event bypass detected",
        "sync bypass detected",
    };

    private static readonly HashSet<string> SuspiciousResourceFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        "hook",
        "inject",
        "native_hook",
        "script_inject",
        "dll_inject",
        "code_inject",
        "bypass",
        "loader",
        "injector",
        "hack",
        "cheat",
        "exploit",
        "ragemp_hook",
        "ragemp_inject",
        "ragemp_bypass",
        "rage_hook",
        "rage_inject",
        "rage_bypass",
        "native_bypass",
        "code_bypass",
        "hook_bypass",
        "ragemp_trainer",
        "ragemp_mod",
        "ragemp_menu",
        "script_hook",
        "script_bypass",
        "resource_hook",
        "resource_inject",
        "node_hook",
        "node_inject",
        "cef_hook",
        "cef_inject",
        "v8_hook",
        "v8_inject",
        "js_hook",
        "js_inject",
        "hook_v2",
        "inject_v2",
        "bypass_v2",
        "hook_menu",
        "inject_menu",
        "bypass_menu",
        "trainer_hook",
        "mod_hook",
        "hack_hook",
        "exploit_hook",
        "hook_loader",
        "inject_loader",
        "bypass_loader",
        "hook_dll",
        "inject_dll",
        "bypass_dll",
    };

    private static readonly HashSet<string> DownloadArchiveNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "ragemp_inject.zip",
        "ragemp_inject.rar",
        "ragemp_inject.7z",
        "ragemp_hook.zip",
        "ragemp_hook.rar",
        "ragemp_hook.7z",
        "ragemp_native_hook.zip",
        "ragemp_native_hook.rar",
        "ragemp_native_hook.7z",
        "ragemp_bypass.zip",
        "ragemp_bypass.rar",
        "ragemp_bypass.7z",
        "ragemp_loader.zip",
        "ragemp_loader.rar",
        "ragemp_loader.7z",
        "ragemp_cheat.zip",
        "ragemp_cheat.rar",
        "ragemp_cheat.7z",
        "ragemp_hack.zip",
        "ragemp_hack.rar",
        "ragemp_hack.7z",
        "ragemp_exploit.zip",
        "ragemp_exploit.rar",
        "ragemp_trainer.zip",
        "ragemp_trainer.rar",
        "ragemp_menu.zip",
        "ragemp_menu.rar",
        "ragemp_mod.zip",
        "ragemp_mod.rar",
        "rage_inject.zip",
        "rage_inject.rar",
        "rage_hook.zip",
        "rage_hook.rar",
        "rage_bypass.zip",
        "rage_bypass.rar",
        "node_inject.zip",
        "node_inject.rar",
        "cef_inject.zip",
        "cef_inject.rar",
        "cef_hook.zip",
        "cef_hook.rar",
        "v8_inject.zip",
        "v8_inject.rar",
        "js_inject.zip",
        "js_inject.rar",
        "js_hook.zip",
        "js_hook.rar",
        "script_inject_rage.zip",
        "script_inject_rage.rar",
    };

    private static readonly string[] UserAssistToolNames =
    {
        "ragemp_inject",
        "ragemp_hook",
        "ragemp_native_hook",
        "ragemp_script_inject",
        "ragemp_bypass",
        "ragemp_loader",
        "ragemp_injector",
        "ragemp_cheat",
        "ragemp_hack",
        "ragemp_exploit",
        "rage_inject",
        "rage_hook",
        "rage_bypass",
        "inject_ragemp",
        "hook_ragemp",
        "bypass_ragemp",
        "node_inject",
        "node_hook",
        "cef_inject",
        "cef_hook",
        "v8_inject",
        "js_inject",
        "js_hook",
        "script_inject_rage",
        "script_hook_rage",
        "native_inject_rage",
        "native_hook_rage",
        "ragemp_menu",
        "ragemp_trainer",
        "ragemp_mod",
        "ragemp_internal",
        "ragemp_external",
        "ragemp_hook_v2",
        "ragemp_inject_v2",
        "ragemp_bypass_v2",
    };

    private static readonly string[] MuiCacheToolNames =
    {
        "ragemp_inject",
        "ragemp_hook",
        "ragemp_bypass",
        "ragemp_loader",
        "ragemp_cheat",
        "ragemp_hack",
        "rage_inject",
        "rage_hook",
        "rage_bypass",
        "node_inject",
        "node_hook",
        "cef_inject",
        "cef_hook",
        "v8_inject",
        "js_inject",
        "js_hook",
        "script_inject_rage",
        "native_hook_rage",
        "ragemp_menu",
        "ragemp_trainer",
        "ragemp_exploit",
        "ragemp_hook_v2",
        "ragemp_inject_v2",
        "ragemp_bypass_v2",
        "rage_cheat_v2",
        "rage_hack_v2",
        "inject_dll_rage",
        "hook_dll_rage",
        "bypass_dll_rage",
        "native_bypass",
    };

    private static readonly string[] CacheCheatFileKeywords =
    {
        "inject",
        "hook",
        "bypass",
        "cheat",
        "hack",
        "exploit",
        "loader",
        "trainer",
        "menu",
        "native",
        "patch",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckRageMPInjectExecutables(ctx, ct),
            CheckRageMPInjectDlls(ctx, ct),
            CheckRageMPInjectScriptFiles(ctx, ct),
            CheckRageMPInjectOffsetFiles(ctx, ct),
            CheckRageMPCacheCheatFiles(ctx, ct),
            CheckRageMPInjectClientLogs(ctx, ct),
            CheckRageMPInjectServerLogs(ctx, ct),
            CheckRageMPInjectResourceFolders(ctx, ct),
            CheckRageMPInjectDownloadArtifacts(ctx, ct),
            CheckRegistryForRageMPInjection(ctx, ct)
        );
    }

    private Task CheckRageMPInjectExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new List<string>
        {
            Desktop,
            Downloads,
            TempDir,
            Path.Combine(LocalApp, "Temp"),
            AppData,
            LocalApp,
        };
        searchDirs.AddRange(RageMPRootPaths);

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.exe", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);
                if (!InjectExeNames.Contains(fileName)) continue;

                string content = string.Empty;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RageMP Script Injection / Hook Executable: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Executable '{fileName}' matches a known RageMP script injection or native hook " +
                             "tool name. These tools are used to inject JavaScript/Node.js code into RageMP " +
                             "client packages, hook native GTA5 functions via the CEF/V8 bridge, or bypass " +
                             "RageMP server-side anti-cheat validation.",
                    Detail = $"Found in: {dir}"
                });
            }
        }
    }, ct);

    private Task CheckRageMPInjectDlls(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new List<string>
        {
            Desktop,
            Downloads,
            TempDir,
            Path.Combine(LocalApp, "Temp"),
            AppData,
            LocalApp,
        };
        searchDirs.AddRange(RageMPRootPaths);

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.dll", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);
                if (!InjectDllNames.Contains(fileName)) continue;

                string content = string.Empty;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RageMP Injection / Hook DLL: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"DLL '{fileName}' matches a known RageMP script injection or native hook library. " +
                             "These DLLs are injected into RageMP client processes (ragemp_v.exe) to hook " +
                             "native GTA5 game functions, intercept CEF/V8/Node.js calls, or bypass " +
                             "RageMP anti-cheat integrity checks.",
                    Detail = $"Found in: {dir}"
                });
            }
        }
    }, ct);

    private Task CheckRageMPInjectScriptFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scriptDirs = new List<string>
        {
            RageMPPackages,
            RageMPClientPackages,
            Path.Combine(RageMPAppData, "client_packages"),
            Path.Combine(RageMPAppData, "packages"),
            Path.Combine(RageMPLocalApp, "client_packages"),
            Path.Combine(RageMPLocalApp, "packages"),
        };
        foreach (var root in RageMPRootPaths)
        {
            scriptDirs.Add(Path.Combine(root, "packages"));
            scriptDirs.Add(Path.Combine(root, "client_packages"));
        }

        var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".js", ".mjs", ".cjs", ".ts" };

        foreach (var dir in scriptDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                var ext = Path.GetExtension(file);
                if (!extensions.Contains(ext)) continue;

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException)
                {
                    continue;
                }

                int matchCount = 0;
                var matchedKeywords = new List<string>();
                foreach (var kw in ScriptCheatKeywords)
                {
                    if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        matchCount++;
                        matchedKeywords.Add(kw);
                    }
                }

                if (matchCount >= 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP Script Injection / Hook Script: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Script file '{Path.GetFileName(file)}' in RageMP packages directory " +
                                 $"contains {matchCount} keywords associated with RageMP script injection " +
                                 "or native hook cheats. These scripts exploit the RageMP CEF/V8/Node.js " +
                                 "scripting bridge to invoke native GTA5 functions, patch game memory, " +
                                 "or bypass server-side anti-cheat validation.",
                        Detail = $"Matched keywords ({matchCount}): {string.Join(", ", matchedKeywords.Take(10))}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckRageMPInjectOffsetFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new List<string>
        {
            Desktop,
            Downloads,
        };
        searchDirs.AddRange(RageMPRootPaths);
        searchDirs.Add(RageMPAppData);
        searchDirs.Add(RageMPLocalApp);

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                var fileName = Path.GetFileName(file);
                if (!OffsetFileNames.Contains(fileName)) continue;

                ctx.IncrementFiles();
                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException)
                {
                    continue;
                }

                bool hasHexPattern = content.Contains("0x", StringComparison.OrdinalIgnoreCase);
                bool hasKeyword = OffsetFileKeywords.Any(k =>
                    content.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (!hasHexPattern && !hasKeyword) continue;

                var matchedKws = OffsetFileKeywords
                    .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RageMP Hook Offset / Address File: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Offset/address file '{fileName}' contains " +
                             (hasHexPattern ? "hexadecimal memory addresses (0x prefixed) " : "") +
                             (hasKeyword ? $"and keywords: {string.Join(", ", matchedKws)}" : "") +
                             ". Offset files containing GTA5/RageMP native addresses or memory patterns " +
                             "are used by hook and injection cheats to locate game functions at runtime " +
                             "for patching or intercepting.",
                    Detail = $"Hex patterns present: {hasHexPattern}; Keywords: {string.Join(", ", matchedKws)}"
                });
            }
        }
    }, ct);

    private Task CheckRageMPCacheCheatFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            RageMPCache,
            RageMPLocalCache,
            RageMPAppData,
            RageMPLocalApp,
            Path.Combine(AppData, "RAGE Multiplayer"),
            Path.Combine(LocalApp, "RAGE Multiplayer"),
        };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var ext = Path.GetExtension(file);
                bool isDll = ext.Equals(".dll", StringComparison.OrdinalIgnoreCase);
                bool isSys = ext.Equals(".sys", StringComparison.OrdinalIgnoreCase);
                if (!isDll && !isSys) continue;

                var fileName = Path.GetFileName(file);
                var fileNameLower = fileName.ToLowerInvariant();
                bool matchesKeyword = CacheCheatFileKeywords.Any(k =>
                    fileNameLower.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (isSys)
                {
                    string content = string.Empty;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Kernel Driver (.sys) in RageMP Cache: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"A kernel driver file '{fileName}' was found in the RageMP application " +
                                 "data directories. Kernel drivers in RageMP cache directories are strongly " +
                                 "suspicious and may represent BYOVD-based bypass tools loaded to disable " +
                                 "RageMP anti-cheat or kernel integrity checks at the driver level.",
                        Detail = $"Directory: {dir}"
                    });
                    continue;
                }

                if (!matchesKeyword) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspicious Inject/Hook DLL in RageMP Cache: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"DLL '{fileName}' with injection or hook-related name was found in RageMP " +
                             "cache or application data directories. Cheat DLLs are sometimes staged in " +
                             "cache directories to evade detection scans before being loaded into the " +
                             "RageMP game process (ragemp_v.exe).",
                    Detail = $"Directory: {dir}"
                });
            }
        }
    }, ct);

    private Task CheckRageMPInjectClientLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logDirs = new List<string>
        {
            RageMPLogs,
            RageMPAppData,
            RageMPLocalApp,
            Path.Combine(RageMPLocalApp, "logs"),
            Path.Combine(AppData, "RAGE Multiplayer", "logs"),
        };
        foreach (var root in RageMPRootPaths)
            logDirs.Add(Path.Combine(root, "logs"));

        foreach (var dir in logDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.log", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException)
                {
                    continue;
                }

                var contentLower = content.ToLowerInvariant();
                foreach (var pattern in ClientLogPatterns)
                {
                    if (!contentLower.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Client Log: Script Injection / Hook Pattern",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"RageMP client log file contains the pattern '{pattern}', indicating that " +
                                 "a script injection or native hook cheat was detected or attempted during " +
                                 "a RageMP session on this system. Client log entries from anti-cheat events " +
                                 "are strong forensic evidence of active cheat engagement.",
                        Detail = $"Pattern matched: '{pattern}'"
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckRageMPInjectServerLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var serverLogDirs = new List<string>
        {
            Path.Combine(UserProfile, "ragemp-server", "logs"),
            Path.Combine(UserProfile, "ragemp-server", "log"),
            Path.Combine(UserProfile, "RageMP-server", "logs"),
            Path.Combine(UserProfile, "server", "logs"),
            Path.Combine(RageMPAppData, "server", "logs"),
            Path.Combine(RageMPLocalApp, "server", "logs"),
            Path.Combine(AppData, "RAGE Multiplayer", "server", "logs"),
        };
        foreach (var root in RageMPRootPaths)
        {
            serverLogDirs.Add(Path.Combine(root, "server", "logs"));
            serverLogDirs.Add(Path.Combine(root, "log"));
        }

        foreach (var dir in serverLogDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.log", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException)
                {
                    continue;
                }

                var contentLower = content.ToLowerInvariant();
                foreach (var pattern in ServerLogPatterns)
                {
                    if (!contentLower.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP Server Log: Injection / Hook Detection Record",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"RageMP server log contains the pattern '{pattern}', indicating that the " +
                                 "server detected or logged a script injection or native hook event from a " +
                                 "client. Server-side detection records are authoritative forensic evidence " +
                                 "since they originate from the game server and cannot be tampered by the client.",
                        Detail = $"Pattern matched: '{pattern}'"
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckRageMPInjectResourceFolders(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var resourceRoots = new List<string>
        {
            RageMPPackages,
            RageMPClientPackages,
            Path.Combine(RageMPAppData, "packages"),
            Path.Combine(RageMPAppData, "client_packages"),
            Path.Combine(RageMPLocalApp, "packages"),
            Path.Combine(RageMPLocalApp, "client_packages"),
        };
        foreach (var root in RageMPRootPaths)
        {
            resourceRoots.Add(Path.Combine(root, "packages"));
            resourceRoots.Add(Path.Combine(root, "client_packages"));
        }

        foreach (var root in resourceRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            string[] subDirs;
            try
            {
                subDirs = Directory.GetDirectories(root, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var subDir in subDirs)
            {
                if (ct.IsCancellationRequested) return;
                var folderName = Path.GetFileName(subDir);
                if (!SuspiciousResourceFolders.Contains(folderName)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspicious RageMP Package Folder: {folderName}",
                    Risk = RiskLevel.High,
                    Location = subDir,
                    FileName = folderName,
                    Reason = $"Package/resource folder '{folderName}' found in RageMP packages or " +
                             "client_packages directories matches a known inject, hook, or bypass cheat " +
                             "package name. Cheat packages loaded through the RageMP package system can " +
                             "invoke native GTA5 functions, manipulate game memory, inject JavaScript " +
                             "through the CEF bridge, or bypass server anti-cheat checks.",
                    Detail = $"Parent directory: {root}"
                });
            }
        }
    }, ct);

    private Task CheckRageMPInjectDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var searchDirs = new[] { Downloads, Desktop };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*.*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);
                if (!DownloadArchiveNames.Contains(fileName)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"RageMP Inject/Hook Archive Download: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Archive file '{fileName}' matching a known RageMP script injection or native " +
                             "hook cheat tool name was found in Downloads or Desktop. The presence of this " +
                             "archive is a strong forensic indicator that the user downloaded a RageMP cheat " +
                             "package, even if the extracted files have since been removed.",
                    Detail = $"Found in: {dir}"
                });
            }
        }
    }, ct);

    private Task CheckRegistryForRageMPInjection(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        CheckUserAssistForRageMPInject(ctx, ct);
        CheckMuiCacheForRageMPInject(ctx, ct);
        CheckRunKeysForRageMPInject(ctx, ct);
        CheckSoftwareKeysForRageMPInject(ctx, ct);
        CheckUninstallKeysForRageMPInject(ctx, ct);
    }, ct);

    private void CheckUserAssistForRageMPInject(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var ua = baseKey.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (ua is null) return;

            foreach (var guid in ua.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                using var count = ua.OpenSubKey($@"{guid}\Count");
                if (count is null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var valueName in count.GetValueNames())
                {
                    var decoded = Rot13Decode(valueName);
                    if (string.IsNullOrWhiteSpace(decoded)) continue;
                    var decodedLower = decoded.ToLowerInvariant();

                    foreach (var toolName in UserAssistToolNames)
                    {
                        if (!decodedLower.Contains(toolName, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP Inject Tool in UserAssist (Executed): {toolName}",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                            Reason = $"UserAssist registry key records execution of a program matching the " +
                                     $"RageMP injection/hook tool name '{toolName}'. UserAssist tracks GUI " +
                                     "program launches, making this a strong forensic indicator that this " +
                                     "tool was actively run on this system during a RageMP session.",
                            Detail = $"Decoded value: {decoded} (ROT13 encoded in registry)"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }

    private void CheckMuiCacheForRageMPInject(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var mui = baseKey.OpenSubKey(
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
            if (mui is null) return;
            ctx.IncrementRegistryKeys();

            foreach (var valueName in mui.GetValueNames())
            {
                if (ct.IsCancellationRequested) return;
                var nameLower = valueName.ToLowerInvariant();

                foreach (var toolName in MuiCacheToolNames)
                {
                    if (!nameLower.Contains(toolName, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP Hook Tool in MUICache: {toolName}",
                        Risk = RiskLevel.High,
                        Location = @"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                        Reason = $"MUICache registry entry references a path containing '{toolName}', a known " +
                                 "RageMP injection or hook tool name. MUICache records display names of " +
                                 "previously executed applications, providing forensic evidence of cheat " +
                                 "tool execution even after the file has been deleted.",
                        Detail = $"Registry value name: {valueName}"
                    });
                    break;
                }
            }
        }
        catch { }
    }

    private void CheckRunKeysForRageMPInject(ScanContext ctx, CancellationToken ct)
    {
        var runKeyPaths = new[]
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        foreach (var keyPath in runKeyPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
                using var key = baseKey.OpenSubKey(keyPath);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    var valueData = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    var combinedLower = (valueName + " " + valueData).ToLowerInvariant();

                    bool matchesInject = UserAssistToolNames.Any(t =>
                        combinedLower.Contains(t, StringComparison.OrdinalIgnoreCase));
                    if (!matchesInject) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP Inject Tool Auto-Start Registry Entry: {valueName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{keyPath}",
                        Reason = $"Registry Run key '{keyPath}' contains an auto-start entry '{valueName}' " +
                                 "referencing a RageMP injection or hook tool. Auto-start entries ensure the " +
                                 "cheat tool launches automatically with Windows, indicating persistent " +
                                 "cheat installation targeting RageMP sessions.",
                        Detail = $"Value: {valueName} = {valueData}"
                    });
                }
            }
            catch { }

            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
                using var key = baseKey.OpenSubKey(keyPath);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    var valueData = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    var combinedLower = (valueName + " " + valueData).ToLowerInvariant();

                    bool matchesInject = UserAssistToolNames.Any(t =>
                        combinedLower.Contains(t, StringComparison.OrdinalIgnoreCase));
                    if (!matchesInject) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP Inject Tool System Auto-Start: {valueName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{keyPath}",
                        Reason = $"System-wide registry Run key contains '{valueName}' referencing a RageMP " +
                                 "injection or hook tool. A system-level auto-start entry indicates the cheat " +
                                 "tool was installed with administrative privileges for persistent access " +
                                 "to all RageMP game sessions.",
                        Detail = $"Value: {valueName} = {valueData}"
                    });
                }
            }
            catch { }
        }
    }

    private void CheckSoftwareKeysForRageMPInject(ScanContext ctx, CancellationToken ct)
    {
        var softwareKeyPaths = new[]
        {
            @"Software\RageMPInject",
            @"Software\RageMPHook",
            @"Software\RageMPNativeHook",
            @"Software\RageMPBypass",
            @"Software\RageMPLoader",
            @"Software\RageMPCheat",
            @"Software\RageInject",
            @"Software\RageHook",
            @"Software\RageBypass",
            @"Software\NodeInject",
            @"Software\CefInject",
            @"Software\V8Inject",
            @"Software\JsInject",
            @"Software\JsHook",
            @"Software\ScriptInjectRage",
            @"Software\NativeHookRage",
        };

        foreach (var keyPath in softwareKeyPaths)
        {
            if (ct.IsCancellationRequested) return;
            foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                    using var key = baseKey.OpenSubKey(keyPath);
                    if (key is null) continue;
                    ctx.IncrementRegistryKeys();

                    var hiveName = hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM";
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"RageMP Inject Tool Registry Key: {keyPath}",
                        Risk = RiskLevel.High,
                        Location = $@"{hiveName}\{keyPath}",
                        Reason = $"Registry key '{keyPath}' associated with a RageMP script injection or native " +
                                 "hook tool was found. Cheat tools typically write registry keys during " +
                                 "installation or first-run configuration, and their presence strongly " +
                                 "indicates this tool was installed on this system.",
                        Detail = $"Hive: {hiveName}"
                    });
                }
                catch { }
            }
        }
    }

    private void CheckUninstallKeysForRageMPInject(ScanContext ctx, CancellationToken ct)
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        var cheatInstallerKeywords = new[]
        {
            "ragemp inject", "ragemp hook", "ragemp native hook", "ragemp bypass",
            "ragemp cheat", "ragemp hack", "ragemp exploit", "ragemp trainer",
            "ragemp mod", "ragemp menu", "rage inject", "rage hook", "rage bypass",
            "node inject", "cef inject", "cef hook", "v8 inject", "js inject",
            "js hook", "script inject rage", "native hook rage", "ragemp loader",
        };

        foreach (var uninstallPath in uninstallPaths)
        {
            if (ct.IsCancellationRequested) return;
            foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
            {
                try
                {
                    using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                    using var uninstall = baseKey.OpenSubKey(uninstallPath);
                    if (uninstall is null) continue;

                    foreach (var subKeyName in uninstall.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        using var subKey = uninstall.OpenSubKey(subKeyName);
                        if (subKey is null) continue;
                        ctx.IncrementRegistryKeys();

                        var displayName = subKey.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        var displayNameLower = displayName.ToLowerInvariant();

                        bool isCheatInstaller = cheatInstallerKeywords.Any(k =>
                            displayNameLower.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (!isCheatInstaller) continue;

                        var installLocation = subKey.GetValue("InstallLocation")?.ToString() ?? string.Empty;
                        var hiveName = hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM";

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP Cheat Tool Installer Entry: {displayName}",
                            Risk = RiskLevel.High,
                            Location = $@"{hiveName}\{uninstallPath}\{subKeyName}",
                            Reason = $"Uninstall registry entry '{displayName}' matches a known RageMP " +
                                     "script injection or hook cheat tool installer. A formal installer " +
                                     "entry is stronger forensic evidence than loose file artifacts, " +
                                     "indicating the cheat tool was intentionally installed on this system.",
                            Detail = string.IsNullOrEmpty(installLocation)
                                ? $"Product key: {subKeyName}"
                                : $"Install location: {installLocation}"
                        });
                    }
                }
                catch { }
            }
        }
    }

    private static string Rot13Decode(string s)
    {
        var chars = s.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (c >= 'A' && c <= 'Z')
                chars[i] = (char)('A' + (c - 'A' + 13) % 26);
            else if (c >= 'a' && c <= 'z')
                chars[i] = (char)('a' + (c - 'a' + 13) % 26);
        }
        return new string(chars);
    }
}
