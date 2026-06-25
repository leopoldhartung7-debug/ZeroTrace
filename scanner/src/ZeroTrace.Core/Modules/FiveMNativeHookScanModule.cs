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

public sealed class FiveMNativeHookScanModule : IScanModule
{
    public string Name => "FiveM Native Hook & Code Injection Forensic Scan";
    public double Weight => 4.3;
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

    private static readonly string FiveMLocalApp = Path.Combine(LocalApp, "FiveM");
    private static readonly string FiveMApp = Path.Combine(LocalApp, "FiveM", "FiveM.app");
    private static readonly string FiveMCache = Path.Combine(LocalApp, "FiveM", "FiveM.app", "cache");
    private static readonly string CitizenFX = Path.Combine(AppData, "CitizenFX");
    private static readonly string CitizenFXLogs = Path.Combine(AppData, "CitizenFX", "logs");

    private static readonly HashSet<string> HookExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "fivem_hook.exe",
        "fivem_inject.exe",
        "fivem_native_hook.exe",
        "fivem_code_inject.exe",
        "fivem_dll_inject.exe",
        "fivem_internal.exe",
        "fivem_external.exe",
        "fivem_bypass.exe",
        "fivem_loader.exe",
        "fivem_injector.exe",
        "native_hook.exe",
        "native_injector.exe",
        "code_inject_fivem.exe",
        "dll_inject_fivem.exe",
        "hook_fivem.exe",
        "inject_fivem.exe",
        "bypass_fivem.exe",
        "fivem_native.exe",
        "fivem_menu.exe",
        "fivem_trainer.exe",
        "fivem_mod.exe",
        "fivem_cheat.exe",
        "fivem_hack.exe",
        "fivem_exploit.exe",
        "hook_injector.exe",
        "hook_loader.exe",
        "hook_bypass.exe",
        "hook_inject.exe",
        "native_bypass.exe",
        "native_loader.exe",
        "native_inject.exe",
        "code_hook.exe",
        "code_loader.exe",
        "dll_hook.exe",
        "dll_loader.exe",
        "pe_inject.exe",
        "pe_loader.exe",
        "process_inject.exe",
        "process_hook.exe",
        "memory_hook.exe",
        "memory_inject.exe",
        "fivem_api.exe",
        "fivem_sdk.exe",
        "fivem_dev.exe",
        "fivem_debug.exe",
        "fivem_patch.exe",
        "fivem_patcher.exe",
        "lua_inject.exe",
        "lua_hook.exe",
        "lua_bypass.exe",
        "lua_loader.exe",
        "lua_exec.exe",
        "script_inject.exe",
        "script_hook.exe",
        "scripthookv.exe",
        "scripthookv2.exe",
        "scripthookv3.exe",
        "script_bypass.exe",
        "script_loader.exe",
        "resource_inject.exe",
        "resource_hook.exe",
        "resource_loader.exe",
        "citizen_inject.exe",
        "citizen_hook.exe",
        "citizen_loader.exe",
    };

    private static readonly HashSet<string> HookDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "fivem_hook.dll",
        "fivem_native_hook.dll",
        "fivem_code_inject.dll",
        "fivem_bypass.dll",
        "fivem_loader.dll",
        "native_hook.dll",
        "native_injector.dll",
        "code_inject.dll",
        "hook_inject.dll",
        "dll_inject.dll",
        "bypass_hook.dll",
        "hook_bypass.dll",
        "native_bypass.dll",
        "code_bypass.dll",
        "hook_loader.dll",
        "native_loader.dll",
        "code_loader.dll",
        "fivem_internal.dll",
        "fivem_external.dll",
        "fivem_menu.dll",
        "fivem_trainer.dll",
        "fivem_mod.dll",
        "fivem_cheat.dll",
        "fivem_hack.dll",
        "fivem_exploit.dll",
        "hook_dll.dll",
        "hook_lib.dll",
        "inject_dll.dll",
        "inject_lib.dll",
        "bypass_dll.dll",
        "bypass_lib.dll",
        "lua_hook.dll",
        "lua_inject.dll",
        "lua_bypass.dll",
        "lua_loader.dll",
        "script_hook.dll",
        "script_inject.dll",
        "script_bypass.dll",
        "resource_hook.dll",
        "resource_inject.dll",
        "citizen_hook.dll",
        "citizen_inject.dll",
        "fivem_api.dll",
        "fivem_sdk.dll",
        "hook_v2.dll",
        "inject_v2.dll",
        "bypass_v2.dll",
        "loader_v2.dll",
        "hook_x64.dll",
        "inject_x64.dll",
    };

    private static readonly string[] ScriptCheatKeywords =
    {
        "Citizen.InvokeNative",
        "Hook",
        "NativeHook",
        "InlineHook",
        "VTableHook",
        "IAT_Hook",
        "EATHook",
        "Detour",
        "hook_function",
        "inject_code",
        "write_memory",
        "patch_bytes",
        "nop_instruction",
        "jmp_hook",
        "call_hook",
        "bypass_check",
        "bypass_anticheat",
        "bypass_detection",
        "exploit",
        "overwrite_native",
        "overwrite_function",
        "hook_native",
        "inject_native",
        "patch_native",
        "bypass_native",
    };

    private static readonly HashSet<string> OffsetFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "offsets.txt",
        "offsets.json",
        "offsets.ini",
        "addresses.txt",
        "addresses.json",
        "natives.txt",
        "natives.json",
        "native_offsets.txt",
        "patterns.txt",
        "patterns.json",
        "signatures.txt",
        "hook_offsets.txt",
        "inject_offsets.txt",
        "bypass_offsets.txt",
    };

    private static readonly string[] OffsetFileKeywords =
    {
        "GTA5",
        "FiveM",
        "native",
        "hook",
        "inject",
        "bypass",
    };

    private static readonly string[] ClientLogPatterns =
    {
        "native hook detected",
        "code injection detected",
        "hook detected",
        "inject detected",
        "bypass detected",
        "dll inject",
        "hook attempt",
        "native override",
        "function hook",
        "memory patch",
        "byte patch",
        "nop patch",
        "jmp hook",
        "call hook",
        "inline hook",
        "vtable hook",
        "iat hook",
        "eat hook",
        "detour detected",
        "native scan detected",
        "memory scan detected",
        "function scan detected",
        "hook scan detected",
        "inject scan detected",
        "bypass scan detected",
        "anti-cheat: hook",
        "ac: inject",
        "cheat detected: hook",
        "cheat detected: inject",
        "ban for hook",
        "ban for inject",
        "ban for bypass",
        "kick for hook",
        "kick for inject",
        "kick for bypass",
        "native integrity failed",
        "native checksum mismatch",
        "hook integrity check",
        "injection attempt blocked",
        "code cave detected",
        "trampolined function",
        "patched export",
    };

    private static readonly string[] ServerLogPatterns =
    {
        "client hook detected",
        "client inject detected",
        "client bypass detected",
        "native hook detected",
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
        "ban for code injection",
        "ban for native hook",
        "kick for code injection",
        "kick for native hook",
        "suspicious native call",
        "suspicious function call",
        "suspicious memory access",
        "resource banned: hook",
        "resource banned: inject",
        "resource kicked: hook",
        "resource kicked: inject",
        "native spoof detected",
        "function address mismatch",
        "client integrity failed",
        "memory write detected",
        "hook bypass attempt",
        "native return spoof",
        "exec native blocked",
    };

    private static readonly HashSet<string> SuspiciousResourceFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        "hook",
        "native_hook",
        "code_inject",
        "dll_inject",
        "bypass",
        "loader",
        "injector",
        "hack",
        "cheat",
        "exploit",
        "fivem_hook",
        "fivem_inject",
        "fivem_bypass",
        "native_bypass",
        "code_bypass",
        "hook_bypass",
        "fivem_trainer",
        "fivem_mod",
        "fivem_menu",
        "script_hook",
        "script_inject",
        "script_bypass",
        "resource_hook",
        "resource_inject",
        "citizen_hook",
        "lua_hook",
        "lua_inject",
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
        "hook_lib",
        "inject_lib",
        "bypass_lib",
        "hook_tools",
        "inject_tools",
        "bypass_tools",
    };

    private static readonly HashSet<string> DownloadArchiveNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "fivem_hook.zip",
        "fivem_hook.rar",
        "fivem_hook.7z",
        "fivem_inject.zip",
        "fivem_inject.rar",
        "fivem_inject.7z",
        "fivem_native_hook.zip",
        "fivem_native_hook.rar",
        "fivem_native_hook.7z",
        "fivem_bypass.zip",
        "fivem_bypass.rar",
        "fivem_bypass.7z",
        "fivem_loader.zip",
        "fivem_loader.rar",
        "fivem_loader.7z",
        "native_hook.zip",
        "native_hook.rar",
        "native_hook.7z",
        "native_inject.zip",
        "native_inject.rar",
        "hook_inject.zip",
        "hook_inject.rar",
        "dll_inject_fivem.zip",
        "dll_inject_fivem.rar",
        "code_inject.zip",
        "code_inject.rar",
        "fivem_cheat.zip",
        "fivem_cheat.rar",
        "fivem_hack.zip",
        "fivem_hack.rar",
        "fivem_exploit.zip",
        "fivem_exploit.rar",
        "fivem_trainer.zip",
        "fivem_trainer.rar",
        "fivem_mod.zip",
        "fivem_mod.rar",
        "fivem_menu.zip",
        "fivem_menu.rar",
        "lua_hook.zip",
        "lua_hook.rar",
        "lua_inject.zip",
        "lua_inject.rar",
        "script_hook.zip",
        "script_hook.rar",
        "scripthookv.zip",
        "scripthookv.rar",
        "resource_inject.zip",
        "resource_inject.rar",
        "citizen_hook.zip",
        "citizen_hook.rar",
    };

    private static readonly string[] UserAssistToolNames =
    {
        "fivem_hook",
        "fivem_inject",
        "fivem_native_hook",
        "fivem_code_inject",
        "fivem_dll_inject",
        "fivem_bypass",
        "fivem_loader",
        "fivem_injector",
        "native_hook",
        "native_injector",
        "hook_fivem",
        "inject_fivem",
        "bypass_fivem",
        "fivem_menu",
        "fivem_trainer",
        "fivem_cheat",
        "fivem_hack",
        "fivem_exploit",
        "hook_injector",
        "hook_loader",
        "hook_bypass",
        "lua_inject",
        "lua_hook",
        "lua_bypass",
        "script_inject",
        "script_hook",
        "scripthookv",
        "scripthookv2",
        "resource_inject",
        "resource_hook",
        "citizen_inject",
        "citizen_hook",
        "citizen_loader",
        "fivem_patcher",
        "fivem_patch",
    };

    private static readonly string[] MuiCacheToolNames =
    {
        "fivem_hook",
        "fivem_inject",
        "native_hook",
        "native_inject",
        "code_inject",
        "dll_inject",
        "hook_bypass",
        "lua_hook",
        "lua_inject",
        "script_hook",
        "script_inject",
        "fivem_bypass",
        "fivem_loader",
        "fivem_cheat",
        "fivem_hack",
        "resource_hook",
        "citizen_hook",
        "citizen_inject",
        "fivem_trainer",
        "fivem_menu",
        "fivem_exploit",
        "fivem_patcher",
        "hook_loader",
        "inject_loader",
        "bypass_loader",
        "hook_v2",
        "inject_v2",
        "bypass_v2",
        "hook_x64",
        "inject_x64",
        "fivem_api",
    };

    private static readonly string[] FiveMServerLogPaths =
    {
        Path.Combine(AppData, "CitizenFX", "logs"),
        Path.Combine(LocalApp, "FiveM", "FiveM.app", "logs"),
        Path.Combine(LocalApp, "FiveM", "FiveM.app", "server-data", "log"),
        Path.Combine(LocalApp, "FiveM", "FiveM.app", "server-data", "logs"),
        Path.Combine(UserProfile, "fivem-server", "logs"),
    };

    private static readonly string[] CacheCheatDllKeywords =
    {
        "hook",
        "inject",
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
            CheckFiveMHookExecutables(ctx, ct),
            CheckFiveMHookDlls(ctx, ct),
            CheckFiveMHookScriptFiles(ctx, ct),
            CheckFiveMHookOffsetFiles(ctx, ct),
            CheckFiveMCacheCheatDlls(ctx, ct),
            CheckFiveMHookClientLogs(ctx, ct),
            CheckFiveMHookServerLogs(ctx, ct),
            CheckFiveMHookResourceFolders(ctx, ct),
            CheckFiveMHookDownloadArtifacts(ctx, ct),
            CheckRegistryForFiveMHooks(ctx, ct)
        );
    }

    private Task CheckFiveMHookExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            Desktop,
            Downloads,
            TempDir,
            Path.Combine(LocalApp, "Temp"),
            AppData,
            LocalApp,
            FiveMLocalApp,
            FiveMApp,
            FiveMCache,
            CitizenFX,
        };

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
                if (!HookExeNames.Contains(fileName)) continue;

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
                    Title = $"FiveM Native Hook / Injection Executable: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Executable '{fileName}' matches a known FiveM native hook or code injection tool name. " +
                             "Such tools are used to hook FiveM game functions, inject code into the game process, " +
                             "or bypass FiveM anti-cheat by patching native functions at runtime.",
                    Detail = $"Found in: {dir}"
                });
            }
        }
    }, ct);

    private Task CheckFiveMHookDlls(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            Desktop,
            Downloads,
            TempDir,
            Path.Combine(LocalApp, "Temp"),
            AppData,
            LocalApp,
            FiveMLocalApp,
            FiveMApp,
            FiveMCache,
            CitizenFX,
        };

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
                if (!HookDllNames.Contains(fileName)) continue;

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
                    Title = $"FiveM Hook / Injection DLL: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"DLL '{fileName}' matches a known FiveM native hook or code injection library. " +
                             "These DLLs are injected into FiveM game processes to hook native game functions, " +
                             "intercept API calls, or bypass integrity checks performed by the Cfx.re anti-cheat.",
                    Detail = $"Found in: {dir}"
                });
            }
        }
    }, ct);

    private Task CheckFiveMHookScriptFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scriptDirs = new[]
        {
            FiveMCache,
            FiveMApp,
            Path.Combine(FiveMApp, "data"),
            Path.Combine(FiveMApp, "resources"),
            Path.Combine(FiveMApp, "citizen"),
            Path.Combine(FiveMLocalApp, "data"),
            Path.Combine(FiveMLocalApp, "resources"),
            Path.Combine(CitizenFX, "resources"),
            Path.Combine(CitizenFX, "cache"),
        };

        var extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".lua", ".js", ".ts" };

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
                        Title = $"FiveM Hook/Injection Script: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Script file '{Path.GetFileName(file)}' contains {matchCount} keywords " +
                                 "associated with FiveM native hook or code injection cheats. " +
                                 "Cheat scripts use these patterns to intercept native function calls, " +
                                 "patch game memory, or bypass Cfx.re anti-cheat checks.",
                        Detail = $"Matched keywords ({matchCount}): {string.Join(", ", matchedKeywords.Take(10))}"
                    });
                }
            }
        }
    }, ct);

    private Task CheckFiveMHookOffsetFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            Desktop,
            Downloads,
            FiveMLocalApp,
            FiveMApp,
            FiveMCache,
            CitizenFX,
            Path.Combine(AppData, "CitizenFX"),
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
                    Title = $"FiveM Hook Offset / Address File: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Offset/address file '{fileName}' contains " +
                             (hasHexPattern ? "hexadecimal memory addresses (0x prefixed) " : "") +
                             (hasKeyword ? $"and keywords: {string.Join(", ", matchedKws)}" : "") +
                             ". Files containing GTA5/FiveM native offsets or memory patterns are used by " +
                             "hook and injection cheats to locate game functions at runtime.",
                    Detail = $"Hex patterns present: {hasHexPattern}; Keywords: {string.Join(", ", matchedKws)}"
                });
            }
        }
    }, ct);

    private Task CheckFiveMCacheCheatDlls(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            FiveMCache,
            CitizenFX,
            Path.Combine(LocalApp, "FiveM"),
            Path.Combine(AppData, "CitizenFX"),
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
                bool matchesKeyword = CacheCheatDllKeywords.Any(k =>
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
                        Title = $"Kernel Driver (.sys) in FiveM Cache: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"A kernel driver file '{fileName}' was found in the FiveM application data " +
                                 "directories. Kernel drivers in FiveM cache or CitizenFX directories are " +
                                 "highly suspicious and may represent BYOVD-based anti-cheat bypass tools " +
                                 "that are loaded to disable FiveM integrity checks at kernel level.",
                        Detail = $"Directory: {dir}"
                    });
                    continue;
                }

                if (!matchesKeyword) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Suspicious Hook/Inject DLL in FiveM Cache: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"DLL '{fileName}' with hook/injection-related name was found in FiveM cache " +
                             "or CitizenFX application data. Cheat DLLs are sometimes staged in cache " +
                             "directories to evade detection before being loaded into the game process.",
                    Detail = $"Directory: {dir}"
                });
            }
        }
    }, ct);

    private Task CheckFiveMHookClientLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logDirs = new[]
        {
            CitizenFXLogs,
            FiveMApp,
            FiveMLocalApp,
            Path.Combine(FiveMApp, "logs"),
        };

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
                        Title = $"FiveM Client Log: Hook/Injection Pattern Detected",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"FiveM client log file contains the pattern '{pattern}', indicating that a " +
                                 "native hook or code injection cheat was detected or attempted on this system. " +
                                 "This log entry was generated by FiveM or Cfx.re anti-cheat during a session " +
                                 "where hook/injection activity was observed.",
                        Detail = $"Pattern matched: '{pattern}'"
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckFiveMHookServerLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var dir in FiveMServerLogPaths)
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
                        Title = $"FiveM Server Log: Hook/Injection Detection Record",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"FiveM server log contains the pattern '{pattern}', indicating that the " +
                                 "server detected or logged a hook/injection cheat event from a client. " +
                                 "Server-side detection logs are strong forensic evidence of active cheat usage " +
                                 "since they originate from the authoritative game server.",
                        Detail = $"Pattern matched: '{pattern}'"
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckFiveMHookResourceFolders(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var resourceRoots = new[]
        {
            Path.Combine(FiveMApp, "resources"),
            Path.Combine(FiveMApp, "citizen", "scripting"),
            Path.Combine(FiveMLocalApp, "resources"),
            Path.Combine(FiveMLocalApp, "citizen", "scripting"),
            Path.Combine(CitizenFX, "resources"),
            Path.Combine(UserProfile, "fivem-server", "resources"),
            Path.Combine(UserProfile, "fivem-server", "citizen", "scripting"),
        };

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
                    Title = $"Suspicious FiveM Resource Folder: {folderName}",
                    Risk = RiskLevel.High,
                    Location = subDir,
                    FileName = folderName,
                    Reason = $"Resource folder '{folderName}' found in FiveM resource directories matches " +
                             "a known hook, inject, or bypass cheat resource name. Cheat resources are " +
                             "loaded as FiveM server resources and can hook game natives, inject code, " +
                             "or bypass anti-cheat checks from within the resource scripting environment.",
                    Detail = $"Parent directory: {root}"
                });
            }
        }
    }, ct);

    private Task CheckFiveMHookDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                    Title = $"FiveM Hook/Inject Archive Download: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Archive file '{fileName}' matching a known FiveM native hook or code injection " +
                             "cheat tool name was found in Downloads or Desktop. The presence of this archive " +
                             "is a strong forensic indicator that the user downloaded a FiveM cheat package, " +
                             "even if the extracted files have since been deleted.",
                    Detail = $"Found in: {dir}"
                });
            }
        }
    }, ct);

    private Task CheckRegistryForFiveMHooks(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        CheckUserAssistForFiveMHooks(ctx, ct);
        CheckMuiCacheForFiveMHooks(ctx, ct);
        CheckRunKeysForFiveMHooks(ctx, ct);
        CheckSoftwareKeysForFiveMHooks(ctx, ct);
        CheckUninstallKeysForFiveMHooks(ctx, ct);
    }, ct);

    private void CheckUserAssistForFiveMHooks(ScanContext ctx, CancellationToken ct)
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
                            Title = $"FiveM Hook Tool in UserAssist (Executed): {toolName}",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                            Reason = $"UserAssist registry key records execution of a program matching the " +
                                     $"FiveM hook/injection tool name '{toolName}'. UserAssist tracks GUI " +
                                     "program launches, making this a strong indicator that this tool was " +
                                     "actively run on this system.",
                            Detail = $"Decoded value: {decoded} (ROT13 encoded in registry)"
                        });
                        break;
                    }
                }
            }
        }
        catch { }
    }

    private void CheckMuiCacheForFiveMHooks(ScanContext ctx, CancellationToken ct)
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
                        Title = $"FiveM Inject Tool in MUICache: {toolName}",
                        Risk = RiskLevel.High,
                        Location = @"HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                        Reason = $"MUICache registry entry references a path containing '{toolName}', a known " +
                                 "FiveM hook or injection tool name. MUICache records the display names of " +
                                 "previously executed applications, providing forensic evidence of cheat tool execution.",
                        Detail = $"Registry value name: {valueName}"
                    });
                    break;
                }
            }
        }
        catch { }
    }

    private void CheckRunKeysForFiveMHooks(ScanContext ctx, CancellationToken ct)
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

                    bool matchesHook = UserAssistToolNames.Any(t =>
                        combinedLower.Contains(t, StringComparison.OrdinalIgnoreCase));
                    if (!matchesHook) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Hook Tool Auto-Start Registry Entry: {valueName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{keyPath}",
                        Reason = $"Registry Run/RunOnce key '{keyPath}' contains an auto-start entry " +
                                 $"'{valueName}' referencing a FiveM hook or injection tool. Auto-start " +
                                 "entries ensure the cheat tool launches automatically with Windows, " +
                                 "indicating persistent cheat installation.",
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

                    bool matchesHook = UserAssistToolNames.Any(t =>
                        combinedLower.Contains(t, StringComparison.OrdinalIgnoreCase));
                    if (!matchesHook) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Hook Tool System Auto-Start: {valueName}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{keyPath}",
                        Reason = $"System-wide registry Run key contains '{valueName}' referencing a FiveM " +
                                 "hook or injection tool. A system-level auto-start entry indicates the cheat " +
                                 "tool was installed with administrative privileges for persistent access.",
                        Detail = $"Value: {valueName} = {valueData}"
                    });
                }
            }
            catch { }
        }
    }

    private void CheckSoftwareKeysForFiveMHooks(ScanContext ctx, CancellationToken ct)
    {
        var softwareKeyPaths = new[]
        {
            @"Software\FiveMHook",
            @"Software\FiveMInject",
            @"Software\FiveMNativeHook",
            @"Software\NativeHook",
            @"Software\CodeInject",
            @"Software\FiveMCheat",
            @"Software\FiveMBypass",
            @"Software\FiveMLoader",
            @"Software\LuaHook",
            @"Software\LuaInject",
            @"Software\ScriptHook",
            @"Software\ScriptInject",
            @"Software\ResourceHook",
            @"Software\CitizenHook",
            @"Software\HookInjector",
            @"Software\BypassFiveM",
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
                        Title = $"FiveM Hook Tool Registry Key: {keyPath}",
                        Risk = RiskLevel.High,
                        Location = $@"{hiveName}\{keyPath}",
                        Reason = $"Registry key '{keyPath}' associated with a FiveM native hook or injection " +
                                 "tool was found. Cheat tools write registry keys during installation or " +
                                 "configuration, and their presence indicates this tool was installed " +
                                 "on this system.",
                        Detail = $"Hive: {hiveName}"
                    });
                }
                catch { }
            }
        }
    }

    private void CheckUninstallKeysForFiveMHooks(ScanContext ctx, CancellationToken ct)
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        var cheatInstallerKeywords = new[]
        {
            "fivem hook", "fivem inject", "native hook", "code inject",
            "dll inject", "fivem bypass", "fivem cheat", "fivem hack",
            "fivem exploit", "fivem trainer", "fivem mod", "lua hook",
            "lua inject", "script hook", "script inject", "resource hook",
            "citizen hook", "citizen inject", "hook injector", "hook bypass",
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
                            Title = $"FiveM Cheat Tool Installer Entry: {displayName}",
                            Risk = RiskLevel.High,
                            Location = $@"{hiveName}\{uninstallPath}\{subKeyName}",
                            Reason = $"Uninstall registry entry '{displayName}' matches a known FiveM hook " +
                                     "or injection cheat installer. The presence of an uninstall entry indicates " +
                                     "the cheat tool was formally installed on this system, which is stronger " +
                                     "evidence than loose file artifacts alone.",
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
