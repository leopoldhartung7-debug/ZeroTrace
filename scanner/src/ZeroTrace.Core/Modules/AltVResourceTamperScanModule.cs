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

public sealed class AltVResourceTamperScanModule : IScanModule
{
    public string Name => "alt:V Resource Tampering & File Injection Forensic Scan";
    public double Weight => 4.2;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

    private static readonly string[] AltVBasePaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "altv"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "altv-launcher"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "alt-v"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "alt-v"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents", "altv"),
        @"C:\altv",
        @"C:\altv-launcher",
        @"C:\Program Files\altv",
        @"C:\Program Files (x86)\altv",
    ];

    private static readonly string[] TamperExecutables =
    [
        "altv_tamper.exe",
        "altv_resource_tamper.exe",
        "altv_file_inject.exe",
        "altv_resource_inject.exe",
        "altv_resource_modify.exe",
        "altv_resource_patch.exe",
        "altv_resource_hack.exe",
        "altv_resource_exploit.exe",
        "altv_file_tamper.exe",
        "altv_file_modify.exe",
        "altv_file_patch.exe",
        "altv_file_hack.exe",
        "altv_file_exploit.exe",
        "tamper_altv.exe",
        "resource_tamper_altv.exe",
        "file_inject_altv.exe",
        "resource_inject_altv.exe",
        "resource_modify_altv.exe",
        "resource_patch_altv.exe",
        "resource_hack_altv.exe",
        "resource_exploit_altv.exe",
        "file_tamper_altv.exe",
        "file_modify_altv.exe",
        "file_patch_altv.exe",
        "file_hack_altv.exe",
        "file_exploit_altv.exe",
        "alt_tamper.exe",
        "alt_resource_tamper.exe",
        "alt_file_inject.exe",
        "alt_resource_inject.exe",
        "alt_resource_modify.exe",
        "alt_resource_patch.exe",
        "alt_resource_hack.exe",
        "alt_resource_exploit.exe",
        "alt_file_tamper.exe",
        "alt_file_modify.exe",
        "alt_file_patch.exe",
        "alt_file_hack.exe",
        "alt_file_exploit.exe",
        "altv_manifest_tamper.exe",
        "altv_manifest_inject.exe",
        "altv_manifest_modify.exe",
        "altv_manifest_patch.exe",
        "altv_manifest_hack.exe",
        "altv_manifest_exploit.exe",
        "altv_bytecode_tamper.exe",
        "altv_bytecode_inject.exe",
        "altv_bytecode_modify.exe",
        "altv_bytecode_patch.exe",
        "altv_bytecode_hack.exe",
        "altv_bytecode_exploit.exe",
        "altv_script_tamper.exe",
        "altv_script_inject.exe",
        "altv_script_modify.exe",
        "altv_script_patch.exe",
        "altv_script_hack.exe",
        "altv_script_exploit.exe",
        "altv_asset_tamper.exe",
        "altv_asset_inject.exe",
        "altv_asset_modify.exe",
        "altv_asset_patch.exe",
        "altv_asset_hack.exe",
        "altv_asset_exploit.exe",
        "resource_tamper_v2.exe",
        "file_inject_v2.exe",
        "altv_resource_tamper_v2.exe",
        "altv_file_inject_v2.exe",
        "altv_tamper_tool.exe",
        "altv_inject_tool.exe",
    ];

    private static readonly string[] TamperDlls =
    [
        "altv_tamper.dll",
        "altv_resource_tamper.dll",
        "altv_file_inject.dll",
        "altv_resource_inject.dll",
        "altv_resource_modify.dll",
        "altv_resource_patch.dll",
        "altv_resource_hack.dll",
        "altv_resource_exploit.dll",
        "altv_file_tamper.dll",
        "altv_file_modify.dll",
        "altv_file_patch.dll",
        "altv_file_hack.dll",
        "altv_file_exploit.dll",
        "tamper_altv.dll",
        "resource_tamper_altv.dll",
        "file_inject_altv.dll",
        "resource_inject_altv.dll",
        "resource_modify_altv.dll",
        "resource_patch_altv.dll",
        "resource_hack_altv.dll",
        "resource_exploit_altv.dll",
        "file_tamper_altv.dll",
        "file_modify_altv.dll",
        "file_patch_altv.dll",
        "file_hack_altv.dll",
        "file_exploit_altv.dll",
        "altv_manifest_tamper.dll",
        "altv_manifest_inject.dll",
        "altv_manifest_modify.dll",
        "altv_manifest_patch.dll",
        "altv_manifest_hack.dll",
        "altv_manifest_exploit.dll",
        "altv_bytecode_tamper.dll",
        "altv_bytecode_inject.dll",
        "altv_bytecode_modify.dll",
        "altv_bytecode_patch.dll",
        "altv_bytecode_hack.dll",
        "altv_bytecode_exploit.dll",
        "altv_script_tamper.dll",
        "altv_script_inject.dll",
        "altv_script_modify.dll",
        "altv_script_patch.dll",
        "altv_script_hack.dll",
        "altv_script_exploit.dll",
        "resource_tamper_v2.dll",
        "file_inject_v2.dll",
    ];

    private static readonly string[] ManifestSuspiciousPatterns =
    [
        "eval(",
        "execute(",
        "base64",
        "decode",
        "http://",
        "https://",
        "require(",
        "loadstring(",
        "dofile(",
        "loadfile(",
        "pcall(load",
        "rawset(",
        "rawget(",
        "getfenv(",
        "setfenv(",
        "debug.getinfo",
        "debug.sethook",
        "io.open(",
        "os.execute(",
        "string.char(",
        "string.byte(",
        "table.concat(",
        "\\x",
        "\\u00",
        "_G[",
        "inject",
        "tamper",
        "payload",
    ];

    private static readonly string[] ScriptSuspiciousPatterns =
    [
        "eval(",
        "Function(",
        "new Function",
        "eval(atob",
        "eval(Buffer",
        "base64",
        "fromCharCode",
        "decodeURIComponent",
        "unescape(",
        "tamper",
        "inject",
        "modify",
        "patch",
        "hack",
        "exploit",
        "bypass_check",
        "bypass_anticheat",
        "bypass_detection",
        "payload",
        "shellcode",
        "obfuscate",
        "deobfuscate",
        "unpack",
        "_0x",
        "\\x",
        "\\u00",
        "obf_",
        "hex_decode",
        "decode_string",
        "eval(decodeURIComponent",
        "String.fromCharCode",
        "atob(",
        "btoa(",
    ];

    private static readonly string[] ClientLogPatterns =
    [
        "resource tampered",
        "file tampered",
        "manifest tampered",
        "script tampered",
        "asset tampered",
        "resource injected",
        "file injected",
        "manifest injected",
        "script injected",
        "resource modified",
        "file modified",
        "manifest modified",
        "script modified",
        "resource patched",
        "file patched",
        "manifest patched",
        "script patched",
        "checksum mismatch",
        "hash mismatch",
        "integrity check failed",
        "resource integrity",
        "file integrity",
        "manifest integrity",
        "script integrity",
        "tamper detected",
        "inject detected",
        "modify detected",
        "patch detected",
        "hack detected",
        "exploit detected",
        "resource verification failed",
        "file verification failed",
        "manifest verification failed",
        "script verification failed",
        "anti-cheat: tamper",
        "ac: inject",
        "ac: modify",
        "ac: patch",
        "ban for tampering",
        "kick for tampering",
        "invalid resource checksum",
        "resource signature invalid",
        "file signature invalid",
        "bytecode tamper",
        "script injection detected",
    ];

    private static readonly string[] ServerLogPatterns =
    [
        "resource tampered detected",
        "file tampered detected",
        "manifest tampered detected",
        "script tampered detected",
        "asset tampered detected",
        "resource injected detected",
        "file injected detected",
        "manifest injected detected",
        "script injected detected",
        "resource modified detected",
        "file modified detected",
        "manifest modified detected",
        "script modified detected",
        "resource patched detected",
        "file patched detected",
        "manifest patched detected",
        "script patched detected",
        "checksum mismatch detected",
        "hash mismatch detected",
        "integrity check failed",
        "resource integrity violation",
        "file integrity violation",
        "manifest integrity violation",
        "script integrity violation",
        "tamper attempt detected",
        "inject attempt detected",
        "modify attempt detected",
        "patch attempt detected",
        "hack attempt detected",
        "exploit attempt detected",
        "resource verification failed",
        "file verification failed",
        "manifest verification failed",
        "script verification failed",
        "anti-cheat: tamper",
        "ac: inject",
        "ac: modify",
        "ac: patch",
        "banned for tampering",
        "kicked for tampering",
        "bytecode integrity failed",
        "invalid script hash",
        "resource cache corrupted",
        "asset verification failed",
        "resource load blocked",
    ];

    private static readonly string[] DownloadArchiveNames =
    [
        "altv_tamper.zip",
        "altv_resource_tamper.zip",
        "altv_file_inject.zip",
        "altv_resource_inject.zip",
        "altv_resource_modify.zip",
        "altv_resource_patch.zip",
        "altv_resource_hack.zip",
        "altv_resource_exploit.zip",
        "altv_file_tamper.zip",
        "altv_tamper.rar",
        "altv_resource_tamper.rar",
        "altv_file_inject.rar",
        "altv_resource_inject.rar",
        "altv_resource_hack.rar",
        "altv_resource_exploit.rar",
        "altv_tamper.7z",
        "altv_resource_tamper.7z",
        "altv_file_inject.7z",
        "altv_resource_inject.7z",
        "tamper_altv.zip",
        "tamper_altv.rar",
        "resource_tamper_altv.zip",
        "resource_tamper_altv.rar",
        "file_inject_altv.zip",
        "file_inject_altv.rar",
        "resource_inject_altv.zip",
        "resource_inject_altv.rar",
        "alt_tamper.zip",
        "alt_tamper.rar",
        "alt_resource_tamper.zip",
        "alt_resource_tamper.rar",
        "altv_manifest_tamper.zip",
        "altv_manifest_inject.zip",
        "altv_manifest_hack.zip",
        "altv_bytecode_tamper.zip",
        "altv_bytecode_inject.zip",
        "altv_script_tamper.zip",
        "altv_script_inject.zip",
        "altv_asset_tamper.zip",
        "altv_asset_inject.zip",
        "altv_tamper_setup.exe",
        "altv_resource_tamper_setup.exe",
        "altv_file_inject_setup.exe",
        "altv_resource_inject_setup.exe",
        "altv_resource_hack_setup.exe",
        "altv_tamper_v2.exe",
        "altv_resource_tamper_v2.exe",
        "resource_tamper_v2.zip",
        "file_inject_v2.zip",
        "altv_tamper_tool_setup.exe",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckResourceTamperExecutables(ctx, ct),
            CheckResourceTamperDlls(ctx, ct),
            CheckTamperedManifestFiles(ctx, ct),
            CheckTamperedScriptFiles(ctx, ct),
            CheckResourceTamperClientLogs(ctx, ct),
            CheckResourceTamperServerLogs(ctx, ct),
            CheckResourceTamperDownloadArtifacts(ctx, ct),
            CheckRegistryForResourceTamper(ctx, ct)
        );
    }

    private Task CheckResourceTamperExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>(AltVBasePaths)
        {
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            Path.GetTempPath(),
            AppData,
            LocalAppData,
            Path.Combine(LocalAppData, "Temp"),
            Path.Combine(UserProfile, "Documents"),
        };

        foreach (var dir in scanDirs.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in EnumerateFilesRecursive(dir, maxDepth: 5, ct))
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);
                    if (!fn.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.IncrementFiles();

                    if (TamperExecutables.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V resource tamper / file injection executable detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known alt:V resource tampering or file injection executable '{fn}' found on disk. " +
                                     "These tools are used to manipulate alt:V resource files, inject unauthorized scripts or assets, " +
                                     "modify manifests to bypass integrity checks, or patch bytecode to evade server-side validation on alt:V GTA:V multiplayer servers.",
                            Detail = $"Full path: {file}"
                        });
                    }
                    else
                    {
                        var fnLower = fn.ToLowerInvariant();
                        bool isHeuristic =
                            (fnLower.Contains("altv") || fnLower.Contains("alt_v") || fnLower.Contains("alt-v"))
                            && (fnLower.Contains("tamper") || fnLower.Contains("inject") || fnLower.Contains("modify")
                                || fnLower.Contains("patch") || fnLower.Contains("exploit")
                                || fnLower.Contains("bytecode") || fnLower.Contains("manifest")
                                || fnLower.Contains("resource_hack") || fnLower.Contains("file_hack"));
                        if (isHeuristic)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V resource tamper executable (heuristic): {fn}",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(file) ?? dir,
                                FileName = fn,
                                Reason = $"Executable '{fn}' contains both alt:V-related and resource tampering/injection terms in its filename. " +
                                         "Heuristic match indicates this file is likely a resource tamper or file injection tool targeting the alt:V platform.",
                                Detail = $"Full path: {file}"
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckResourceTamperDlls(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>(AltVBasePaths)
        {
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            Path.GetTempPath(),
            AppData,
            LocalAppData,
            Path.Combine(LocalAppData, "Temp"),
            Path.Combine(UserProfile, "Documents"),
        };

        foreach (var dir in scanDirs.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in EnumerateFilesRecursive(dir, maxDepth: 5, ct))
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);
                    if (!fn.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.IncrementFiles();

                    if (TamperDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V resource tamper / file injection DLL detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known alt:V resource tampering or file injection DLL '{fn}' found on disk. " +
                                     "Tamper DLLs targeting alt:V are typically injected into the client or resource runtime to intercept integrity checks, " +
                                     "modify resource files in memory, forge checksums, or silently patch bytecode and assets loaded by the platform.",
                            Detail = $"Full path: {file}"
                        });
                    }
                    else
                    {
                        var fnLower = fn.ToLowerInvariant();
                        bool isHeuristic =
                            (fnLower.Contains("altv") || fnLower.Contains("alt_v") || fnLower.Contains("alt-v"))
                            && (fnLower.Contains("tamper") || fnLower.Contains("inject") || fnLower.Contains("modify")
                                || fnLower.Contains("patch") || fnLower.Contains("exploit")
                                || fnLower.Contains("bytecode") || fnLower.Contains("manifest"));
                        if (isHeuristic)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V resource tamper DLL (heuristic): {fn}",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(file) ?? dir,
                                FileName = fn,
                                Reason = $"DLL '{fn}' contains both alt:V-related and resource tampering/injection terms in its filename. " +
                                         "Heuristic match indicates this library is likely a resource tamper or file injection component targeting the alt:V platform.",
                                Detail = $"Full path: {file}"
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckTamperedManifestFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var baseDir in AltVBasePaths)
        {
            foreach (var subDir in new[] { "resources", "client_packages", "data" })
            {
                var searchRoot = Path.Combine(baseDir, subDir);
                if (!Directory.Exists(searchRoot)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(searchRoot, maxDepth: 8, ct))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fn = Path.GetFileName(file);
                        bool isManifest =
                            fn.Equals("resource.cfg", StringComparison.OrdinalIgnoreCase)
                            || fn.Equals("__resource.lua", StringComparison.OrdinalIgnoreCase)
                            || fn.Equals("fxmanifest.lua", StringComparison.OrdinalIgnoreCase);
                        if (!isManifest) continue;
                        ctx.IncrementFiles();

                        string content;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }

                        int hits = 0;
                        var matchedPatterns = new List<string>();
                        foreach (var pattern in ManifestSuspiciousPatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                hits++;
                                matchedPatterns.Add(pattern);
                            }
                        }

                        bool hasExternalUrl = content.Contains("http://", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("https://", StringComparison.OrdinalIgnoreCase);
                        bool hasEval = content.Contains("eval(", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("execute(", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("loadstring(", StringComparison.OrdinalIgnoreCase);
                        bool hasBase64 = content.Contains("base64", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("decode", StringComparison.OrdinalIgnoreCase);
                        bool hasObfuscation = content.Contains("\\x", StringComparison.Ordinal)
                            || content.Contains("\\u00", StringComparison.Ordinal)
                            || content.Contains("string.char(", StringComparison.OrdinalIgnoreCase);

                        bool shouldFlag = (hasExternalUrl && (hasEval || hasBase64))
                            || hasEval
                            || (hasBase64 && hasObfuscation)
                            || hits >= 3;

                        if (shouldFlag)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious alt:V resource manifest: {fn}",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(file) ?? searchRoot,
                                FileName = fn,
                                Reason = $"alt:V resource manifest file '{fn}' contains {hits} suspicious pattern(s) " +
                                         $"indicating tampering or injection (matched: {string.Join(", ", matchedPatterns.Take(5))}). " +
                                         "Tampered manifests are used to load unauthorized scripts, reference external payload URLs, " +
                                         "include obfuscated execution chains, or add malicious dependency entries that bypass alt:V resource integrity validation.",
                                Detail = $"File: {file} | Pattern hits: {hits}" +
                                         (hasExternalUrl ? " | Contains external URL reference" : string.Empty) +
                                         (hasEval ? " | Contains eval/execute/loadstring" : string.Empty) +
                                         (hasBase64 ? " | Contains base64/decode reference" : string.Empty) +
                                         (hasObfuscation ? " | Contains obfuscation patterns" : string.Empty)
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckTamperedScriptFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var baseDir in AltVBasePaths)
        {
            foreach (var subDir in new[] { "resources", "client_packages" })
            {
                var searchRoot = Path.Combine(baseDir, subDir);
                if (!Directory.Exists(searchRoot)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(searchRoot, maxDepth: 8, ct))
                    {
                        ct.ThrowIfCancellationRequested();
                        var ext = Path.GetExtension(file);
                        bool isScript =
                            ext.Equals(".js", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".ts", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".mjs", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".cjs", StringComparison.OrdinalIgnoreCase);
                        if (!isScript) continue;
                        ctx.IncrementFiles();

                        string content;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }

                        int hits = 0;
                        string firstMatch = string.Empty;
                        var matchedPatterns = new List<string>();
                        foreach (var pattern in ScriptSuspiciousPatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                hits++;
                                matchedPatterns.Add(pattern);
                                if (firstMatch.Length == 0) firstMatch = pattern;
                            }
                        }

                        if (hits >= 4)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Tampered/injected alt:V script: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(file) ?? searchRoot,
                                FileName = Path.GetFileName(file),
                                Reason = $"alt:V script file '{Path.GetFileName(file)}' contains {hits} tampering or injection indicators " +
                                         $"(first match: '{firstMatch}'). Scripts with 4+ of these patterns strongly indicate resource file injection, " +
                                         "obfuscated payload delivery, eval-based code execution chains, or anti-cheat bypass logic " +
                                         "injected into alt:V resource scripts.",
                                Detail = $"File: {file} | Pattern hits: {hits} | Matched: {string.Join(", ", matchedPatterns.Take(8))}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckResourceTamperClientLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var baseDir in AltVBasePaths)
        {
            if (!Directory.Exists(baseDir)) continue;
            try
            {
                var logFiles = EnumerateFilesRecursive(baseDir, maxDepth: 5, ct)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f);
                        return ext.Equals(".log", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".txt", StringComparison.OrdinalIgnoreCase);
                    });

                foreach (var logFile in logFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    foreach (var pattern in ClientLogPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            var lineCtx = FindLineContaining(content, pattern);
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V client log: resource tamper / file injection artifact",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(logFile) ?? baseDir,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"alt:V client log contains resource tampering or file injection pattern: '{pattern}'. " +
                                         "Client logs record cheat tool activity including resource integrity failures, checksum mismatches, " +
                                         "manifest tamper detections, script injection confirmations, and anti-cheat triggered ban or kick events on alt:V servers.",
                                Detail = lineCtx is not null
                                    ? $"Log file: {logFile} | Context: {lineCtx}"
                                    : $"Log file: {logFile} | Pattern: {pattern}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }, ct);

    private Task CheckResourceTamperServerLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var serverLogDirs = new[]
        {
            Path.Combine(UserProfile, "altv-server", "logs"),
            Path.Combine(UserProfile, "altv-server", "log"),
            Path.Combine(UserProfile, "alt-server", "logs"),
            Path.Combine(UserProfile, "alt-server", "log"),
            Path.Combine(UserProfile, "altv_server", "logs"),
            Path.Combine(UserProfile, "Documents", "altv-server", "logs"),
            Path.Combine(UserProfile, "Documents", "alt-server", "logs"),
            Path.Combine(UserProfile, "Documents", "altv_server", "logs"),
            @"C:\altv-server\logs",
            @"C:\altv_server\logs",
            @"C:\alt-server\logs",
            @"C:\altv\server\logs",
            @"C:\altv-server\log",
            @"C:\altv_server\log",
            @"C:\alt-server\log",
        };

        foreach (var logDir in serverLogDirs)
        {
            if (!Directory.Exists(logDir)) continue;
            try
            {
                var logFiles = EnumerateFilesRecursive(logDir, maxDepth: 3, ct)
                    .Where(f =>
                    {
                        var ext = Path.GetExtension(f);
                        return ext.Equals(".log", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".txt", StringComparison.OrdinalIgnoreCase);
                    });

                foreach (var logFile in logFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string content;
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    foreach (var pattern in ServerLogPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            var lineCtx = FindLineContaining(content, pattern);
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V server log: resource tamper / file injection detection record",
                                Risk = RiskLevel.High,
                                Location = logDir,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"alt:V server log contains resource tampering or file injection detection record: '{pattern}'. " +
                                         "Server logs record ban/kick events, detected resource integrity violations, checksum mismatch alerts, " +
                                         "manifest tamper blocks, and forbidden script injection activity on alt:V multiplayer servers.",
                                Detail = lineCtx is not null
                                    ? $"Log file: {logFile} | Context: {lineCtx}"
                                    : $"Log file: {logFile} | Pattern: {pattern}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }, ct);

    private Task CheckResourceTamperDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new[]
        {
            Path.Combine(UserProfile, "Downloads"),
            Desktop,
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in EnumerateFilesRecursive(dir, maxDepth: 3, ct))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (DownloadArchiveNames.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V resource tamper tool download artifact: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"alt:V resource tampering or file injection tool archive/installer '{fn}' found in {dir}. " +
                                     "Downloaded tamper archives and setup executables indicate prior acquisition of resource tampering software " +
                                     "used to manipulate alt:V multiplayer server resource files, manifests, scripts, or assets.",
                            Detail = $"Full path: {file}"
                        });
                    }
                    else
                    {
                        var fnLower = fn.ToLowerInvariant();
                        bool isSuspicious =
                            (fnLower.Contains("altv") || fnLower.Contains("alt_v") || fnLower.Contains("alt-v"))
                            && (fnLower.Contains("tamper") || fnLower.Contains("inject") || fnLower.Contains("modify")
                                || fnLower.Contains("patch") || fnLower.Contains("exploit")
                                || fnLower.Contains("manifest") || fnLower.Contains("bytecode")
                                || fnLower.Contains("resource_hack") || fnLower.Contains("file_hack")
                                || fnLower.Contains("script_hack") || fnLower.Contains("asset_inject"));
                        if (isSuspicious)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V resource tamper download artifact (heuristic): {fn}",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(file) ?? dir,
                                FileName = fn,
                                Reason = $"File '{fn}' in {dir} contains both alt:V-related and resource tampering/injection terms in its name. " +
                                         "Heuristic match indicates this is likely a resource tamper or file injection tool archive targeting alt:V.",
                                Detail = $"Full path: {file}"
                            });
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckRegistryForResourceTamper(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        CheckUserAssistForResourceTamper(ctx, ct);
        CheckMuiCacheForResourceTamper(ctx, ct);
        CheckRunKeysForResourceTamper(ctx, ct);
        CheckUninstallKeysForResourceTamper(ctx, ct);
    }, ct);

    private void CheckUserAssistForResourceTamper(ScanContext ctx, CancellationToken ct)
    {
        const string uaPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        try
        {
            using var ua = Registry.CurrentUser.OpenSubKey(uaPath, writable: false);
            if (ua == null) return;
            foreach (var guidName in ua.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var count = ua.OpenSubKey($@"{guidName}\Count", writable: false);
                    if (count == null) continue;
                    foreach (var valName in count.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();
                        var decoded = Rot13Decode(valName);
                        var lower = decoded.ToLowerInvariant();
                        bool isTamper =
                            TamperExecutables.Any(k => lower.Contains(
                                k.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase),
                                StringComparison.OrdinalIgnoreCase))
                            || (lower.Contains("altv") && lower.Contains("tamper"))
                            || (lower.Contains("altv") && lower.Contains("inject") && lower.Contains("resource"))
                            || (lower.Contains("altv") && lower.Contains("manifest") && lower.Contains("hack"))
                            || (lower.Contains("altv") && lower.Contains("bytecode") && lower.Contains("patch"))
                            || (lower.Contains("altv") && lower.Contains("file_inject"))
                            || (lower.Contains("altv") && lower.Contains("resource_inject"))
                            || (lower.Contains("altv") && lower.Contains("script_tamper"))
                            || (lower.Contains("altv") && lower.Contains("asset_inject"))
                            || (lower.Contains("alt_v") && lower.Contains("file_tamper"))
                            || (lower.Contains("alt-v") && lower.Contains("resource_hack"));
                        if (isTamper)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V resource tamper tool execution (UserAssist)",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{uaPath}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"Windows UserAssist registry records execution of an alt:V resource tampering or file injection tool: '{decoded}'. " +
                                         "UserAssist tracks every GUI program launched by the user and is a reliable forensic indicator " +
                                         "of prior execution of resource tamper or file injection software targeting alt:V multiplayer.",
                                Detail = $"Decoded entry: {decoded}"
                            });
                        }
                    }
                }
                catch (Exception) { }
            }
        }
        catch (Exception) { }
    }

    private void CheckMuiCacheForResourceTamper(ScanContext ctx, CancellationToken ct)
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
                using var mui = Registry.CurrentUser.OpenSubKey(muiPath, writable: false);
                if (mui == null) continue;
                foreach (var valName in mui.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    var lower = valName.ToLowerInvariant();
                    bool isTamper =
                        TamperExecutables.Any(k => lower.Contains(
                            k.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase),
                            StringComparison.OrdinalIgnoreCase))
                        || (lower.Contains("altv") && lower.Contains("tamper"))
                        || (lower.Contains("altv") && lower.Contains("resource_inject"))
                        || (lower.Contains("altv") && lower.Contains("file_inject"))
                        || (lower.Contains("altv") && lower.Contains("manifest_hack"))
                        || (lower.Contains("altv") && lower.Contains("bytecode_patch"))
                        || (lower.Contains("altv") && lower.Contains("script_tamper"))
                        || (lower.Contains("altv") && lower.Contains("asset_inject"))
                        || (lower.Contains("alt_v") && lower.Contains("file_tamper"))
                        || (lower.Contains("alt-v") && lower.Contains("resource_hack"));
                    if (isTamper)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V resource tamper tool execution (MUICache)",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\" + muiPath,
                            FileName = Path.GetFileName(valName),
                            Reason = $"Windows MUICache records an alt:V resource tampering or file injection executable was run: '{valName}'. " +
                                     "MUICache stores the friendly name of every EXE ever executed and persists even after the file is deleted, " +
                                     "providing durable forensic evidence of resource tamper or file injection tool usage targeting alt:V.",
                            Detail = $"MUICache entry: {valName}"
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }

    private void CheckRunKeysForResourceTamper(ScanContext ctx, CancellationToken ct)
    {
        var runKeyEntries = new[]
        {
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine, "HKLM"),
        };

        foreach (var (keyPath, hive, hiveName) in runKeyEntries)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ctx.IncrementRegistryKeys();
                using var run = hive.OpenSubKey(keyPath, writable: false);
                if (run == null) continue;
                foreach (var val in run.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var data = run.GetValue(val)?.ToString() ?? string.Empty;
                    var lower = data.ToLowerInvariant();
                    bool isTamper =
                        TamperExecutables.Any(k => lower.Contains(
                            k.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase),
                            StringComparison.OrdinalIgnoreCase))
                        || (lower.Contains("altv") && lower.Contains("tamper"))
                        || (lower.Contains("altv") && lower.Contains("resource_inject"))
                        || (lower.Contains("altv") && lower.Contains("file_inject"))
                        || (lower.Contains("altv") && lower.Contains("manifest_hack"))
                        || (lower.Contains("altv") && lower.Contains("bytecode_patch"))
                        || (lower.Contains("altv") && lower.Contains("script_tamper"))
                        || (lower.Contains("alt_v") && lower.Contains("file_tamper"))
                        || (lower.Contains("alt-v") && lower.Contains("resource_hack"));
                    if (isTamper)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V resource tamper tool autostart (Run key)",
                            Risk = RiskLevel.High,
                            Location = $@"{hiveName}\{keyPath}",
                            FileName = val,
                            Reason = $"alt:V resource tampering or file injection tool configured to auto-start via Windows Run registry key. " +
                                     $"Value '{val}' points to: '{data}'. " +
                                     "Auto-start entries indicate persistent installation of resource tamper or file injection software targeting alt:V.",
                            Detail = $"Value: {val} = {data}"
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }

    private void CheckUninstallKeysForResourceTamper(ScanContext ctx, CancellationToken ct)
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        foreach (var uninstallPath in uninstallPaths)
        {
            try
            {
                using var uninst = Registry.LocalMachine.OpenSubKey(uninstallPath, writable: false);
                if (uninst == null) continue;
                foreach (var subKeyName in uninst.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var sub = uninst.OpenSubKey(subKeyName, writable: false);
                        var displayName = sub?.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        var installLocation = sub?.GetValue("InstallLocation")?.ToString() ?? string.Empty;
                        var lower = displayName.ToLowerInvariant();
                        var locLower = installLocation.ToLowerInvariant();
                        bool isTamper =
                            (lower.Contains("altv") || lower.Contains("alt:v") || lower.Contains("alt-v"))
                            && (lower.Contains("tamper") || lower.Contains("resource inject")
                                || lower.Contains("file inject") || lower.Contains("manifest hack")
                                || lower.Contains("bytecode patch") || lower.Contains("script inject")
                                || lower.Contains("asset inject") || lower.Contains("resource hack"))
                            || (locLower.Contains("altv") && locLower.Contains("tamper"))
                            || (locLower.Contains("altv") && locLower.Contains("resource_inject"))
                            || (locLower.Contains("altv") && locLower.Contains("file_inject"));
                        if (isTamper)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V resource tamper tool installer record",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                FileName = displayName,
                                Reason = $"Uninstall registry record found for alt:V resource tampering software: '{displayName}'. " +
                                         "This indicates a resource tamper or file injection tool was formally installed on this system targeting alt:V GTA:V multiplayer.",
                                Detail = $"Key: {subKeyName} | DisplayName: {displayName} | Location: {installLocation}"
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
            catch (Exception) { }
        }

        try
        {
            using var uninst = Registry.CurrentUser.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", writable: false);
            if (uninst == null) return;
            foreach (var subKeyName in uninst.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                try
                {
                    using var sub = uninst.OpenSubKey(subKeyName, writable: false);
                    var displayName = sub?.GetValue("DisplayName")?.ToString() ?? string.Empty;
                    var lower = displayName.ToLowerInvariant();
                    bool isTamper =
                        (lower.Contains("altv") || lower.Contains("alt:v") || lower.Contains("alt-v"))
                        && (lower.Contains("tamper") || lower.Contains("resource inject")
                            || lower.Contains("file inject") || lower.Contains("manifest hack")
                            || lower.Contains("bytecode patch") || lower.Contains("script inject")
                            || lower.Contains("asset inject") || lower.Contains("resource hack"));
                    if (isTamper)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V resource tamper tool installer record (HKCU)",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{subKeyName}",
                            FileName = displayName,
                            Reason = $"User-level uninstall registry record found for alt:V resource tampering software: '{displayName}'. " +
                                     "This indicates a resource tamper or file injection tool was installed at the user level targeting alt:V multiplayer.",
                            Detail = $"Key: {subKeyName} | DisplayName: {displayName}"
                        });
                    }
                }
                catch (Exception) { }
            }
        }
        catch (Exception) { }
    }

    private static IEnumerable<string> EnumerateFilesRecursive(string root, int maxDepth, CancellationToken ct)
    {
        var stack = new Stack<(string dir, int depth)>();
        stack.Push((root, 0));

        while (stack.Count > 0)
        {
            if (ct.IsCancellationRequested) yield break;
            var (dir, depth) = stack.Pop();

            string[] files = Array.Empty<string>();
            try { files = Directory.GetFiles(dir); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var f in files) yield return f;

            if (depth >= maxDepth) continue;

            string[] subDirs = Array.Empty<string>();
            try { subDirs = Directory.GetDirectories(dir); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var sub in subDirs) stack.Push((sub, depth + 1));
        }
    }

    private static string? FindLineContaining(string content, string pattern)
    {
        foreach (var line in content.Split('\n'))
        {
            if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                var trimmed = line.Trim();
                return trimmed.Length > 200 ? trimmed[..200] : trimmed;
            }
        }
        return null;
    }

    private static string Rot13Decode(string s)
    {
        return new string(s.Select(c =>
            c >= 'a' && c <= 'z' ? (char)('a' + (c - 'a' + 13) % 26) :
            c >= 'A' && c <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) : c).ToArray());
    }
}
