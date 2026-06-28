using Microsoft.Win32;
using System.Runtime.Versioning;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class RobloxExecutorDeepForensicScanModule : IScanModule
{
    public string Name => "Roblox Executor Deep Forensic";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Static path roots resolved once at class-load time
    // -------------------------------------------------------------------------
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static readonly string Downloads =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

    private static readonly string Temp =
        Path.GetTempPath();

    // -------------------------------------------------------------------------
    // Check 1 — Known executor installation directories
    // -------------------------------------------------------------------------
    private static readonly string[] ExecutorInstallDirs =
    {
        "Synapse X",
        "KRNL",
        "Sentinel",
        "Script-Ware",
        "Fluxus",
        "OxygenU",
        "JJSploit",
        "Comet",
        "Coco Z",
        "Wave",
        "Hydrogen",
    };

    // -------------------------------------------------------------------------
    // Check 2 — Known executor executable file names
    // -------------------------------------------------------------------------
    private static readonly string[] ExecutorExeNames =
    {
        "synapse.exe",
        "krnl.exe",
        "sentinellauncher.exe",
        "scriptware.exe",
        "jjsploit.exe",
        "fluxus.exe",
        "oxygenu.exe",
        "comet.exe",
        "cocoz.exe",
        "wave.exe",
        "hydrogen.exe",
        "executor.exe",
        "rbxexecutor.exe",
        "robloxhack.exe",
        "synapsex.exe",
        "krnllauncher.exe",
    };

    // -------------------------------------------------------------------------
    // Check 3 — Roblox API keywords inside workspace/autoexec script dirs
    // -------------------------------------------------------------------------
    private static readonly string[] RobloxApiKeywords =
    {
        "game:GetService",
        "Players.LocalPlayer",
        "workspace.FindFirstChild",
        "getgenv",
        "hookfunction",
    };

    // -------------------------------------------------------------------------
    // Check 4 — Exploit Lua script content keywords
    // -------------------------------------------------------------------------
    private static readonly string[] ExploitLuaKeywords =
    {
        "loadstring",
        "getgenv",
        "hookfunction",
        "require(game",
        "game:GetObjects",
        "decompile",
        "dumpstring",
        "syn.request",
        "HttpGet",
        "getrawmetatable",
        "newcclosure",
        "setreadonly",
        "getrenv",
        "getnamecallmethod",
        "checkcaller",
        "isexecutorclosure",
        "cloneref",
    };

    // -------------------------------------------------------------------------
    // Check 5 — License / auth file patterns
    // -------------------------------------------------------------------------
    private static readonly string[] AuthFileNames =
    {
        "auth.json",
        "hwid_token",
        "hwid_token.txt",
        "token.txt",
        "license.lic",
        "license.key",
    };

    private static readonly string[] AuthFileExtensions =
    {
        ".lic",
        ".key",
    };

    private static readonly string[] AuthContentKeywords =
    {
        "synapse_auth",
        "krnl_auth",
        "sentinel_token",
        "fluxus_auth",
        "hwid",
        "license_key",
    };

    // -------------------------------------------------------------------------
    // Check 6 — Game-targeting exploit script keywords
    // -------------------------------------------------------------------------
    private static readonly string[] GameNames =
    {
        "Blox Fruits",
        "Pet Simulator",
        "Arsenal",
        "Murder Mystery",
        "MM2",
        "Adopt Me",
        "Da Hood",
        "Brookhaven",
        "Bloxburg",
    };

    private static readonly string[] ExploitTechniqueKeywords =
    {
        "speedhack",
        "speed hack",
        "esp",
        "teleport",
        "aimbot",
        "noclip",
        "god mode",
        "autofarm",
        "auto farm",
        "inf stamina",
        "kill aura",
        "fly hack",
    };

    // -------------------------------------------------------------------------
    // Check 7 — Executor API DLL artifact names
    // -------------------------------------------------------------------------
    private static readonly string[] ExecutorDllNames =
    {
        "SynapseX.dll",
        "UNC.dll",
        "KRNL_core.dll",
        "executor_bridge.dll",
        "roblox_bridge.dll",
        "krnl.dll",
        "fluxus.dll",
        "hydrogen.dll",
        "sentinel.dll",
        "comet.dll",
        "wave.dll",
        "executor.dll",
    };

    // -------------------------------------------------------------------------
    // Check 8 — Executor error log content keywords
    // -------------------------------------------------------------------------
    private static readonly string[] ErrorLogKeywords =
    {
        "synapse",
        "krnl",
        "sentinel",
        "scriptware",
        "fluxus",
        "jjsploit",
        "oxygenu",
        "executor",
        "robloxplayerbeta",
        "crash",
        "exception",
        "fatal",
        "inject",
    };

    // -------------------------------------------------------------------------
    // Check 9 — Executor update/installer artifact names
    // -------------------------------------------------------------------------
    private static readonly string[] InstallerFileKeywords =
    {
        "synapse",
        "krnl",
        "sentinel",
        "scriptware",
        "jjsploit",
        "fluxus",
        "oxygenu",
        "executor",
        "roblox_hack",
        "roblox_cheat",
        "rblx_executor",
    };

    private static readonly string[] InstallerExtensions =
    {
        ".exe",
        ".msi",
        ".zip",
        ".7z",
    };

    // -------------------------------------------------------------------------
    // Check 10 — Roblox binary exploit content keywords
    // -------------------------------------------------------------------------
    private static readonly string[] RbxFileExploitKeywords =
    {
        "exploit",
        "executor",
        "script hub",
        "loadstring",
        "getgenv",
        "hookfunction",
        "hack",
        "cheat",
        "autofarm",
        "esp",
        "aimbot",
    };

    // -------------------------------------------------------------------------
    // Check 11 — Registry trace executor names (ROT13 UserAssist / MuiCache / autostart)
    // -------------------------------------------------------------------------
    private static readonly string[] ExecutorRegistryKeywords =
    {
        "synapse",
        "krnl",
        "sentinel",
        "scriptware",
        "jjsploit",
        "fluxus",
        "oxygenu",
        "cocoz",
        "hydrogen",
        "wave executor",
        "roblox executor",
        "rblxexec",
        "rbxexecutor",
    };

    // -------------------------------------------------------------------------
    // Check 12 — Prefetch executor binary names
    // -------------------------------------------------------------------------
    private static readonly string[] ExecutorPrefetchNames =
    {
        "KRNL",
        "SYNAPSE",
        "SYNAPSEX",
        "JJSPLOIT",
        "FLUXUS",
        "SENTINEL",
        "SCRIPTWARE",
        "OXYGENU",
        "HYDROGEN",
        "COCOZ",
        "WAVE",
        "ROBLOX_EXECUTOR",
        "RBXEXECUTOR",
        "EXECUTOR",
    };

    // -------------------------------------------------------------------------
    // Check 13 — Browser history text search keywords
    // -------------------------------------------------------------------------
    private static readonly string[] BrowserHistoryKeywords =
    {
        "synapse x roblox",
        "krnl executor",
        "roblox exploit",
        "roblox hack",
        "bloxburg dupe",
        "roblox executor download",
        "jjsploit download",
        "fluxus executor",
        "hydrogen executor",
        "sentinel roblox",
        "scriptware roblox",
        "roblox script hub",
        "roblox pastebin exploit",
        "oxygenu executor",
        "roblox autofarm script",
        "wave executor roblox",
    };

    // -------------------------------------------------------------------------
    // Check 14 — Discord executor artifact keywords
    // -------------------------------------------------------------------------
    private static readonly string[] DiscordExecutorKeywords =
    {
        "Synapse X Discord",
        "KRNL Discord",
        "Fluxus Discord",
        "Sentinel Discord",
        "Hydrogen Discord",
        "ScriptWare Discord",
        "executor key",
        "executor purchase",
        "executor receipt",
        "synapse purchase",
        "krnl key",
        "roblox executor invite",
        "executor whitelist",
    };

    // -------------------------------------------------------------------------
    // Check 15 — Roblox exploit script repository keywords
    // -------------------------------------------------------------------------
    private static readonly string[] ScriptRepoKeywords =
    {
        "roblox",
        "rbx",
        "exploit",
        "executor",
        "autofarm",
        "script hub",
        "loadstring",
        "getgenv",
        "hookfunction",
    };

    // -------------------------------------------------------------------------
    // Check 16 — Anti-detection / Hyperion bypass artifact keywords
    // -------------------------------------------------------------------------
    private static readonly string[] AntiDetectionKeywords =
    {
        "hyperion",
        "byfron",
        "roblox anti cheat",
        "patch memory",
        "bypass hyperion",
        "bypass byfron",
        "roblox memory patch",
        "RobloxPlayerBeta",
        "inject roblox",
        "dll inject",
        "dll injector",
        "manual map",
        "manualmap",
    };

    // -------------------------------------------------------------------------
    // Check 17 — Python automation script keywords
    // -------------------------------------------------------------------------
    private static readonly string[] PythonAutomationKeywords =
    {
        "roblox",
        "executor",
        "pywin32",
        "win32api",
        "win32gui",
        "subprocess",
        "pyautogui",
        "autoit",
        "RobloxPlayerBeta",
        "inject",
        "krnl",
        "synapse",
        "jjsploit",
    };

    // -------------------------------------------------------------------------
    // Check 18 — Payment artifact keywords in Downloads/email files
    // -------------------------------------------------------------------------
    private static readonly string[] PaymentArtifactKeywords =
    {
        "synapse x",
        "krnl",
        "sentinel",
        "scriptware",
        "fluxus",
        "jjsploit",
        "hydrogen executor",
        "wave executor",
        "oxygenu",
        "executor subscription",
        "executor purchase",
        "roblox executor",
        "receipt",
        "invoice",
        "paypal",
        "crypto",
        "bitcoin",
    };

    // =========================================================================
    // RunAsync — fan-out to all 18 sub-checks in parallel
    // =========================================================================
    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.WhenAll(
            CheckExecutorInstallDirs(ctx, ct),
            CheckExecutorExeFiles(ctx, ct),
            CheckWorkspaceAutoexecScripts(ctx, ct),
            CheckExploitLuaScripts(ctx, ct),
            CheckLicenseAuthFiles(ctx, ct),
            CheckGameTargetingScripts(ctx, ct),
            CheckExecutorDllArtifacts(ctx, ct),
            CheckCrashDumpsAndErrorLogs(ctx, ct),
            CheckInstallerArtifacts(ctx, ct),
            CheckRobloxBinaryFiles(ctx, ct),
            CheckRegistryTraces(ctx, ct),
            CheckPrefetchArtifacts(ctx, ct),
            CheckBrowserHistoryFiles(ctx, ct),
            CheckDiscordArtifacts(ctx, ct),
            CheckScriptRepositories(ctx, ct),
            CheckAntiDetectionArtifacts(ctx, ct),
            CheckPythonAutomationScripts(ctx, ct),
            CheckPaymentArtifacts(ctx, ct)
        );
    }

    // =========================================================================
    // Check 1 — Executor installation directories
    // =========================================================================
    private Task CheckExecutorInstallDirs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            foreach (var dirName in ExecutorInstallDirs)
            {
                ct.ThrowIfCancellationRequested();
                var fullPath = Path.Combine(LocalAppData, dirName);
                if (!Directory.Exists(fullPath)) continue;

                try
                {
                    ctx.IncrementFiles();
                    var entries = Directory.GetFileSystemEntries(fullPath);
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Roblox Executor installation directory: {dirName}",
                        Risk     = RiskLevel.Critical,
                        Location = fullPath,
                        FileName = dirName,
                        Reason   = $"The directory '{fullPath}' is the known installation path for the " +
                                   $"'{dirName}' Roblox exploit executor. Presence of this directory " +
                                   "confirms the executor was installed on this system.",
                        Detail   = $"Directory: {fullPath} | Entries: {entries.Length}",
                    });
                }
                catch { }
            }

            ctx.Report(0.05, "ExecutorDirs", "Executor install directories checked");
        }, ct);

    // =========================================================================
    // Check 2 — Executor executable files in common user directories
    // =========================================================================
    private Task CheckExecutorExeFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var searchRoots = new[]
            {
                Downloads,
                Desktop,
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                UserProfile,
            };

            foreach (var root in searchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;

                string[] files;
                try
                {
                    files = Directory.GetFiles(root, "*.exe", SearchOption.TopDirectoryOnly);
                }
                catch { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var fileName = Path.GetFileName(file);
                    ctx.IncrementFiles();

                    var matched = ExecutorExeNames.FirstOrDefault(n =>
                        fileName.Equals(n, StringComparison.OrdinalIgnoreCase));

                    if (matched is null)
                    {
                        var lower = fileName.ToLowerInvariant();
                        matched = ExecutorExeNames.FirstOrDefault(n =>
                            lower.Contains(n.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase),
                                StringComparison.OrdinalIgnoreCase));
                    }

                    if (matched is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Roblox executor executable: {fileName}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"The file '{fileName}' matches the known name of a Roblox exploit " +
                                   $"executor (matched pattern: '{matched}'). Found in: {root}.",
                        Detail   = $"Path: {file}",
                    });
                }
            }

            ctx.Report(0.10, "ExecutorExes", "Executor executable files checked");
        }, ct);

    // =========================================================================
    // Check 3 — Workspace / autoexec script directories with Roblox API calls
    // =========================================================================
    private Task CheckWorkspaceAutoexecScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var workspaceDirNames = new[]
            {
                "workspace",
                "autoexec",
                "scripts",
                "auto_exec",
            };

            foreach (var executorDir in ExecutorInstallDirs)
            {
                ct.ThrowIfCancellationRequested();
                var executorRoot = Path.Combine(LocalAppData, executorDir);
                if (!Directory.Exists(executorRoot)) continue;

                foreach (var wsDirName in workspaceDirNames)
                {
                    ct.ThrowIfCancellationRequested();
                    var wsPath = Path.Combine(executorRoot, wsDirName);
                    if (!Directory.Exists(wsPath)) continue;

                    string[] luaFiles;
                    try
                    {
                        luaFiles = Directory.GetFiles(wsPath, "*.lua", SearchOption.AllDirectories);
                    }
                    catch { continue; }

                    foreach (var luaFile in luaFiles)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();

                        try
                        {
                            string content;
                            using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);

                            var matchedApi = RobloxApiKeywords.FirstOrDefault(kw =>
                                content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                            if (matchedApi is null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Executor autoexec script with Roblox API: {Path.GetFileName(luaFile)}",
                                Risk     = RiskLevel.Critical,
                                Location = luaFile,
                                FileName = Path.GetFileName(luaFile),
                                Reason   = $"Lua script found in executor workspace/autoexec directory " +
                                           $"'{wsPath}' contains the Roblox API call '{matchedApi}'. " +
                                           "Autoexec scripts run automatically when the executor attaches to Roblox.",
                                Detail   = $"Executor: {executorDir} | API keyword: {matchedApi} | File: {luaFile}",
                            });
                        }
                        catch { }
                    }
                }
            }

            ctx.Report(0.15, "AutoexecScripts", "Workspace autoexec scripts checked");
        }, ct);

    // =========================================================================
    // Check 4 — Exploit Lua scripts in user directories
    // =========================================================================
    private Task CheckExploitLuaScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var luaSearchRoots = new[]
            {
                Downloads,
                Desktop,
                Path.Combine(UserProfile, "Documents"),
                Path.Combine(AppData, "Roblox"),
                Path.Combine(LocalAppData, "Roblox"),
            };

            foreach (var root in luaSearchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;

                string[] luaFiles;
                try
                {
                    luaFiles = Directory.GetFiles(root, "*.lua", SearchOption.AllDirectories);
                }
                catch { continue; }

                foreach (var luaFile in luaFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        string content;
                        using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);

                        var matchedKw = ExploitLuaKeywords.FirstOrDefault(kw =>
                            content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                        if (matchedKw is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Roblox exploit Lua script: {Path.GetFileName(luaFile)}",
                            Risk     = RiskLevel.High,
                            Location = luaFile,
                            FileName = Path.GetFileName(luaFile),
                            Reason   = $"Lua script at '{luaFile}' contains the exploit API keyword " +
                                       $"'{matchedKw}'. This function is specific to Roblox executor " +
                                       "environments and is not present in legitimate Roblox client scripts.",
                            Detail   = $"Keyword: {matchedKw} | Path: {luaFile}",
                        });
                    }
                    catch { }
                }
            }

            ctx.Report(0.20, "ExploitLua", "Exploit Lua scripts checked");
        }, ct);

    // =========================================================================
    // Check 5 — Executor license key and auth files
    // =========================================================================
    private Task CheckLicenseAuthFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            foreach (var executorDir in ExecutorInstallDirs)
            {
                ct.ThrowIfCancellationRequested();
                var executorRoot = Path.Combine(LocalAppData, executorDir);
                if (!Directory.Exists(executorRoot)) continue;

                string[] allFiles;
                try
                {
                    allFiles = Directory.GetFiles(executorRoot, "*", SearchOption.AllDirectories);
                }
                catch { continue; }

                foreach (var file in allFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    var fileName = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    var isAuthByName = AuthFileNames.Any(n =>
                        fileName.Equals(n, StringComparison.OrdinalIgnoreCase));

                    var isAuthByExt = AuthFileExtensions.Any(e =>
                        ext.Equals(e, StringComparison.OrdinalIgnoreCase));

                    if (isAuthByName || isAuthByExt)
                    {
                        string? contentSnippet = null;
                        string? matchedKw = null;
                        try
                        {
                            string content;
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);

                            matchedKw = AuthContentKeywords.FirstOrDefault(kw =>
                                content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                            var preview = content.Length > 120 ? content[..120] : content;
                            contentSnippet = preview.Replace('\n', ' ').Replace('\r', ' ');
                        }
                        catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Executor license/auth file: {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"License or authentication file '{fileName}' found inside " +
                                       $"the '{executorDir}' executor directory. These files contain " +
                                       "HWID tokens or license keys used to authenticate executor access." +
                                       (matchedKw is not null ? $" Content keyword: '{matchedKw}'." : ""),
                            Detail   = $"Executor: {executorDir} | File: {file}" +
                                       (contentSnippet is not null ? $" | Preview: {contentSnippet}" : ""),
                        });
                        continue;
                    }

                    if (isAuthByExt) continue;

                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);

                        var matchedKw = AuthContentKeywords.FirstOrDefault(kw =>
                            content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                        if (matchedKw is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Executor auth token in file: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"File '{fileName}' in executor directory contains the auth " +
                                       $"keyword '{matchedKw}', indicating it stores authentication " +
                                       "or HWID data for the executor.",
                            Detail   = $"Executor: {executorDir} | Keyword: {matchedKw} | File: {file}",
                        });
                    }
                    catch { }
                }
            }

            ctx.Report(0.25, "AuthFiles", "License/auth files checked");
        }, ct);

    // =========================================================================
    // Check 6 — Game-targeting exploit scripts
    // =========================================================================
    private Task CheckGameTargetingScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var searchRoots = new[]
            {
                Downloads,
                Desktop,
                Path.Combine(UserProfile, "Documents"),
            };

            foreach (var executorDir in ExecutorInstallDirs)
            {
                var wsPath = Path.Combine(LocalAppData, executorDir, "workspace");
                if (Directory.Exists(wsPath) && !searchRoots.Contains(wsPath, StringComparer.OrdinalIgnoreCase))
                {
                    searchRoots = searchRoots.Append(wsPath).ToArray();
                }
                var autoexecPath = Path.Combine(LocalAppData, executorDir, "autoexec");
                if (Directory.Exists(autoexecPath) && !searchRoots.Contains(autoexecPath, StringComparer.OrdinalIgnoreCase))
                {
                    searchRoots = searchRoots.Append(autoexecPath).ToArray();
                }
            }

            foreach (var root in searchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;

                string[] luaFiles;
                try
                {
                    luaFiles = Directory.GetFiles(root, "*.lua", SearchOption.AllDirectories);
                }
                catch { continue; }

                foreach (var luaFile in luaFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        string content;
                        using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);

                        var matchedGame = GameNames.FirstOrDefault(g =>
                            content.Contains(g, StringComparison.OrdinalIgnoreCase));

                        if (matchedGame is null) continue;

                        var matchedTech = ExploitTechniqueKeywords.FirstOrDefault(t =>
                            content.Contains(t, StringComparison.OrdinalIgnoreCase));

                        if (matchedTech is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Game-targeting exploit script ({matchedGame}): {Path.GetFileName(luaFile)}",
                            Risk     = RiskLevel.Critical,
                            Location = luaFile,
                            FileName = Path.GetFileName(luaFile),
                            Reason   = $"Lua script targets the Roblox game '{matchedGame}' and contains " +
                                       $"the exploit technique keyword '{matchedTech}'. This is a game-specific " +
                                       "cheat script designed to manipulate gameplay.",
                            Detail   = $"Game: {matchedGame} | Technique: {matchedTech} | File: {luaFile}",
                        });
                    }
                    catch { }
                }
            }

            ctx.Report(0.30, "GameScripts", "Game-targeting exploit scripts checked");
        }, ct);

    // =========================================================================
    // Check 7 — Executor API DLL artifacts
    // =========================================================================
    private Task CheckExecutorDllArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            foreach (var executorDir in ExecutorInstallDirs)
            {
                ct.ThrowIfCancellationRequested();
                var executorRoot = Path.Combine(LocalAppData, executorDir);
                if (!Directory.Exists(executorRoot)) continue;

                string[] allFiles;
                try
                {
                    allFiles = Directory.GetFiles(executorRoot, "*", SearchOption.AllDirectories);
                }
                catch { continue; }

                foreach (var file in allFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    var fileName = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);
                    ctx.IncrementFiles();

                    if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase))
                    {
                        var isKnownDll = ExecutorDllNames.Any(d =>
                            fileName.Equals(d, StringComparison.OrdinalIgnoreCase));

                        var riskLevel = isKnownDll ? RiskLevel.Critical : RiskLevel.High;
                        var dllReason = isKnownDll
                            ? $"DLL '{fileName}' matches the known executor API DLL name."
                            : $"Unsigned DLL '{fileName}' found inside executor directory '{executorDir}'.";

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Executor DLL artifact: {fileName}",
                            Risk     = riskLevel,
                            Location = file,
                            FileName = fileName,
                            Reason   = dllReason + " Executor DLLs implement the exploit API surface " +
                                       "(UNC, syn.*, getgenv, etc.) injected into the Roblox process.",
                            Detail   = $"Executor: {executorDir} | File: {file}",
                        });
                        continue;
                    }

                    if (ext.Equals(".bin", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            var header = new byte[2];
                            if (await fs.ReadAsync(header.AsMemory(0, 2), ct) == 2 &&
                                header[0] == 0x4D && header[1] == 0x5A)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"Executor PE binary with .bin extension: {fileName}",
                                    Risk     = RiskLevel.High,
                                    Location = file,
                                    FileName = fileName,
                                    Reason   = $"File '{fileName}' in executor directory has a .bin extension " +
                                               "but contains an MZ (PE) header, indicating a renamed executable " +
                                               "or DLL used to evade file-extension-based detection.",
                                    Detail   = $"Executor: {executorDir} | MZ header confirmed | File: {file}",
                                });
                            }
                        }
                        catch { }
                    }
                }
            }

            ctx.Report(0.35, "ExecutorDlls", "Executor DLL artifacts checked");
        }, ct);

    // =========================================================================
    // Check 8 — Executor crash dumps and error logs
    // =========================================================================
    private Task CheckCrashDumpsAndErrorLogs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var werDumpDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Microsoft\Windows\WER\ReportArchive");

            if (Directory.Exists(werDumpDir))
            {
                string[] reportDirs;
                try
                {
                    reportDirs = Directory.GetDirectories(werDumpDir);
                }
                catch { reportDirs = Array.Empty<string>(); }

                foreach (var reportDir in reportDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    var dirName = Path.GetFileName(reportDir).ToLowerInvariant();

                    var matchedExecutor = ExecutorRegistryKeywords.FirstOrDefault(kw =>
                        dirName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedExecutor is null) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"WER crash dump for executor process: {Path.GetFileName(reportDir)}",
                        Risk     = RiskLevel.High,
                        Location = reportDir,
                        FileName = Path.GetFileName(reportDir),
                        Reason   = $"Windows Error Reporting crash dump directory '{Path.GetFileName(reportDir)}' " +
                                   $"contains the executor keyword '{matchedExecutor}', indicating the executor " +
                                   "process crashed and Windows captured a dump. Crash artifacts persist after deletion.",
                        Detail   = $"WER report dir: {reportDir} | Keyword: {matchedExecutor}",
                    });
                }
            }

            foreach (var executorDir in ExecutorInstallDirs)
            {
                ct.ThrowIfCancellationRequested();
                var executorRoot = Path.Combine(LocalAppData, executorDir);
                if (!Directory.Exists(executorRoot)) continue;

                var errorLogPatterns = new[] { "error.log", "crash.log", "*.log" };
                foreach (var pattern in errorLogPatterns)
                {
                    string[] logFiles;
                    try
                    {
                        logFiles = Directory.GetFiles(executorRoot, pattern, SearchOption.AllDirectories);
                    }
                    catch { continue; }

                    foreach (var logFile in logFiles)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();

                        try
                        {
                            string content;
                            using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);

                            var matchedKw = ErrorLogKeywords.FirstOrDefault(kw =>
                                content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                            if (matchedKw is null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Executor error log: {Path.GetFileName(logFile)}",
                                Risk     = RiskLevel.Medium,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason   = $"Error log file '{Path.GetFileName(logFile)}' inside executor " +
                                           $"directory '{executorDir}' contains crash/error information. " +
                                           $"Matched keyword: '{matchedKw}'.",
                                Detail   = $"Executor: {executorDir} | Keyword: {matchedKw} | File: {logFile}",
                            });
                        }
                        catch { }
                    }
                }
            }

            ctx.Report(0.40, "CrashLogs", "Crash dumps and error logs checked");
        }, ct);

    // =========================================================================
    // Check 9 — Executor update and installer artifacts
    // =========================================================================
    private Task CheckInstallerArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var searchRoots = new[]
            {
                Downloads,
                Desktop,
                Temp,
                Path.Combine(LocalAppData, "Temp"),
            };

            foreach (var root in searchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;

                string[] files;
                try
                {
                    files = Directory.GetFiles(root, "*", SearchOption.TopDirectoryOnly);
                }
                catch { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var fileName = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);
                    ctx.IncrementFiles();

                    var hasInstallerExt = InstallerExtensions.Any(e =>
                        ext.Equals(e, StringComparison.OrdinalIgnoreCase));

                    if (!hasInstallerExt) continue;

                    var lower = fileName.ToLowerInvariant();
                    var matchedKw = InstallerFileKeywords.FirstOrDefault(kw =>
                        lower.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Executor installer/update artifact: {fileName}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason   = $"File '{fileName}' in '{root}' matches the executor keyword " +
                                   $"'{matchedKw}' and has an installer extension '{ext}'. " +
                                   "This is likely an executor installer, updater, or bootstrapper.",
                        Detail   = $"Path: {file} | Keyword: {matchedKw}",
                    });
                }
            }

            foreach (var executorDir in ExecutorInstallDirs)
            {
                ct.ThrowIfCancellationRequested();
                var executorRoot = Path.Combine(LocalAppData, executorDir);
                if (!Directory.Exists(executorRoot)) continue;

                string[] logFiles;
                try
                {
                    logFiles = Directory.GetFiles(executorRoot, "*.log", SearchOption.TopDirectoryOnly);
                }
                catch { continue; }

                foreach (var logFile in logFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    var fileName = Path.GetFileName(logFile);
                    ctx.IncrementFiles();

                    var lowerName = fileName.ToLowerInvariant();
                    if (!lowerName.Contains("install", StringComparison.OrdinalIgnoreCase) &&
                        !lowerName.Contains("update", StringComparison.OrdinalIgnoreCase) &&
                        !lowerName.Contains("bootstrap", StringComparison.OrdinalIgnoreCase))
                        continue;

                    string? firstLine = null;
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        firstLine = await sr.ReadLineAsync(ct);
                    }
                    catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Executor installer log: {fileName}",
                        Risk     = RiskLevel.Medium,
                        Location = logFile,
                        FileName = fileName,
                        Reason   = $"Installer/update log file '{fileName}' found in executor " +
                                   $"directory '{executorDir}', indicating the executor was " +
                                   "recently installed or updated.",
                        Detail   = $"Executor: {executorDir} | File: {logFile}" +
                                   (firstLine is not null ? $" | First line: {firstLine}" : ""),
                    });
                }
            }

            ctx.Report(0.45, "InstallerArtifacts", "Installer artifacts checked");
        }, ct);

    // =========================================================================
    // Check 10 — Roblox binary exploit files (.rbxl/.rbxlx/.rbxm)
    // =========================================================================
    private Task CheckRobloxBinaryFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var rbxSearchRoots = new[]
            {
                Downloads,
                Desktop,
                Path.Combine(UserProfile, "Documents"),
                Path.Combine(LocalAppData, "Roblox"),
            };

            var rbxExtensions = new[] { ".rbxl", ".rbxlx", ".rbxm", ".rbxmx" };

            foreach (var root in rbxSearchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;

                string[] files;
                try
                {
                    files = Directory.GetFiles(root, "*", SearchOption.AllDirectories);
                }
                catch { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    if (!rbxExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    ctx.IncrementFiles();

                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);

                        var matchedKw = RbxFileExploitKeywords.FirstOrDefault(kw =>
                            content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                        if (matchedKw is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Roblox file with exploit content: {Path.GetFileName(file)}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason   = $"Roblox '{ext}' file contains the exploit keyword '{matchedKw}'. " +
                                       "Roblox place and model files can contain embedded scripts that " +
                                       "execute exploit code when loaded in the Roblox client.",
                            Detail   = $"Extension: {ext} | Keyword: {matchedKw} | File: {file}",
                        });
                    }
                    catch { }
                }
            }

            ctx.Report(0.50, "RbxFiles", "Roblox binary files checked");
        }, ct);

    // =========================================================================
    // Check 11 — Registry traces (UserAssist, MuiCache, Run/RunOnce, AppCompatFlags)
    // =========================================================================
    private Task CheckRegistryTraces(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();

            CheckUserAssistRegistry(ctx, ct);
            CheckMuiCacheRegistry(ctx, ct);
            CheckRunAutostart(ctx, ct);
            CheckAppCompatFlags(ctx, ct);

            ctx.Report(0.55, "RegistryTraces", "Registry traces checked");
        }, ct);

    private void CheckUserAssistRegistry(ScanContext ctx, CancellationToken ct)
    {
        var userAssistGuids = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count",
        };

        foreach (var keyPath in userAssistGuids)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    var decoded = Rot13(valueName);
                    var decodedLower = decoded.ToLowerInvariant();

                    var matchedKw = ExecutorRegistryKeywords.FirstOrDefault(kw =>
                        decodedLower.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"UserAssist executor trace (ROT13): {matchedKw}",
                        Risk     = RiskLevel.High,
                        Location = $@"HKCU\{keyPath}\{valueName}",
                        FileName = Path.GetFileName(decoded),
                        Reason   = $"UserAssist registry entry (ROT13-decoded: '{decoded}') contains " +
                                   $"the executor keyword '{matchedKw}'. UserAssist records every " +
                                   "application launched from Explorer, persisting even after deletion.",
                        Detail   = $"ROT13 encoded: {valueName} | Decoded: {decoded} | Keyword: {matchedKw}",
                    });
                }
            }
            catch { }
        }
    }

    private void CheckMuiCacheRegistry(ScanContext ctx, CancellationToken ct)
    {
        const string muiCachePath =
            @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(muiCachePath);
            if (key is null) return;

            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                var lower = valueName.ToLowerInvariant();
                var matchedKw = ExecutorRegistryKeywords.FirstOrDefault(kw =>
                    lower.Contains(kw, StringComparison.OrdinalIgnoreCase));

                if (matchedKw is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"MuiCache executor trace: {matchedKw}",
                    Risk     = RiskLevel.High,
                    Location = $@"HKCU\{muiCachePath}\{valueName}",
                    FileName = Path.GetFileName(valueName),
                    Reason   = $"MuiCache registry entry '{valueName}' contains the executor keyword " +
                               $"'{matchedKw}'. MuiCache records every executed program's friendly name, " +
                               "persisting as forensic evidence even after the file is deleted.",
                    Detail   = $"MuiCache key: {valueName} | Keyword: {matchedKw}",
                });
            }
        }
        catch { }
    }

    private void CheckRunAutostart(ScanContext ctx, CancellationToken ct)
    {
        var runKeys = new[]
        {
            (Registry.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        };

        foreach (var (hive, keyPath) in runKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = hive.OpenSubKey(keyPath);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    var value = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    var combined = (valueName + " " + value).ToLowerInvariant();

                    var matchedKw = ExecutorRegistryKeywords.FirstOrDefault(kw =>
                        combined.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Executor autostart Run key: {valueName}",
                        Risk     = RiskLevel.Critical,
                        Location = $@"{(hive == Registry.CurrentUser ? "HKCU" : "HKLM")}\{keyPath}\{valueName}",
                        FileName = Path.GetFileName(value.Trim('"')),
                        Reason   = $"Run/RunOnce registry key '{valueName}' with value '{value}' " +
                                   $"contains executor keyword '{matchedKw}'. This causes the executor " +
                                   "to launch automatically at logon.",
                        Detail   = $"Key: {keyPath} | Name: {valueName} | Value: {value}",
                    });
                }
            }
            catch { }
        }
    }

    private void CheckAppCompatFlags(ScanContext ctx, CancellationToken ct)
    {
        const string appCompatPath =
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store";

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(appCompatPath);
            if (key is null) return;

            foreach (var valueName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();

                var lower = valueName.ToLowerInvariant();
                var matchedKw = ExecutorRegistryKeywords.FirstOrDefault(kw =>
                    lower.Contains(kw, StringComparison.OrdinalIgnoreCase));

                if (matchedKw is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"AppCompatFlags executor trace: {matchedKw}",
                    Risk     = RiskLevel.Medium,
                    Location = $@"HKCU\{appCompatPath}\{valueName}",
                    FileName = Path.GetFileName(valueName),
                    Reason   = $"AppCompatFlags Compatibility Assistant entry '{valueName}' references " +
                               $"executor keyword '{matchedKw}'. Windows records executed programs here " +
                               "as compatibility shim history, persisting after the binary is removed.",
                    Detail   = $"AppCompat entry: {valueName} | Keyword: {matchedKw}",
                });
            }
        }
        catch { }
    }

    // =========================================================================
    // Check 12 — Prefetch artifacts for executor processes
    // =========================================================================
    private Task CheckPrefetchArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            const string prefetchDir = @"C:\Windows\Prefetch";

            if (!Directory.Exists(prefetchDir))
            {
                ctx.Report(0.60, "Prefetch", "Prefetch directory not accessible");
                return;
            }

            string[] pfFiles;
            try
            {
                pfFiles = Directory.GetFiles(prefetchDir, "*.pf");
            }
            catch
            {
                ctx.Report(0.60, "Prefetch", "No access to Prefetch directory");
                return;
            }

            foreach (var pfFile in pfFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                var pfName = Path.GetFileNameWithoutExtension(pfFile).ToUpperInvariant();
                var dashIdx = pfName.LastIndexOf('-');
                var exeBase = dashIdx > 0 && pfName.Length - dashIdx == 9
                    ? pfName[..dashIdx]
                    : pfName;

                var matchedName = ExecutorPrefetchNames.FirstOrDefault(n =>
                    exeBase.Equals(n, StringComparison.OrdinalIgnoreCase) ||
                    exeBase.Contains(n, StringComparison.OrdinalIgnoreCase));

                if (matchedName is null) continue;

                DateTime lastWrite = default;
                try { lastWrite = File.GetLastWriteTime(pfFile); } catch { }

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Prefetch: executor process evidence ({exeBase}.exe)",
                    Risk     = RiskLevel.High,
                    Location = pfFile,
                    FileName = exeBase + ".exe",
                    Reason   = $"Windows Prefetch file '{Path.GetFileName(pfFile)}' records execution of " +
                               $"'{exeBase}.exe', which matches the Roblox executor name '{matchedName}'. " +
                               "Prefetch entries persist after the executable is deleted.",
                    Detail   = lastWrite != default
                        ? $"Prefetch last updated: {lastWrite:yyyy-MM-dd HH:mm:ss} | File: {pfFile}"
                        : $"File: {pfFile}",
                });
            }

            ctx.Report(0.60, "Prefetch", "Executor prefetch artifacts checked");
        }, ct);

    // =========================================================================
    // Check 13 — Browser history files containing executor/exploit search terms
    // =========================================================================
    private Task CheckBrowserHistoryFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();

            var browserProfileRoots = new List<string>();

            var chromiumBases = new[]
            {
                Path.Combine(LocalAppData, "Google", "Chrome", "User Data"),
                Path.Combine(LocalAppData, "Microsoft", "Edge", "User Data"),
                Path.Combine(LocalAppData, "BraveSoftware", "Brave-Browser", "User Data"),
                Path.Combine(LocalAppData, "Opera Software", "Opera Stable"),
                Path.Combine(LocalAppData, "Vivaldi", "User Data"),
            };

            foreach (var chromBase in chromiumBases)
            {
                if (!Directory.Exists(chromBase)) continue;
                foreach (var profileDir in new[] { "Default", "Profile 1", "Profile 2" })
                {
                    var historyFile = Path.Combine(chromBase, profileDir, "History");
                    if (File.Exists(historyFile))
                        browserProfileRoots.Add(historyFile);
                }
            }

            var firefoxBase = Path.Combine(AppData, "Mozilla", "Firefox", "Profiles");
            if (Directory.Exists(firefoxBase))
            {
                try
                {
                    foreach (var profileDir in Directory.GetDirectories(firefoxBase))
                    {
                        var placesDb = Path.Combine(profileDir, "places.sqlite");
                        if (File.Exists(placesDb))
                            browserProfileRoots.Add(placesDb);
                    }
                }
                catch { }
            }

            foreach (var histFile in browserProfileRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!File.Exists(histFile)) continue;
                ctx.IncrementFiles();

                string tempCopy = Path.Combine(
                    Path.GetTempPath(),
                    $"zt_hist_{Guid.NewGuid():N}.tmp");

                try
                {
                    File.Copy(histFile, tempCopy, overwrite: true);

                    string content;
                    using var fs = new FileStream(tempCopy, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                    content = await sr.ReadToEndAsync(ct);

                    var matchedKw = BrowserHistoryKeywords.FirstOrDefault(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Browser history: Roblox executor search/visit",
                        Risk     = RiskLevel.Medium,
                        Location = histFile,
                        FileName = Path.GetFileName(histFile),
                        Reason   = $"Browser history file contains the string '{matchedKw}', " +
                                   "indicating the user searched for or visited pages related to " +
                                   "Roblox executor downloads, exploit scripts, or cheat tools.",
                        Detail   = $"History file: {histFile} | Keyword: {matchedKw}",
                    });
                }
                catch { }
                finally
                {
                    try { if (File.Exists(tempCopy)) File.Delete(tempCopy); } catch { }
                }
            }

            ctx.Report(0.65, "BrowserHistory", "Browser history files checked");
        }, ct);

    // =========================================================================
    // Check 14 — Discord cache artifacts with executor references
    // =========================================================================
    private Task CheckDiscordArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var discordClients = new[] { "discord", "discordptb", "discordcanary" };

            foreach (var client in discordClients)
            {
                ct.ThrowIfCancellationRequested();
                var discordRoot = Path.Combine(AppData, client);
                if (!Directory.Exists(discordRoot)) continue;

                var cacheDirs = new[]
                {
                    Path.Combine(discordRoot, "Cache"),
                    Path.Combine(discordRoot, "Local Storage", "leveldb"),
                    Path.Combine(discordRoot, "Session Storage"),
                };

                foreach (var cacheDir in cacheDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!Directory.Exists(cacheDir)) continue;

                    string[] cacheFiles;
                    try
                    {
                        cacheFiles = Directory.GetFiles(cacheDir, "*", SearchOption.TopDirectoryOnly);
                    }
                    catch { continue; }

                    foreach (var cacheFile in cacheFiles)
                    {
                        ct.ThrowIfCancellationRequested();
                        var ext = Path.GetExtension(cacheFile).ToLowerInvariant();
                        if (ext is ".png" or ".jpg" or ".jpeg" or ".gif" or ".webp") continue;

                        ctx.IncrementFiles();

                        try
                        {
                            string content;
                            using var fs = new FileStream(cacheFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs, Encoding.UTF8,
                                detectEncodingFromByteOrderMarks: true);
                            content = await sr.ReadToEndAsync(ct);

                            var matchedKw = DiscordExecutorKeywords.FirstOrDefault(kw =>
                                content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                            if (matchedKw is null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Discord cache: executor reference ({client})",
                                Risk     = RiskLevel.High,
                                Location = cacheFile,
                                FileName = Path.GetFileName(cacheFile),
                                Reason   = $"Discord ({client}) cache file contains '{matchedKw}', " +
                                           "indicating activity in executor-related Discord servers, " +
                                           "purchase confirmations, or key deliveries via Discord.",
                                Detail   = $"Client: {client} | Cache dir: {cacheDir} | " +
                                           $"Keyword: {matchedKw} | File: {cacheFile}",
                            });
                        }
                        catch { }
                    }
                }
            }

            ctx.Report(0.70, "DiscordArtifacts", "Discord artifacts checked");
        }, ct);

    // =========================================================================
    // Check 15 — Roblox exploit script repositories
    // =========================================================================
    private Task CheckScriptRepositories(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var repoSearchRoots = new[]
            {
                Downloads,
                Desktop,
                Path.Combine(UserProfile, "Documents"),
                Path.Combine(UserProfile, "repos"),
                Path.Combine(UserProfile, "Projects"),
            };

            foreach (var root in repoSearchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;

                string[] subDirs;
                try
                {
                    subDirs = Directory.GetDirectories(root, "*", SearchOption.TopDirectoryOnly);
                }
                catch { continue; }

                foreach (var subDir in subDirs)
                {
                    ct.ThrowIfCancellationRequested();
                    var dirName = Path.GetFileName(subDir).ToLowerInvariant();

                    var isGitRepo = Directory.Exists(Path.Combine(subDir, ".git"));
                    var hasLuaFiles = false;
                    var luaCount = 0;

                    var dirNameMatchedKw = ScriptRepoKeywords.FirstOrDefault(kw =>
                        dirName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (dirNameMatchedKw is null && !isGitRepo) continue;

                    string[] luaFiles;
                    try
                    {
                        luaFiles = Directory.GetFiles(subDir, "*.lua", SearchOption.AllDirectories);
                        luaCount = luaFiles.Length;
                        hasLuaFiles = luaCount > 0;
                    }
                    catch { continue; }

                    if (!hasLuaFiles) continue;

                    string? contentMatchedKw = null;
                    foreach (var luaFile in luaFiles.Take(10))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            string content;
                            using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);

                            contentMatchedKw = ScriptRepoKeywords.FirstOrDefault(kw =>
                                content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                            if (contentMatchedKw is not null) break;
                        }
                        catch { }
                    }

                    if (dirNameMatchedKw is null && contentMatchedKw is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Roblox exploit script repository: {Path.GetFileName(subDir)}",
                        Risk     = RiskLevel.High,
                        Location = subDir,
                        FileName = Path.GetFileName(subDir),
                        Reason   = $"Directory '{Path.GetFileName(subDir)}' " +
                                   (isGitRepo ? "(git repository) " : "") +
                                   $"contains {luaCount} Lua files with Roblox exploit content. " +
                                   (dirNameMatchedKw is not null
                                       ? $"Directory name keyword: '{dirNameMatchedKw}'. "
                                       : "") +
                                   (contentMatchedKw is not null
                                       ? $"Script content keyword: '{contentMatchedKw}'."
                                       : ""),
                        Detail   = $"Path: {subDir} | Git repo: {isGitRepo} | " +
                                   $"Lua files: {luaCount} | Keywords matched: " +
                                   $"{dirNameMatchedKw ?? "none"}/{contentMatchedKw ?? "none"}",
                    });
                }

                string[] zipFiles;
                try
                {
                    zipFiles = Directory.GetFiles(root, "*.zip", SearchOption.TopDirectoryOnly);
                }
                catch { continue; }

                foreach (var zipFile in zipFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    var zipName = Path.GetFileName(zipFile).ToLowerInvariant();
                    ctx.IncrementFiles();

                    var matchedKw = ScriptRepoKeywords.FirstOrDefault(kw =>
                        zipName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (matchedKw is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Roblox script collection ZIP: {Path.GetFileName(zipFile)}",
                        Risk     = RiskLevel.Medium,
                        Location = zipFile,
                        FileName = Path.GetFileName(zipFile),
                        Reason   = $"ZIP archive '{Path.GetFileName(zipFile)}' contains the Roblox/exploit " +
                                   $"keyword '{matchedKw}', suggesting it is a downloaded collection of " +
                                   "Roblox exploit scripts.",
                        Detail   = $"ZIP: {zipFile} | Keyword: {matchedKw}",
                    });
                }
            }

            ctx.Report(0.75, "ScriptRepos", "Script repositories checked");
        }, ct);

    // =========================================================================
    // Check 16 — Anti-detection artifacts targeting Roblox Hyperion/Byfron
    // =========================================================================
    private Task CheckAntiDetectionArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var searchRoots = new[]
            {
                Downloads,
                Desktop,
                Temp,
                Path.Combine(LocalAppData, "Temp"),
                Path.Combine(UserProfile, "Documents"),
            };

            foreach (var executorDir in ExecutorInstallDirs)
            {
                var execRoot = Path.Combine(LocalAppData, executorDir);
                if (Directory.Exists(execRoot))
                    searchRoots = searchRoots.Append(execRoot).ToArray();
            }

            var textExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".lua", ".py", ".txt", ".bat", ".ps1", ".vbs", ".js", ".ts", ".cs", ".cpp", ".c",
            };

            var binaryExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".exe", ".dll", ".bin", ".sys",
            };

            foreach (var root in searchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;

                string[] files;
                try
                {
                    files = Directory.GetFiles(root, "*", SearchOption.TopDirectoryOnly);
                }
                catch { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    var fileName = Path.GetFileName(file);
                    var fileNameLower = fileName.ToLowerInvariant();
                    ctx.IncrementFiles();

                    var nameMatchedKw = AntiDetectionKeywords.FirstOrDefault(kw =>
                        fileNameLower.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (nameMatchedKw is not null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Anti-detection artifact (filename): {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"File '{fileName}' has a name matching anti-detection keyword " +
                                       $"'{nameMatchedKw}', indicating it may be a tool or script designed " +
                                       "to patch Roblox memory, bypass Hyperion/Byfron, or inject into " +
                                       "RobloxPlayerBeta.exe.",
                            Detail   = $"Path: {file} | Keyword: {nameMatchedKw}",
                        });
                        continue;
                    }

                    if (!textExtensions.Contains(ext)) continue;

                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);

                        var contentMatchedKw = AntiDetectionKeywords.FirstOrDefault(kw =>
                            content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                        if (contentMatchedKw is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Anti-detection script content: {fileName}",
                            Risk     = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Script file '{fileName}' contains the anti-detection keyword " +
                                       $"'{contentMatchedKw}', indicating code designed to bypass " +
                                       "Roblox's Hyperion/Byfron anti-cheat by patching memory or " +
                                       "injecting into the Roblox process.",
                            Detail   = $"Path: {file} | Keyword: {contentMatchedKw}",
                        });
                    }
                    catch { }
                }
            }

            ctx.Report(0.80, "AntiDetection", "Anti-detection artifacts checked");
        }, ct);

    // =========================================================================
    // Check 17 — Python and AutoIt automation scripts for Roblox executors
    // =========================================================================
    private Task CheckPythonAutomationScripts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var pySearchRoots = new[]
            {
                Downloads,
                Desktop,
                Path.Combine(UserProfile, "Documents"),
                Path.Combine(UserProfile, "Scripts"),
                Path.Combine(UserProfile, "Python"),
            };

            var automationExtensions = new[] { ".py", ".pyw", ".au3", ".ahk" };

            foreach (var root in pySearchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;

                string[] allFiles;
                try
                {
                    allFiles = Directory.GetFiles(root, "*", SearchOption.AllDirectories);
                }
                catch { continue; }

                foreach (var file in allFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    if (!automationExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    ctx.IncrementFiles();

                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);

                        var matchedKeywords = PythonAutomationKeywords
                            .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            .Take(3)
                            .ToList();

                        if (matchedKeywords.Count < 2) continue;

                        var fileName = Path.GetFileName(file);
                        var isRobloxAutomation =
                            matchedKeywords.Any(kw =>
                                kw.Contains("roblox", StringComparison.OrdinalIgnoreCase) ||
                                kw.Contains("RobloxPlayerBeta", StringComparison.OrdinalIgnoreCase)) &&
                            matchedKeywords.Any(kw =>
                                kw.Contains("subprocess", StringComparison.OrdinalIgnoreCase) ||
                                kw.Contains("win32", StringComparison.OrdinalIgnoreCase) ||
                                kw.Contains("pyautogui", StringComparison.OrdinalIgnoreCase) ||
                                kw.Contains("inject", StringComparison.OrdinalIgnoreCase) ||
                                kw.Contains("autoit", StringComparison.OrdinalIgnoreCase));

                        var risk = isRobloxAutomation ? RiskLevel.High : RiskLevel.Medium;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Python/AutoIt Roblox automation script: {fileName}",
                            Risk     = risk,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Automation script '{fileName}' ({ext}) contains multiple " +
                                       "Roblox executor automation keywords: " +
                                       string.Join(", ", matchedKeywords.Select(k => $"'{k}'")) +
                                       ". This pattern indicates a script that automates launching " +
                                       "the executor alongside Roblox or performs click-automation.",
                            Detail   = $"Path: {file} | Keywords: {string.Join(", ", matchedKeywords)}",
                        });
                    }
                    catch { }
                }
            }

            ctx.Report(0.90, "PythonAutomation", "Python/AutoIt automation scripts checked");
        }, ct);

    // =========================================================================
    // Check 18 — Payment artifacts (receipts, screenshots) in Downloads
    // =========================================================================
    private Task CheckPaymentArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            await Task.Yield();
            var paymentSearchRoots = new[]
            {
                Downloads,
                Desktop,
                Path.Combine(UserProfile, "Documents"),
                Path.Combine(UserProfile, "Pictures"),
            };

            var textExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".txt", ".html", ".htm", ".eml", ".msg", ".pdf", ".json", ".xml", ".csv",
            };

            var imageExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".png", ".jpg", ".jpeg", ".bmp", ".webp",
            };

            foreach (var root in paymentSearchRoots)
            {
                ct.ThrowIfCancellationRequested();
                if (!Directory.Exists(root)) continue;

                string[] allFiles;
                try
                {
                    allFiles = Directory.GetFiles(root, "*", SearchOption.TopDirectoryOnly);
                }
                catch { continue; }

                foreach (var file in allFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    var fileName = Path.GetFileName(file);
                    var fileNameLower = fileName.ToLowerInvariant();
                    ctx.IncrementFiles();

                    if (imageExtensions.Contains(ext))
                    {
                        var nameMatchedKw = PaymentArtifactKeywords.FirstOrDefault(kw =>
                            fileNameLower.Contains(kw, StringComparison.OrdinalIgnoreCase));

                        if (nameMatchedKw is null) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Executor payment screenshot (filename): {fileName}",
                            Risk     = RiskLevel.Medium,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Image file '{fileName}' contains the payment/executor keyword " +
                                       $"'{nameMatchedKw}' in its filename, suggesting it may be a " +
                                       "screenshot of a receipt or transaction for an executor subscription.",
                            Detail   = $"Path: {file} | Keyword: {nameMatchedKw}",
                        });
                        continue;
                    }

                    if (!textExtensions.Contains(ext)) continue;

                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.UTF8,
                            detectEncodingFromByteOrderMarks: true);
                        content = await sr.ReadToEndAsync(ct);

                        var matchedPaymentKws = PaymentArtifactKeywords
                            .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            .Take(3)
                            .ToList();

                        if (matchedPaymentKws.Count < 2) continue;

                        bool hasExecutorRef = matchedPaymentKws.Any(kw =>
                            kw.Contains("synapse", StringComparison.OrdinalIgnoreCase) ||
                            kw.Contains("krnl", StringComparison.OrdinalIgnoreCase) ||
                            kw.Contains("sentinel", StringComparison.OrdinalIgnoreCase) ||
                            kw.Contains("scriptware", StringComparison.OrdinalIgnoreCase) ||
                            kw.Contains("fluxus", StringComparison.OrdinalIgnoreCase) ||
                            kw.Contains("jjsploit", StringComparison.OrdinalIgnoreCase) ||
                            kw.Contains("executor", StringComparison.OrdinalIgnoreCase) ||
                            kw.Contains("hydrogen", StringComparison.OrdinalIgnoreCase) ||
                            kw.Contains("wave executor", StringComparison.OrdinalIgnoreCase) ||
                            kw.Contains("oxygenu", StringComparison.OrdinalIgnoreCase));

                        if (!hasExecutorRef) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Executor payment receipt/email: {fileName}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason   = $"Document '{fileName}' contains multiple payment and executor " +
                                       "keywords: " +
                                       string.Join(", ", matchedPaymentKws.Select(k => $"'{k}'")) +
                                       ". This pattern matches a PayPal receipt, crypto transaction, " +
                                       "or email confirming purchase of a Roblox executor subscription.",
                            Detail   = $"Path: {file} | Keywords: {string.Join(", ", matchedPaymentKws)}",
                        });
                    }
                    catch { }
                }
            }

            ctx.Report(1.0, "PaymentArtifacts", "Payment artifacts checked");
        }, ct);

    // =========================================================================
    // Helper — ROT13 decode (for UserAssist registry entries)
    // =========================================================================
    private static string Rot13(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if      (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
