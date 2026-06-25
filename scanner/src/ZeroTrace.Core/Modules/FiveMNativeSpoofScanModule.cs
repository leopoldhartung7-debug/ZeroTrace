using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMNativeSpoofScanModule : IScanModule
{
    public string Name => "FiveM Native Function Spoofing Detection";
    public double Weight => 4.4;
    public int ParallelGroup => 4;

    // -----------------------------------------------------------------------
    // Known FiveM native spoofing / hooking tool names (40+ variants)
    // -----------------------------------------------------------------------
    private static readonly HashSet<string> NativeSpoofFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // Executable tools
        "fivem_native_spoof.exe",
        "native_hook.exe",
        "fivem_hook.exe",
        "native_spoof.exe",
        "native_bypass.exe",
        "fivem_bypass.exe",
        "invoke_bypass.exe",
        "citizen_bypass.exe",
        "native_table_spoof.exe",
        "ntpc_tool.exe",
        "fivem_native_hook.exe",
        "native_invoker.exe",
        "invoke_spoof.exe",
        "fivem_cheat.exe",
        "fivem_menu.exe",
        "fivem_trainer.exe",
        "fivem_injector.exe",
        "citizenfx_bypass.exe",
        "cfx_bypass.exe",
        "fivem_native_bypass.exe",
        "native_redirect.exe",
        "fivem_native_redirect.exe",
        "invoke_native_bypass.exe",
        "citizenInvokeBypass.exe",
        "nativepatch.exe",
        "fivem_exploit.exe",
        "fivem_lua_executor.exe",
        "lua_executor.exe",
        "resource_injector.exe",
        // DLL variants
        "invoke_bypass.dll",
        "native_hook.dll",
        "fivem_hook.dll",
        "native_spoof.dll",
        "fivem_native_spoof.dll",
        "citizen_hook.dll",
        "cfx_hook.dll",
        "citizenfx_hook.dll",
        "native_invoker.dll",
        "ntpc.dll",
        "native_table_patch.dll",
        "fivem_bypass.dll",
        "native_bypass.dll",
        "invoke_redirect.dll",
        "fivem_native_hook.dll",
        "native_patch.dll",
        "lua_bypass.dll",
        "fivem_lua.dll",
        "resource_hook.dll",
    };

    // Keyword patterns for file name matching (catches renamed variants)
    private static readonly string[] NativeSpoofFileKeywords =
    {
        "native_spoof", "native_hook", "fivem_hook", "invoke_bypass",
        "citizen_bypass", "cfx_bypass", "fivem_bypass", "native_bypass",
        "native_redirect", "ntpc_tool", "invoke_spoof", "fivem_native",
        "native_invoke", "native_table", "citizenfx_bypass", "citizenfx_hook",
        "fivem_exploit", "lua_executor", "resource_inject", "fivem_cheat",
        "fivem_menu", "fivem_inject",
    };

    // Known FiveM cheat menu / native spoof resource folder names (20+ names)
    private static readonly string[] SuspiciousResourceNames =
    {
        "native_spoof",
        "native_hook",
        "invoke_bypass",
        "citizen_bypass",
        "fivem_cheat",
        "fivem_menu",
        "ez_menu",
        "kiddion_fivem",
        "luna_menu",
        "lambda_menu",
        "lamda",
        "executor",
        "lua_executor",
        "native_executor",
        "cfx_bypass",
        "native_bypass",
        "resource_spoof",
        "admin_menu",
        "super_menu",
        "god_mode_resource",
        "invincible_resource",
        "money_drop",
        "freeze_all",
        "player_spoof",
        "native_table_override",
        "ntpc_resource",
        "native_db_override",
    };

    // Lua script patterns indicative of native spoofing / abuse
    private static readonly string[] LuaNativeSpoofPatterns =
    {
        // Native invocation bypass patterns
        "Citizen.InvokeNative",
        "InvokeNative",
        "invoke_native",
        "native_invoke",
        // God mode / invincibility natives
        "SetEntityInvincible",
        "SetPlayerInvincible",
        "SET_ENTITY_INVINCIBLE",
        "SET_PLAYER_INVINCIBLE",
        // Friendly fire / PvP disable
        "NetworkSetFriendlyFireOption",
        "NETWORK_SET_FRIENDLY_FIRE_OPTION",
        "SetCanAttackFriendly",
        // Explosive / griefing natives
        "AddExplosionWithUserVars",
        "AddExplosion",
        "ADD_EXPLOSION",
        "NetworkExplodeVehicle",
        // Money / stat manipulation
        "StatSetInt",
        "StatGetInt",
        "STAT_SET_INT",
        "NetworkIncrementStat",
        // Teleport
        "SetEntityCoords",
        "SET_ENTITY_COORDS",
        "TeleportToCoords",
        // Vehicle spawn / godmode
        "SetVehicleEngineOn",
        "SetVehicleUndriveable",
        // Native table bypass marker
        "NativeDB",
        "NativeTableOverride",
        "NativeMapping",
        "__natives",
        "nativeSpoof",
        "native_spoof",
        "invokeBypass",
        // Raw hash invocation (common in spoofing tools)
        "0x", // raw native hash usage (filtered with context below)
        "Citizen.InvokeNativeByHash",
        "invokeNativeByHash",
        // Session manipulation
        "NetworkSessionIsHost",
        "NetworkGetPlayerIndex",
        "NetworkKickPlayer",
        // Lua execution abuse
        "load(",
        "loadstring(",
        "dofile(",
        "pcall(load",
    };

    // JavaScript native abuse patterns (FiveM JS resources)
    private static readonly string[] JsNativeSpoofPatterns =
    {
        "natives.PLAYER.GET_PLAYER_PED",
        "natives.ENTITY.SET_ENTITY_INVINCIBLE",
        "natives.PLAYER.SET_PLAYER_INVINCIBLE",
        "natives.FIRE.ADD_EXPLOSION",
        "natives.FIRE.ADD_EXPLOSION_WITH_USER_VARS",
        "AddExplosionWithUserVars(",
        "invokeNative(",
        "Citizen.invokeNative(",
        "GetPlayerPed(",
        "SetEntityInvincible(",
        "NetworkSetFriendlyFireOption(",
        "NetworkExplodeVehicle(",
        "StatSetInt(",
        "NativeDB.",
        "nativeSpoof",
        "nativeHook",
        "nativeBypass",
        "invokeBypass",
        "native_table",
        "NativeMapping",
    };

    // Keywords to look for in FiveM config files (.cfg)
    private static readonly string[] CfgSpoofKeywords =
    {
        "native_spoof", "invoke_bypass", "native_bypass", "citizen_bypass",
        "cfx_bypass", "native_hook", "fivem_bypass", "native_redirect",
        "ntpc", "native_table", "invokebypass", "nativespoof",
        "native_db_override", "nativedboverride", "fivem_cheat",
    };

    // CitizenFX.log indicator patterns for native hook activity
    private static readonly string[] CitizenFxLogKeywords =
    {
        "native hook", "native spoof", "invoke bypass", "native bypass",
        "native redirect", "ntpc", "NativeTableOverride", "native_hook",
        "native_spoof", "citizen bypass", "cfx bypass",
        "InvokeNative hook", "native table patch", "NativeDB override",
        "hook installed", "native patched", "invoke redirected",
    };

    // NTPC (native table pointer corruption) artifact file names
    private static readonly string[] NtpcArtifactNames =
    {
        "ntpc.dat", "ntpc.bin", "ntpc.cfg", "ntpc.log",
        "native_table.dat", "native_table.bin", "native_map.dat",
        "native_mapping.dat", "native_db_override.json",
        "native_override.json", "natives_override.json",
        "native_redirect.dat", "invoke_map.dat",
        "nativedb.override", "nativedb_patch.json",
    };

    // FiveM data directories to scan
    private static readonly string[] FiveMDataRoots;
    private static readonly string[] FiveMResourceRoots;

    static FiveMNativeSpoofScanModule()
    {
        var localApp   = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roamingApp = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        FiveMDataRoots = new[]
        {
            Path.Combine(localApp, "FiveM"),
            Path.Combine(localApp, "FiveM", "FiveM.app"),
            Path.Combine(localApp, "FiveM", "FiveM.app", "data"),
            Path.Combine(localApp, "FiveM", "FiveM.app", "cache"),
            Path.Combine(roamingApp, "CitizenFX"),
        };

        FiveMResourceRoots = new[]
        {
            Path.Combine(localApp, "FiveM", "FiveM.app", "data", "resources"),
            Path.Combine(localApp, "FiveM", "FiveM.app", "data", "server-list"),
            Path.Combine(localApp, "FiveM", "resources"),
            Path.Combine(localApp, "FiveM", "FiveM.app", "resources"),
        };
    }

    // -----------------------------------------------------------------------
    // Entry point
    // -----------------------------------------------------------------------
    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting FiveM native spoofing detection...");

        return Task.WhenAll(
            CheckNativeSpoofFiles(ctx, ct),
            CheckFiveMDataDirectories(ctx, ct),
            CheckLuaScriptsForNativeSpoofing(ctx, ct),
            CheckJavaScriptFilesForNativeAbuse(ctx, ct),
            CheckSuspiciousResourceFolders(ctx, ct),
            CheckCitizenFxLog(ctx, ct),
            CheckFiveMConfigFiles(ctx, ct),
            CheckNtpcArtifactFiles(ctx, ct),
            CheckNativeMappingFiles(ctx, ct),
            CheckNativeSpoofProcesses(ctx, ct),
            CheckNativeSpoofRegistryArtifacts(ctx, ct),
            CheckFiveMCacheForSpoofArtifacts(ctx, ct)
        );
    }

    // -----------------------------------------------------------------------
    // Sub-check: known native spoof EXEs / DLLs on disk
    // -----------------------------------------------------------------------
    private Task CheckNativeSpoofFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            var searchRoots = new List<string>(FiveMDataRoots);
            searchRoots.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
            searchRoots.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"));
            searchRoots.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            searchRoots.Add(Path.GetTempPath());
            searchRoots.Add(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn  = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    bool isExeOrDll = ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                                   || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase);
                    if (!isExeOrDll) continue;

                    bool exactMatch   = NativeSpoofFileNames.Contains(fn);
                    bool keywordMatch = !exactMatch && NativeSpoofFileKeywords.Any(k =>
                        fn.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (!exactMatch && !keywordMatch) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"FiveM Native Spoof Tool: {fn}",
                        Risk     = exactMatch ? RiskLevel.Critical : RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = exactMatch
                            ? $"File '{fn}' matches a known FiveM native function spoofing or hooking tool name. " +
                              "These tools intercept FiveM's native function invoker (Citizen.InvokeNative) to " +
                              "spoof or redirect native calls, enabling god mode, explosion griefing, stat manipulation, " +
                              "and other cheat behaviors in GTA:V FiveM multiplayer."
                            : $"File '{fn}' contains a keyword pattern strongly associated with FiveM native " +
                              "spoofing tools. The name indicates this file is designed to hook or redirect " +
                              "FiveM's native function dispatch table.",
                        Detail   = $"Path: {file} | Match: {(exactMatch ? "exact name" : "keyword")} | Ext: {ext}"
                    });
                }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: FiveM data directory scan for suspicious binaries
    // -----------------------------------------------------------------------
    private Task CheckFiveMDataDirectories(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            foreach (var root in FiveMDataRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn  = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    // Flag unexpected binaries (non-Lua, non-JS, non-config) inside FiveM data
                    bool isBinary = ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                                 || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)
                                 || ext.Equals(".sys", StringComparison.OrdinalIgnoreCase);
                    if (!isBinary) continue;

                    // Filter: only flag if name suggests spoof/hack
                    bool keywordMatch = NativeSpoofFileKeywords.Any(k =>
                        fn.Contains(k, StringComparison.OrdinalIgnoreCase))
                        || NativeSpoofFileNames.Contains(fn);

                    if (!keywordMatch) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Native Spoof Binary in FiveM Data Dir: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"A binary file '{fn}' with native spoofing tool naming was found inside the " +
                                   $"FiveM data directory at '{root}'. Binaries inside the FiveM data tree that " +
                                   "match native spoofing patterns are strong indicators of a cheat tool that " +
                                   "integrates directly with the FiveM client data structure.",
                        Detail   = $"Path: {file} | Root: {root}"
                    });
                }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: scan *.lua files for native spoofing / hook patterns
    // -----------------------------------------------------------------------
    private Task CheckLuaScriptsForNativeSpoofing(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            // Build list of Lua search roots: FiveM resources + data dirs
            var luaRoots = new List<string>(FiveMDataRoots);
            luaRoots.AddRange(FiveMResourceRoots);

            foreach (var root in luaRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, "*.lua", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

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
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    var fn = Path.GetFileName(file);

                    // Check each pattern — stop at first definitive hit per file
                    foreach (var pattern in LuaNativeSpoofPatterns)
                    {
                        // Skip trivially short patterns that would cause too many FPs
                        // (the "0x" raw hash pattern needs context of being a native hash)
                        if (pattern.Equals("0x", StringComparison.Ordinal))
                        {
                            // Only flag if "InvokeNative" appears in same file with raw hash
                            bool hasInvoke = content.Contains("InvokeNative", StringComparison.OrdinalIgnoreCase)
                                          || content.Contains("Citizen.Invoke", StringComparison.OrdinalIgnoreCase);
                            // Count occurrences of 0x for native hash density
                            int hashCount = CountOccurrences(content, "0x");
                            if (!hasInvoke || hashCount < 5) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Lua: Native Hash Invocation Pattern: {fn}",
                                Risk     = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason   = $"Lua script '{fn}' contains {hashCount} raw native hash values (0x...) " +
                                           "combined with native invocation calls (InvokeNative/Citizen.Invoke). " +
                                           "This pattern is characteristic of native spoofing scripts that call " +
                                           "GTA:V native functions directly by hash to bypass FiveM API restrictions.",
                                Detail   = $"File: {file} | Raw hash count: {hashCount}"
                            });
                            break;
                        }

                        if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                        var risk = pattern switch
                        {
                            var p when p.Contains("InvokeNative", StringComparison.OrdinalIgnoreCase)      => RiskLevel.Critical,
                            var p when p.Contains("Invincible", StringComparison.OrdinalIgnoreCase)         => RiskLevel.High,
                            var p when p.Contains("FriendlyFire", StringComparison.OrdinalIgnoreCase)       => RiskLevel.High,
                            var p when p.Contains("AddExplosion", StringComparison.OrdinalIgnoreCase)       => RiskLevel.High,
                            var p when p.Contains("NativeDB", StringComparison.OrdinalIgnoreCase)           => RiskLevel.Critical,
                            var p when p.Contains("nativeSpoof", StringComparison.OrdinalIgnoreCase)        => RiskLevel.Critical,
                            var p when p.Contains("invokeBypass", StringComparison.OrdinalIgnoreCase)       => RiskLevel.Critical,
                            var p when p.Contains("loadstring", StringComparison.OrdinalIgnoreCase)         => RiskLevel.High,
                            var p when p.Contains("KickPlayer", StringComparison.OrdinalIgnoreCase)         => RiskLevel.High,
                            _                                                                                 => RiskLevel.Medium,
                        };

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Lua Native Spoof Pattern: {fn}",
                            Risk     = risk,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Lua script '{fn}' contains the pattern '{pattern}' which is associated " +
                                       "with FiveM native function spoofing, abuse of GTA:V native functions, or " +
                                       "cheat resource behavior. FiveM native spoofing scripts use patterns like " +
                                       "Citizen.InvokeNative, SetEntityInvincible, AddExplosion, and raw hash " +
                                       "invocations to perform privileged game actions beyond what legitimate scripts use.",
                            Detail   = $"File: {file} | Pattern: '{pattern}'"
                        });
                        break;
                    }
                }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: scan *.js files for native abuse patterns
    // -----------------------------------------------------------------------
    private Task CheckJavaScriptFilesForNativeAbuse(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            var jsRoots = new List<string>(FiveMDataRoots);
            jsRoots.AddRange(FiveMResourceRoots);

            foreach (var root in jsRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, "*.js", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

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
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    var fn = Path.GetFileName(file);

                    var hitPattern = JsNativeSpoofPatterns.FirstOrDefault(p =>
                        content.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (hitPattern is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"JS Native Abuse Pattern: {fn}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = $"JavaScript resource file '{fn}' contains the native abuse pattern '{hitPattern}'. " +
                                   "FiveM JavaScript resources with direct GTA:V native API calls beyond the sanctioned " +
                                   "FiveM API are characteristic of cheat resources that abuse native functions " +
                                   "(explosion spawning, invincibility, stat manipulation, etc.)",
                        Detail   = $"File: {file} | Pattern: '{hitPattern}'"
                    });
                }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: suspicious resource folder names matching known spoof tools
    // -----------------------------------------------------------------------
    private Task CheckSuspiciousResourceFolders(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            foreach (var resourceRoot in FiveMResourceRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(resourceRoot)) continue;

                IEnumerable<string> dirs;
                try
                {
                    dirs = Directory.EnumerateDirectories(resourceRoot, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var dir in dirs)
                {
                    if (ct.IsCancellationRequested) return;
                    var dirName = Path.GetFileName(dir);

                    bool exactMatch = SuspiciousResourceNames.Any(s =>
                        dirName.Equals(s, StringComparison.OrdinalIgnoreCase));
                    bool keywordMatch = !exactMatch && NativeSpoofFileKeywords.Any(k =>
                        dirName.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (!exactMatch && !keywordMatch) continue;

                    int fileCount = 0;
                    try { fileCount = Directory.GetFiles(dir, "*", SearchOption.AllDirectories).Length; }
                    catch (UnauthorizedAccessException) { }
                    catch (IOException) { }

                    // Check for fxmanifest.lua or __resource.lua to confirm it is a FiveM resource
                    bool hasManifest = File.Exists(Path.Combine(dir, "fxmanifest.lua"))
                                    || File.Exists(Path.Combine(dir, "__resource.lua"));

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Suspicious FiveM Resource Folder: {dirName}",
                        Risk     = exactMatch ? RiskLevel.Critical : RiskLevel.High,
                        Location = dir,
                        FileName = dirName,
                        Reason   = $"FiveM resource folder '{dirName}' in '{resourceRoot}' matches a known " +
                                   "native spoofing or cheat menu resource name pattern. " +
                                   (hasManifest
                                       ? "A FiveM resource manifest (fxmanifest.lua or __resource.lua) is present, " +
                                         "confirming this is an active FiveM resource. "
                                       : "") +
                                   "Cheat resources for FiveM are typically delivered as game resources that hook " +
                                   "native functions, grant invincibility, spawn explosions, or manipulate game state. " +
                                   $"The folder contains {fileCount} file(s).",
                        Detail   = $"Dir: {dir} | Files: {fileCount} | HasManifest: {hasManifest} | " +
                                   $"Match: {(exactMatch ? "exact name" : "keyword")}"
                    });
                }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: CitizenFX.log scan for native hook indicators
    // -----------------------------------------------------------------------
    private Task CheckCitizenFxLog(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            var roamingApp = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var logPaths = new[]
            {
                Path.Combine(roamingApp, "CitizenFX", "CitizenFX.log"),
                Path.Combine(roamingApp, "CitizenFX", "CitizenFX.log.1"),
                Path.Combine(roamingApp, "CitizenFX", "CitizenFX.log.2"),
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "FiveM", "FiveM.app", "logs", "CitizenFX.log"),
            };

            foreach (var logPath in logPaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!File.Exists(logPath)) continue;

                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                var fn = Path.GetFileName(logPath);

                foreach (var keyword in CitizenFxLogKeywords)
                {
                    if (!content.Contains(keyword, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"CitizenFX Log: Native Hook Activity: {keyword}",
                        Risk     = RiskLevel.High,
                        Location = logPath,
                        FileName = fn,
                        Reason   = $"The FiveM CitizenFX log file '{fn}' contains the indicator '{keyword}' " +
                                   "which is associated with native function hook or spoof activity. " +
                                   "FiveM cheat tools may log their own activity or produce diagnostic output " +
                                   "that leaves forensic traces in the CitizenFX log file even after the cheat " +
                                   "tool itself has been removed.",
                        Detail   = $"Log: {logPath} | Keyword: '{keyword}'"
                    });
                    break; // One finding per log file
                }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: FiveM config files (.cfg) with native spoofing keywords
    // -----------------------------------------------------------------------
    private Task CheckFiveMConfigFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            var cfgRoots = new List<string>(FiveMDataRoots);
            cfgRoots.AddRange(FiveMResourceRoots);

            foreach (var root in cfgRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, "*.cfg", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

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
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    var fn = Path.GetFileName(file);
                    var hitKeyword = CfgSpoofKeywords.FirstOrDefault(k =>
                        content.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (hitKeyword is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"FiveM Config: Native Spoof Keyword: {fn}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = $"FiveM config file '{fn}' contains the keyword '{hitKeyword}' associated " +
                                   "with native function spoofing configuration. Cheat tools for FiveM sometimes " +
                                   "modify or create .cfg files to configure their native hook targets, bypass " +
                                   "settings, or load cheat resources automatically on server connection.",
                        Detail   = $"File: {file} | Keyword: '{hitKeyword}'"
                    });
                }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: NTPC (native table pointer corruption) artifact files
    // -----------------------------------------------------------------------
    private Task CheckNtpcArtifactFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            var searchRoots = new List<string>(FiveMDataRoots);
            searchRoots.AddRange(FiveMResourceRoots);
            searchRoots.Add(Path.GetTempPath());
            searchRoots.Add(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file);
                    bool isNtpcArtifact = NtpcArtifactNames.Any(n =>
                        fn.Equals(n, StringComparison.OrdinalIgnoreCase));

                    if (!isNtpcArtifact)
                    {
                        // Also check for keyword patterns in name
                        bool keywordMatch = new[] { "ntpc", "native_table", "native_map", "native_db_override",
                                                    "native_redirect", "invoke_map", "native_override" }
                            .Any(k => fn.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (!keywordMatch) continue;
                    }

                    // Read a snippet to describe the content
                    string snippet = "";
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        char[] buf = new char[256];
                        int read = await sr.ReadAsync(buf, ct);
                        snippet = new string(buf, 0, read).Trim();
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"NTPC Artifact File: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"File '{fn}' matches a known NTPC (Native Table Pointer Corruption) artifact " +
                                   "name pattern. NTPC is a technique used by FiveM cheat tools to corrupt the " +
                                   "GTA:V native function dispatch table, redirecting native calls to custom handlers " +
                                   "that bypass anti-cheat validation and enable cheating. The presence of this file " +
                                   "is a strong indicator of active native spoofing infrastructure.",
                        Detail   = $"Path: {file} | Preview: {snippet[..Math.Min(100, snippet.Length)]}"
                    });
                }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: abnormal native mapping / NativeDB override files
    // -----------------------------------------------------------------------
    private Task CheckNativeMappingFiles(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            // NativeDB override files are JSON files that redefine native hash mappings
            var nativeMappingKeywords = new[]
            {
                "native_mapping", "natives_mapping", "native_db", "nativedb",
                "native_override", "natives_override", "native_redirect",
                "native_alias", "native_hash_map", "invoke_map",
            };

            var searchRoots = new List<string>(FiveMDataRoots);
            searchRoots.AddRange(FiveMResourceRoots);

            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(root, "*.json", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(file);
                    bool nameMatch = nativeMappingKeywords.Any(k =>
                        fn.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (!nameMatch) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    // Confirm it looks like a native mapping by checking for hash patterns
                    bool hasHashes = content.Contains("0x", StringComparison.OrdinalIgnoreCase)
                                  && CountOccurrences(content, "0x") > 3;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"NativeDB Override/Mapping File: {fn}",
                        Risk     = RiskLevel.Critical,
                        Location = file,
                        FileName = fn,
                        Reason   = $"JSON file '{fn}' matches a NativeDB override or native mapping file name pattern. " +
                                   "FiveM native spoofing tools use custom native mapping files to remap GTA:V native " +
                                   "function hashes, either to redirect native calls to custom implementations or to " +
                                   "confuse anti-cheat systems that validate the native dispatch table. " +
                                   (hasHashes ? "The file contains native hash values (0x...) confirming this is a native map." : ""),
                        Detail   = $"Path: {file} | HashesPresent: {hasHashes}"
                    });
                }
            }

            // Also check for native mapping in .lua and .dat files
            foreach (var root in searchRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(root)) continue;

                foreach (var ext in new[] { "*.dat", "*.bin" })
                {
                    IEnumerable<string> dataFiles;
                    try
                    {
                        dataFiles = Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in dataFiles)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        var fn = Path.GetFileName(file);
                        bool nameMatch = nativeMappingKeywords.Any(k =>
                            fn.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (!nameMatch) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Native Mapping Data File: {fn}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason   = $"Data file '{fn}' matches a native mapping artifact name pattern. " +
                                       "Binary native mapping files are used by FiveM cheat loaders to store " +
                                       "pre-computed native hash remapping tables for faster spoofing at runtime.",
                            Detail   = $"Path: {file}"
                        });
                    }
                }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: running processes matching native spoof tool names
    // -----------------------------------------------------------------------
    private Task CheckNativeSpoofProcesses(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            try
            {
                foreach (var proc in ctx.GetProcessSnapshot())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementProcesses();

                    string procName;
                    try { procName = proc.ProcessName; }
                    catch { continue; }

                    bool exactMatch   = NativeSpoofFileNames.Contains(procName + ".exe");
                    bool keywordMatch = !exactMatch && NativeSpoofFileKeywords.Any(k =>
                        procName.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (!exactMatch && !keywordMatch) continue;

                    string? exePath = null;
                    try { exePath = proc.MainModule?.FileName; }
                    catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Native Spoof Process Running: {procName}",
                        Risk     = RiskLevel.Critical,
                        Location = $"PID {proc.Id}",
                        FileName = procName + ".exe",
                        Reason   = $"A process named '{procName}' (PID {proc.Id}) is currently running and matches " +
                                   "a known FiveM native spoofing or hooking tool name. This process may be actively " +
                                   "intercepting and redirecting FiveM native function calls, enabling god mode, " +
                                   "explosion abuse, stat hacking, or other cheat behaviors in real time.",
                        Detail   = $"PID: {proc.Id} | Name: {procName} | Path: {exePath ?? "unknown"}"
                    });
                }
            }
            catch { }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: registry artifacts left by native spoof tools
    // -----------------------------------------------------------------------
    private Task CheckNativeSpoofRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            var registryKeywords = new[]
            {
                "native_spoof", "native_hook", "fivem_hook", "invoke_bypass",
                "citizen_bypass", "cfx_bypass", "fivem_bypass", "native_bypass",
                "native_redirect", "ntpc", "fivem_cheat", "fivem_menu",
                "native_invoke", "invoke_redirect", "fivem_native",
            };

            // Scan HKLM and HKCU SOFTWARE for native spoof tool key names
            foreach (var (hive, hiveLabel) in new[] {
                (Registry.LocalMachine, "HKLM"),
                (Registry.CurrentUser,  "HKCU") })
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    using var softwareKey = hive.OpenSubKey(@"SOFTWARE", writable: false);
                    if (softwareKey is null) continue;

                    foreach (var sub in softwareKey.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        bool match = registryKeywords.Any(k =>
                            sub.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (!match) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Native Spoof Registry Key ({hiveLabel}): {sub}",
                            Risk     = RiskLevel.High,
                            Location = $@"{hiveLabel}\SOFTWARE\{sub}",
                            Reason   = $"Registry key '{hiveLabel}\\SOFTWARE\\{sub}' contains a keyword associated " +
                                       "with FiveM native function spoofing tools. This key may be an installation " +
                                       "remnant or configuration store for a native hook or bypass tool.",
                            Detail   = $"Hive: {hiveLabel} | Key: SOFTWARE\\{sub}"
                        });
                    }
                }
                catch { }
            }

            // Check MUICache for native spoof tool execution history
            const string muiCacheKey =
                @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
            try
            {
                using var muiKey = Registry.CurrentUser.OpenSubKey(muiCacheKey, writable: false);
                if (muiKey is not null)
                {
                    foreach (var valueName in muiKey.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        var path = valueName;
                        var dotIdx = valueName.LastIndexOf('.');
                        if (dotIdx > 0 && !valueName[dotIdx..].Contains('\\'))
                            path = valueName[..dotIdx];

                        var friendlyName = muiKey.GetValue(valueName) as string ?? "";
                        var combined     = (path + " " + friendlyName).ToLowerInvariant();

                        bool match = registryKeywords.Any(k =>
                            combined.Contains(k, StringComparison.OrdinalIgnoreCase))
                            || NativeSpoofFileNames.Contains(Path.GetFileName(path));

                        if (!match) continue;

                        var fn     = Path.GetFileName(path);
                        bool exists = File.Exists(path);

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"MUICache: FiveM Native Spoof Tool Executed: {fn}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKCU\{muiCacheKey}",
                            FileName = fn,
                            Reason   = $"MUICache records that '{fn}' was executed on this system and the name " +
                                       "matches a FiveM native spoofing tool. " +
                                       (exists
                                           ? "The file is still present on disk."
                                           : "The file has been deleted, but its execution is forensically confirmed."),
                            Detail   = $"Path: {path} | Description: {friendlyName} | Exists: {exists}"
                        });
                    }
                }
            }
            catch { }

            // Check UserAssist for native spoof execution
            const string userAssistBase =
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
            try
            {
                using var uaBase = Registry.CurrentUser.OpenSubKey(userAssistBase, writable: false);
                if (uaBase is not null)
                {
                    foreach (var guidName in uaBase.GetSubKeyNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        try
                        {
                            using var countKey = uaBase.OpenSubKey($@"{guidName}\Count", writable: false);
                            if (countKey is null) continue;

                            foreach (var encodedName in countKey.GetValueNames())
                            {
                                if (ct.IsCancellationRequested) return;
                                ctx.IncrementRegistryKeys();

                                var decoded = Rot13(encodedName);
                                bool match  = registryKeywords.Any(k =>
                                    decoded.Contains(k, StringComparison.OrdinalIgnoreCase))
                                    || NativeSpoofFileNames.Contains(Path.GetFileName(decoded));

                                if (!match) continue;

                                int runCount = 0;
                                DateTime? lastRun = null;
                                try
                                {
                                    var data = countKey.GetValue(encodedName) as byte[];
                                    if (data is { Length: >= 16 })
                                    {
                                        runCount = BitConverter.ToInt32(data, 4);
                                        long ft  = BitConverter.ToInt64(data, 8);
                                        if (ft > 0) lastRun = DateTime.FromFileTimeUtc(ft);
                                    }
                                }
                                catch { }

                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"UserAssist: FiveM Native Spoof Tool: {Path.GetFileName(decoded)}",
                                    Risk     = RiskLevel.Critical,
                                    Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                    FileName = Path.GetFileName(decoded),
                                    Reason   = $"UserAssist records (ROT13-decoded) show execution of " +
                                               $"'{Path.GetFileName(decoded)}', a FiveM native spoofing tool. " +
                                               $"Executed {runCount} time(s)" +
                                               (lastRun.HasValue ? $", last {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                               ". These records persist after the file is deleted.",
                                    Detail   = $"Decoded: {decoded} | Runs: {runCount} | " +
                                               $"Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}"
                                });
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Sub-check: FiveM cache directory for spoof/injection artifacts
    // -----------------------------------------------------------------------
    private Task CheckFiveMCacheForSpoofArtifacts(ScanContext ctx, CancellationToken ct)
    {
        return Task.Run(async () =>
        {
            await Task.Yield();

            var localApp   = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var cachePaths = new[]
            {
                Path.Combine(localApp, "FiveM", "FiveM.app", "cache"),
                Path.Combine(localApp, "FiveM", "FiveM.app", "cache", "game"),
                Path.Combine(localApp, "FiveM", "FiveM.app", "data", "cache"),
                Path.Combine(localApp, "FiveM", "FiveM.app", "citizen", "scripting"),
            };

            foreach (var cacheRoot in cachePaths)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(cacheRoot)) continue;

                // Scan for suspicious DLLs or scripts cached by cheat tools
                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(cacheRoot, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn  = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    // Unexpected DLLs in the scripting cache
                    bool isDll = ext.Equals(".dll", StringComparison.OrdinalIgnoreCase);
                    if (isDll)
                    {
                        bool match = NativeSpoofFileKeywords.Any(k =>
                            fn.Contains(k, StringComparison.OrdinalIgnoreCase))
                            || NativeSpoofFileNames.Contains(fn);

                        if (match)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"Native Spoof DLL in FiveM Cache: {fn}",
                                Risk     = RiskLevel.Critical,
                                Location = file,
                                FileName = fn,
                                Reason   = $"A DLL file '{fn}' matching native spoofing tool keywords was found in " +
                                           $"the FiveM cache directory at '{cacheRoot}'. Cheat tools can drop their " +
                                           "hook DLLs into the FiveM cache to ensure they are loaded alongside " +
                                           "FiveM's own scripting runtime components.",
                                Detail   = $"Path: {file} | Cache root: {cacheRoot}"
                            });
                        }
                        continue;
                    }

                    // Lua scripts in cache with spoof patterns
                    bool isLua = ext.Equals(".lua", StringComparison.OrdinalIgnoreCase);
                    if (!isLua) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    var hitPattern = LuaNativeSpoofPatterns
                        .Where(p => !p.Equals("0x", StringComparison.Ordinal))
                        .FirstOrDefault(p => content.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (hitPattern is null) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Native Spoof Lua in FiveM Cache: {fn}",
                        Risk     = RiskLevel.High,
                        Location = file,
                        FileName = fn,
                        Reason   = $"Cached Lua script '{fn}' in the FiveM cache directory contains the native " +
                                   $"spoofing pattern '{hitPattern}'. Scripts stored in the FiveM cache are loaded " +
                                   "by the scripting runtime. A cheat tool may inject Lua scripts into the cache " +
                                   "to execute native spoof code when FiveM starts without requiring a visible resource.",
                        Detail   = $"File: {file} | Pattern: '{hitPattern}'"
                    });
                }
            }

            // Additionally check for fxmanifest.lua or __resource.lua with suspicious content
            // in any FiveM data subdirectory
            foreach (var dataRoot in FiveMDataRoots)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(dataRoot)) continue;

                foreach (var manifestName in new[] { "fxmanifest.lua", "__resource.lua" })
                {
                    IEnumerable<string> manifests;
                    try
                    {
                        manifests = Directory.EnumerateFiles(
                            dataRoot, manifestName, SearchOption.AllDirectories);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var manifest in manifests)
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementFiles();

                        string content;
                        try
                        {
                            using var fs = new FileStream(manifest, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }
                        catch (UnauthorizedAccessException) { continue; }

                        // Look for suspicious resource script entries or cheat keywords in manifest
                        var suspiciousManifestKeywords = new[]
                        {
                            "native_spoof", "invoke_bypass", "native_hook", "cfx_bypass",
                            "fivem_cheat", "god_mode", "invincible", "money_drop",
                            "explosion", "ntpc", "native_table",
                        };

                        var hit = suspiciousManifestKeywords.FirstOrDefault(k =>
                            content.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hit is null) continue;

                        var fn      = Path.GetFileName(manifest);
                        var dirName = Path.GetDirectoryName(manifest) ?? "";

                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Suspicious FiveM Resource Manifest: {fn} in {Path.GetFileName(dirName)}",
                            Risk     = RiskLevel.Critical,
                            Location = manifest,
                            FileName = fn,
                            Reason   = $"FiveM resource manifest '{fn}' in resource '{Path.GetFileName(dirName)}' " +
                                       $"contains the suspicious keyword '{hit}'. Resource manifests define what " +
                                       "scripts are loaded for a FiveM resource. A manifest referencing native spoof, " +
                                       "god mode, explosion, or bypass scripts indicates a cheat resource that is " +
                                       "configured to load anti-detection or cheating functionality.",
                            Detail   = $"Manifest: {manifest} | Keyword: '{hit}' | Resource: {Path.GetFileName(dirName)}"
                        });
                    }
                }
            }
        }, ct);
    }

    // -----------------------------------------------------------------------
    // Helper: ROT13 decode (for UserAssist registry entries)
    // -----------------------------------------------------------------------
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

    // -----------------------------------------------------------------------
    // Helper: count non-overlapping occurrences of a substring
    // -----------------------------------------------------------------------
    private static int CountOccurrences(string haystack, string needle)
    {
        if (string.IsNullOrEmpty(needle)) return 0;
        int count = 0;
        int idx   = 0;
        while ((idx = haystack.IndexOf(needle, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            count++;
            idx += needle.Length;
        }
        return count;
    }
}
