using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class AltVObjectSpawnAbuseScanModule : IScanModule
{
    public string Name => "alt:V Object Spawn Abuse Forensic Scan";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    private static readonly string AppData =
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string LocalAppData =
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string Desktop =
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static readonly string UserProfile =
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static readonly string TempDir =
        Path.Combine(LocalAppData, "Temp");

    private static readonly string[] AltVRoots =
    [
        Path.Combine(AppData, "altv"),
        Path.Combine(LocalAppData, "altv"),
        Path.Combine(AppData, "alt-v"),
        Path.Combine(LocalAppData, "alt-v"),
        Path.Combine(UserProfile, "altv"),
        Path.Combine(UserProfile, "alt-v"),
    ];

    private static readonly string[] KnownSpawnAbuseExecutables =
    [
        "ObjectSpammer.exe",
        "PropFlooder.exe",
        "EntitySpammer.exe",
        "AltVCrasher.exe",
        "objectspammer.exe",
        "propflooder.exe",
        "entityspammer.exe",
        "altvcrasher.exe",
        "ObjectFlooder.exe",
        "objectflooder.exe",
        "CrashSpawner.exe",
        "crashspawner.exe",
        "SpawnAbuser.exe",
        "spawnabuser.exe",
        "EntityFlooder.exe",
        "entityflooder.exe",
        "PropSpammer.exe",
        "propspammer.exe",
        "ObjectCrasher.exe",
        "objectcrasher.exe",
        "PropCrasher.exe",
        "propcrasher.exe",
        "SpawnCrasher.exe",
        "spawncrasher.exe",
        "ObjectSpam.exe",
        "objectspam.exe",
        "EntitySpam.exe",
        "entityspam.exe",
        "PropSpam.exe",
        "propspam.exe",
        "altv_object_spam.exe",
        "altv_prop_flood.exe",
        "altv_entity_spam.exe",
        "altv_spawn_abuse.exe",
        "altv_crash_spawn.exe",
        "altv_object_flood.exe",
        "altv_entity_flood.exe",
    ];

    private static readonly string[] KnownSpawnAbuseScriptNames =
    [
        "objectSpam.js",
        "propSpam.lua",
        "spawnAbuse.js",
        "spawnAbuse.lua",
        "objectFlooder.js",
        "objectFlooder.lua",
        "crashSpawner.js",
        "crashSpawner.lua",
        "entitySpam.js",
        "entitySpam.lua",
        "entitySpammer.js",
        "entitySpammer.lua",
        "objectSpammer.js",
        "objectSpammer.lua",
        "propFlooder.js",
        "propFlooder.lua",
        "spawnAbuser.js",
        "spawnAbuser.lua",
        "entityFlooder.js",
        "entityFlooder.lua",
        "propSpammer.js",
        "propSpammer.lua",
        "objectCrasher.js",
        "objectCrasher.lua",
        "propCrasher.js",
        "propCrasher.lua",
        "spawnCrasher.js",
        "spawnCrasher.lua",
        "crashViaSpawn.js",
        "crashViaSpawn.lua",
        "serverCrashSpawn.js",
        "serverCrashSpawn.lua",
        "objectSpam_v2.js",
        "entitySpam_v2.js",
        "propFlood.js",
        "propFlood.lua",
    ];

    private static readonly string[] SpawnAbuseScriptKeywordPatterns =
    [
        "objectSpam",
        "propSpam",
        "spawnAbuse",
        "objectFlooder",
        "crashSpawner",
        "entitySpam",
        "entitySpammer",
        "propFlooder",
        "spamObject",
        "floodEntities",
        "crashServer spawn",
        "spawn crash",
        "spawnCrasher",
        "objectCrasher",
        "propCrasher",
        "entityFlooder",
        "objectFlood",
        "entityFlood",
        "spawnAbuser",
    ];

    private static readonly string[] JsSpawnAbuseCodePatterns =
    [
        "createObject",
        "setObjectCoords",
        "spamObject",
        "floodEntities",
        "crashServer",
        "alt.emit('spawnAbuse'",
        "alt.emit(\"spawnAbuse\"",
        "alt.emit('objectSpam'",
        "alt.emit(\"objectSpam\"",
        "alt.emit('entitySpam'",
        "alt.emit(\"entitySpam\"",
        "spawnAbuse",
        "objectSpam",
        "entitySpam",
        "propSpam",
        "propFlood",
        "objectFlood",
        "entityFlood",
        "spawnCrash",
        "crashViaSpawn",
        "for.*createObject",
        "while.*createObject",
        "setInterval.*createObject",
        "createObjectNoOffset",
        "createVehicle.*flood",
    ];

    private static readonly string[] LuaSpawnAbuseCodePatterns =
    [
        "CreateObject",
        "SetObjectCoords",
        "spamObject",
        "floodEntities",
        "crashServer",
        "spawnAbuse",
        "objectSpam",
        "entitySpam",
        "propSpam",
        "propFlood",
        "objectFlood",
        "entityFlood",
        "spawnCrash",
        "crashViaSpawn",
        "CreateModelSwap",
        "CreatePed.*while",
        "CreateVehicle.*for",
        "CreateObject.*while",
        "CreateObject.*for",
        "RequestModel.*spam",
        "HasModelLoaded.*flood",
    ];

    private static readonly string[] LogFileSpawnAbusePatterns =
    [
        "object spawn",
        "prop flood",
        "entity spam",
        "spawn abuse",
        "crash via object",
        "server crash spawn",
        "object spam",
        "entity flood",
        "object flood",
        "prop spam",
        "spawn crash",
        "crash spawn",
        "object crasher",
        "prop crasher",
        "entity crasher",
        "spawner abuse",
        "server overload spawn",
        "object rate limit",
        "entity rate limit",
        "spawn rate limit",
        "prop rate limit",
        "ban for object spam",
        "kick for spawn abuse",
        "detected spawn abuse",
        "object flood detected",
        "entity flood detected",
    ];

    private static readonly string[] DiscordSpawnAbuseKeywords =
    [
        "altv object spam",
        "prop flood",
        "entity spammer altv",
        "spawn crash",
        "object spammer",
        "altv spawn abuse",
        "entity spam altv",
        "prop flooder",
        "object flood altv",
        "crash via object",
        "crashspawner",
        "objectflooder",
        "entityflooder",
        "spawnabuse",
        "altv crash spawn",
        "server crash object",
        "spawn griefing",
        "prop griefing",
        "entity griefing",
    ];

    private static readonly string[] SpawnAbuseFileSuffixPatterns =
    [
        "objectSpam",
        "propSpam",
        "spawnAbuse",
        "objectFlooder",
        "crashSpawner",
        "entitySpam",
        "spawnAbuser",
        "entityFlooder",
        "propFlooder",
        "objectCrasher",
        "propCrasher",
        "spawnCrasher",
        "entityCrasher",
        "objectFlood",
        "entityFlood",
        "propFlood",
        "spawnCrash",
        "crashSpawn",
    ];

    private static readonly string[] SpawnAbuseResourceFolderNames =
    [
        "object-spam",
        "objectspam",
        "prop-flood",
        "propflood",
        "entity-spam",
        "entityspam",
        "spawn-abuse",
        "spawnabuse",
        "crash-spawner",
        "crashspawner",
        "object-flooder",
        "objectflooder",
        "entity-flooder",
        "entityflooder",
        "prop-spammer",
        "propspammer",
        "object-crasher",
        "objectcrasher",
        "prop-crasher",
        "propcrasher",
        "spawn-crasher",
        "spawncrasher",
        "entity-crasher",
        "entitycrasher",
        "spawn-crash",
        "spawncrash",
        "crash-spawn",
        "crashspawn",
        "altv-object-spam",
        "altv-prop-flood",
        "altv-entity-spam",
        "altv-spawn-abuse",
        "server-crash-spawn",
    ];

    private static readonly string[] PrefetchSpawnAbuseKeywords =
    [
        "OBJECTSPAMMER",
        "PROPFLOODER",
        "ENTITYSPAMMER",
        "ALTVCRASHER",
        "OBJECTFLOODER",
        "CRASHSPAWNER",
        "SPAWNABUSE",
        "ENTITYFLOODER",
        "PROPSPAMMER",
        "OBJECTCRASHER",
        "PROPCRASHER",
        "SPAWNCRASHER",
    ];

    private static readonly string[] UserAssistSpawnAbuseKeywords =
    [
        "objectspammer",
        "propflooder",
        "entityspammer",
        "altvcrasher",
        "objectflooder",
        "crashspawner",
        "spawnabuse",
        "spawnabuser",
        "entityflooder",
        "propspammer",
        "objectcrasher",
        "propcrasher",
        "spawncrasher",
        "entitycrasher",
        "object spam",
        "prop flood",
        "entity spam",
        "spawn crash",
    ];

    private static readonly string[] CefSpawnAbuseKeywords =
    [
        "object spam",
        "prop flood",
        "entity spam",
        "spawn abuse",
        "objectspammer",
        "propflooder",
        "entityspammer",
        "altvcrasher",
        "objectflooder",
        "crashspawner",
        "spawnabuse",
        "crash via object",
        "spawn crash altv",
        "altv object flood",
        "altv entity spam",
    ];

    private static readonly string[] AltVResourceSubDirs =
    [
        "resources",
        "client_packages",
        "plugins",
        "mods",
        "scripts",
        "addons",
        "packages",
        "data",
        "cache",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckKnownSpawnAbuseExecutables(ctx, ct),
            CheckAltVDirectoriesForSpawnAbuseScripts(ctx, ct),
            CheckResourceDirsForSpawnAbuseResources(ctx, ct),
            CheckJavaScriptFilesForSpawnAbusePatterns(ctx, ct),
            CheckLuaFilesForSpawnAbusePatterns(ctx, ct),
            CheckLogFilesForSpawnAbuseKeywords(ctx, ct),
            CheckRegistryForSpawnAbuseArtifacts(ctx, ct),
            CheckUserAssistForSpawnAbuseExecutables(ctx, ct),
            CheckTempAndAppDataForSpawnAbuseArtifacts(ctx, ct),
            CheckDiscordCacheForSpawnAbuseKeywords(ctx, ct),
            CheckCefCacheForSpawnAbuseKeywords(ctx, ct),
            CheckPrefetchForSpawnAbuseExecutables(ctx, ct)
        );

        ctx.Report(1.0, Name, "alt:V object spawn abuse forensic scan complete");
    }

    private Task CheckKnownSpawnAbuseExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>(AltVRoots)
        {
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            TempDir,
            AppData,
            LocalAppData,
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    if (KnownSpawnAbuseExecutables.Any(k =>
                            fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Known alt:V object spawn abuse executable: {fn}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fn,
                            Reason = $"Known alt:V object/prop spawn abuse tool executable '{fn}' found on disk. " +
                                     "These tools spawn excessive objects, props, or entities to grief or crash alt:V servers. " +
                                     "Presence of this file is a strong indicator of spawn-abuse activity.",
                            Detail = $"Full path: {file}",
                        });
                        continue;
                    }

                    foreach (var keyword in SpawnAbuseFileSuffixPatterns)
                    {
                        if (fn.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious spawn-abuse executable name: {fn}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = fn,
                                Reason = $"Executable '{fn}' contains spawn-abuse keyword '{keyword}'. " +
                                         "This naming pattern is associated with alt:V object spam or prop flooding tools.",
                                Detail = $"Matched keyword: {keyword} | Path: {file}",
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckAltVDirectoriesForSpawnAbuseScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var root in AltVRoots)
        {
            if (!Directory.Exists(root)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    foreach (var scriptName in KnownSpawnAbuseScriptNames)
                    {
                        if (fn.Equals(scriptName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Known spawn-abuse script in alt:V directory: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Known object/prop spawn-abuse script '{fn}' found inside alt:V data directory '{root}'. " +
                                         "These scripts automate massive object or entity spawning to crash or grief alt:V servers.",
                                Detail = $"Script path: {file}",
                            });
                            break;
                        }
                    }

                    if (ext.Equals(".js", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".lua", StringComparison.OrdinalIgnoreCase) ||
                        ext.Equals(".ts", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (var keyword in SpawnAbuseScriptKeywordPatterns)
                        {
                            if (fn.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Spawn-abuse script name in alt:V dir: {fn}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = fn,
                                    Reason = $"Script file '{fn}' in alt:V directory contains spawn-abuse keyword '{keyword}' in its name. " +
                                             "This is a strong indicator of a spawn-abuse script used to flood or crash alt:V servers.",
                                    Detail = $"Matched keyword: {keyword} | Path: {file}",
                                });
                                break;
                            }
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckResourceDirsForSpawnAbuseResources(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var root in AltVRoots)
        {
            if (!Directory.Exists(root)) continue;
            ct.ThrowIfCancellationRequested();

            foreach (var subDir in AltVResourceSubDirs)
            {
                var resourcesPath = Path.Combine(root, subDir);
                if (!Directory.Exists(resourcesPath)) continue;

                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(resourcesPath, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var dirName = Path.GetFileName(dir);

                        foreach (var badFolder in SpawnAbuseResourceFolderNames)
                        {
                            if (dirName.Equals(badFolder, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Spawn-abuse resource folder in alt:V resources: {dirName}",
                                    Risk = RiskLevel.High,
                                    Location = dir,
                                    FileName = dirName,
                                    Reason = $"alt:V resource directory named '{dirName}' matches a known spawn-abuse resource name. " +
                                             "Spawn-abuse resources are loaded as alt:V resources to repeatedly spawn objects or entities " +
                                             "until the server crashes or becomes unusable.",
                                    Detail = $"Resource dir: {dir}",
                                });
                                break;
                            }
                        }

                        foreach (var keyword in SpawnAbuseFileSuffixPatterns)
                        {
                            if (dirName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Suspicious resource folder name (spawn-abuse): {dirName}",
                                    Risk = RiskLevel.Medium,
                                    Location = dir,
                                    FileName = dirName,
                                    Reason = $"alt:V resource folder '{dirName}' contains spawn-abuse keyword '{keyword}'. " +
                                             "This directory may contain a spawn-abuse resource that floods the server with objects.",
                                    Detail = $"Matched keyword: {keyword} | Path: {dir}",
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckJavaScriptFilesForSpawnAbusePatterns(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var jsScanDirs = new List<string>(AltVRoots)
        {
            AppData,
            LocalAppData,
        };

        foreach (var dir in jsScanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.js", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length > 2 * 1024 * 1024) continue;

                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);

                        var matches = JsSpawnAbuseCodePatterns
                            .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matches.Count == 0) continue;

                        bool hasLoop = content.Contains("for (", StringComparison.OrdinalIgnoreCase) ||
                                       content.Contains("while (", StringComparison.OrdinalIgnoreCase) ||
                                       content.Contains("setInterval(", StringComparison.OrdinalIgnoreCase);

                        bool hasCreateObject = content.Contains("createObject", StringComparison.OrdinalIgnoreCase) ||
                                              content.Contains("createObjectNoOffset", StringComparison.OrdinalIgnoreCase);

                        var risk = (hasLoop && hasCreateObject) ? RiskLevel.High
                                 : matches.Count >= 2 ? RiskLevel.High
                                 : RiskLevel.Medium;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"JavaScript file with spawn-abuse patterns: {fn}",
                            Risk = risk,
                            Location = file,
                            FileName = fn,
                            Reason = $"JavaScript file '{fn}' contains {matches.Count} spawn-abuse code pattern(s): " +
                                     string.Join(", ", matches.Take(4).Select(m => $"'{m}'")) +
                                     (matches.Count > 4 ? " ..." : "") + ". " +
                                     (hasLoop && hasCreateObject
                                         ? "File uses object creation inside a loop — classic object spam/flood pattern. "
                                         : "") +
                                     "These patterns are used by alt:V spawn-abuse tools to crash servers via excessive entity creation.",
                            Detail = $"Patterns ({matches.Count}): {string.Join(", ", matches.Take(6))} | " +
                                     $"Loop detected: {hasLoop} | CreateObject: {hasCreateObject}",
                        });
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckLuaFilesForSpawnAbusePatterns(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var luaScanDirs = new List<string>(AltVRoots)
        {
            AppData,
            LocalAppData,
        };

        foreach (var dir in luaScanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length > 2 * 1024 * 1024) continue;

                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);

                        var matches = LuaSpawnAbuseCodePatterns
                            .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matches.Count == 0) continue;

                        bool hasLoop = content.Contains("for ", StringComparison.OrdinalIgnoreCase) ||
                                       content.Contains("while ", StringComparison.OrdinalIgnoreCase) ||
                                       content.Contains("repeat ", StringComparison.OrdinalIgnoreCase);

                        bool hasCreateObject = content.Contains("CreateObject", StringComparison.OrdinalIgnoreCase) ||
                                              content.Contains("CreateObjectNoOffset", StringComparison.OrdinalIgnoreCase);

                        var risk = (hasLoop && hasCreateObject) ? RiskLevel.High
                                 : matches.Count >= 2 ? RiskLevel.High
                                 : RiskLevel.Medium;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Lua file with spawn-abuse patterns: {fn}",
                            Risk = risk,
                            Location = file,
                            FileName = fn,
                            Reason = $"Lua file '{fn}' contains {matches.Count} spawn-abuse code pattern(s): " +
                                     string.Join(", ", matches.Take(4).Select(m => $"'{m}'")) +
                                     (matches.Count > 4 ? " ..." : "") + ". " +
                                     (hasLoop && hasCreateObject
                                         ? "File calls CreateObject inside a loop — classic object spawn flood. "
                                         : "") +
                                     "These patterns are used by alt:V spawn-abuse tools to overload servers via entity flooding.",
                            Detail = $"Patterns ({matches.Count}): {string.Join(", ", matches.Take(6))} | " +
                                     $"Loop: {hasLoop} | CreateObject: {hasCreateObject}",
                        });
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckLogFilesForSpawnAbuseKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logDirs = new List<string>(AltVRoots)
        {
            AppData,
            LocalAppData,
            Path.Combine(UserProfile, "Downloads"),
            TempDir,
        };

        var logExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".log", ".txt", ".json", ".cfg",
        };

        foreach (var dir in logDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    if (!logExtensions.Contains(ext)) continue;

                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length > 4 * 1024 * 1024) continue;

                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);

                        var matches = LogFileSpawnAbusePatterns
                            .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matches.Count == 0) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Log file containing spawn-abuse references: {fn}",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = fn,
                            Reason = $"Log/config file '{fn}' contains {matches.Count} spawn-abuse reference(s): " +
                                     string.Join(", ", matches.Take(4).Select(m => $"'{m}'")) +
                                     (matches.Count > 4 ? " ..." : "") + ". " +
                                     "These log entries indicate prior object spam, prop flooding, or entity-based server crashes on alt:V.",
                            Detail = $"Matched patterns ({matches.Count}): {string.Join(", ", matches.Take(6))}",
                        });
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckRegistryForSpawnAbuseArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var registryPaths = new[]
        {
            @"Software\AltV\SpawnAbuse",
            @"Software\AltVTools\ObjectSpam",
            @"Software\AltVTools",
            @"Software\AltV",
            @"Software\ObjectSpammer",
            @"Software\PropFlooder",
            @"Software\EntitySpammer",
            @"Software\AltVCrasher",
            @"Software\CrashSpawner",
            @"Software\EntityFlooder",
            @"Software\SpawnAbuse",
            @"Software\SpawnAbuser",
            @"Software\ObjectFlooder",
            @"Software\PropSpammer",
            @"Software\EntitySpam",
            @"Software\ObjectCrasher",
            @"Software\PropCrasher",
            @"Software\SpawnCrasher",
        };

        foreach (var regPath in registryPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Registry key for spawn-abuse tool: {regPath}",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{regPath}",
                    Reason = $"Registry key 'HKCU\\{regPath}' found. " +
                             "This key is created by known alt:V object/prop spawn-abuse tools. " +
                             "Its presence indicates that a spawn-abuse tool was installed or executed on this machine.",
                    Detail = $"Registry path: HKCU\\{regPath} | Values: {string.Join(", ", key.GetValueNames().Take(5))}",
                });
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var hklmPaths = new[]
        {
            @"Software\AltV\SpawnAbuse",
            @"Software\AltVTools\ObjectSpam",
            @"Software\ObjectSpammer",
            @"Software\PropFlooder",
            @"Software\EntitySpammer",
            @"Software\AltVCrasher",
            @"Software\CrashSpawner",
        };

        foreach (var regPath in hklmPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"HKLM registry key for spawn-abuse tool: {regPath}",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{regPath}",
                    Reason = $"Registry key 'HKLM\\{regPath}' found. " +
                             "This machine-level key is created by alt:V spawn-abuse tools that install system-wide. " +
                             "Its presence strongly indicates installation of an object/prop spawn-abuse tool.",
                    Detail = $"Registry path: HKLM\\{regPath}",
                });
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckUserAssistForSpawnAbuseExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string UserAssistBase =
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

        try
        {
            using var baseKey = Registry.CurrentUser.OpenSubKey(UserAssistBase, writable: false);
            if (baseKey is null) return;

            foreach (var guidName in baseKey.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var countKey = baseKey.OpenSubKey($@"{guidName}\Count", writable: false);
                    if (countKey is null) continue;

                    foreach (var encodedName in countKey.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();

                        var decoded = Rot13Decode(encodedName);

                        var hit = UserAssistSpawnAbuseKeywords.FirstOrDefault(k =>
                            decoded.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hit is null) continue;

                        int runCount = 0;
                        DateTime? lastRun = null;
                        try
                        {
                            var data = countKey.GetValue(encodedName) as byte[];
                            if (data is { Length: >= 16 })
                            {
                                runCount = BitConverter.ToInt32(data, 4);
                                var fileTime = BitConverter.ToInt64(data, 8);
                                if (fileTime > 0)
                                    lastRun = DateTime.FromFileTimeUtc(fileTime);
                            }
                        }
                        catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"UserAssist: spawn-abuse executable executed — {hit}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{UserAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason = $"Windows UserAssist entry shows execution of spawn-abuse tool '{Path.GetFileName(decoded)}' " +
                                     $"({runCount} time(s) executed" +
                                     (lastRun.HasValue ? $", last seen {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                     $"). Matched keyword: '{hit}'. " +
                                     "UserAssist entries persist even after the binary has been deleted.",
                            Detail = $"Decoded: {decoded} | Executions: {runCount} | " +
                                     $"Last run: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}",
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }, ct);

    private Task CheckTempAndAppDataForSpawnAbuseArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var artifactDirs = new[]
        {
            TempDir,
            AppData,
            LocalAppData,
            Path.Combine(UserProfile, "Downloads"),
            Desktop,
        };

        var interestingExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".zip", ".rar", ".7z", ".bat", ".ps1", ".js", ".lua", ".txt",
        };

        foreach (var dir in artifactDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    if (!interestingExtensions.Contains(ext)) continue;

                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    foreach (var keyword in SpawnAbuseFileSuffixPatterns)
                    {
                        if (fn.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Spawn-abuse artifact in temp/AppData: {fn}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = fn,
                                Reason = $"File '{fn}' in '{dir}' contains spawn-abuse keyword '{keyword}'. " +
                                         "Spawn-abuse tools often leave temporary artifacts in AppData or Temp directories " +
                                         "when downloading, extracting, or running object flooding scripts.",
                                Detail = $"Matched keyword: {keyword} | Path: {file}",
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var archiveExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".zip", ".rar", ".7z",
        };

        foreach (var dir in artifactDirs)
        {
            if (!Directory.Exists(dir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    var ext = Path.GetExtension(file);
                    if (!archiveExtensions.Contains(ext)) continue;

                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    foreach (var keyword in SpawnAbuseFileSuffixPatterns)
                    {
                        if (fn.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Spawn-abuse archive artifact: {fn}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = fn,
                                Reason = $"Archive file '{fn}' in '{dir}' contains spawn-abuse keyword '{keyword}'. " +
                                         "This archive may contain an alt:V spawn-abuse tool or script that floods servers with objects.",
                                Detail = $"Matched keyword: {keyword} | Archive: {file}",
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDiscordCacheForSpawnAbuseKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var discordClients = new[] { "discord", "discordptb", "discordcanary" };

        foreach (var client in discordClients)
        {
            ct.ThrowIfCancellationRequested();
            var root = Path.Combine(AppData, client);
            if (!Directory.Exists(root)) continue;

            var cacheDirs = new[]
            {
                Path.Combine(root, "Cache"),
                Path.Combine(root, "Code Cache"),
                Path.Combine(root, "Local Storage"),
                Path.Combine(root, "GPUCache"),
            };

            foreach (var cacheDir in cacheDirs)
            {
                if (!Directory.Exists(cacheDir)) continue;
                ct.ThrowIfCancellationRequested();
                try
                {
                    foreach (var file in Directory.EnumerateFiles(cacheDir, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fi = new FileInfo(file);
                        if (fi.Length > 512 * 1024) continue;
                        if (fi.Length == 0) continue;

                        ctx.IncrementFiles();

                        try
                        {
                            string content;
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                            content = await sr.ReadToEndAsync(ct);

                            var matches = DiscordSpawnAbuseKeywords
                                .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                                .ToList();

                            if (matches.Count == 0) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Discord cache: spawn-abuse keyword references in {client}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Discord client '{client}' cache file contains {matches.Count} spawn-abuse keyword(s): " +
                                         string.Join(", ", matches.Take(4).Select(m => $"'{m}'")) +
                                         (matches.Count > 4 ? " ..." : "") + ". " +
                                         "This indicates potential membership in or communication about alt:V spawn-abuse communities or cheat distribution channels.",
                                Detail = $"Discord client: {client} | Cache file: {file} | " +
                                         $"Keywords ({matches.Count}): {string.Join(", ", matches.Take(6))}",
                            });
                        }
                        catch (IOException) { }
                        catch (UnauthorizedAccessException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckCefCacheForSpawnAbuseKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var cefDirs = new List<string>();

        foreach (var root in AltVRoots)
        {
            cefDirs.Add(Path.Combine(root, "cef"));
            cefDirs.Add(Path.Combine(root, "cache", "cef"));
            cefDirs.Add(Path.Combine(root, "data", "cef"));
            cefDirs.Add(Path.Combine(root, "CEFCache"));
        }

        foreach (var cefDir in cefDirs)
        {
            if (!Directory.Exists(cefDir)) continue;
            ct.ThrowIfCancellationRequested();
            try
            {
                foreach (var file in Directory.EnumerateFiles(cefDir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    var fi = new FileInfo(file);
                    if (fi.Length > 1 * 1024 * 1024) continue;
                    if (fi.Length == 0) continue;

                    ctx.IncrementFiles();

                    try
                    {
                        string content;
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                        content = await sr.ReadToEndAsync(ct);

                        var matches = CefSpawnAbuseKeywords
                            .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matches.Count == 0) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V CEF cache: spawn-abuse references found",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"alt:V CEF/browser cache file contains {matches.Count} spawn-abuse keyword(s): " +
                                     string.Join(", ", matches.Take(4).Select(m => $"'{m}'")) +
                                     (matches.Count > 4 ? " ..." : "") + ". " +
                                     "The CEF cache stores web content visited from within alt:V, indicating the user may have browsed " +
                                     "spawn-abuse tool download sites or cheat communities from inside the game client.",
                            Detail = $"CEF cache dir: {cefDir} | File: {file} | " +
                                     $"Keywords ({matches.Count}): {string.Join(", ", matches.Take(6))}",
                        });
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckPrefetchForSpawnAbuseExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string PrefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(PrefetchDir)) return;

        string[] pfFiles;
        try
        {
            pfFiles = Directory.GetFiles(PrefetchDir, "*.pf");
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var file in pfFiles)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            var pfName = Path.GetFileNameWithoutExtension(file);
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            var hit = PrefetchSpawnAbuseKeywords.FirstOrDefault(k =>
                exeName.Contains(k, StringComparison.OrdinalIgnoreCase));
            if (hit is null) continue;

            DateTime? lastWrite = null;
            try { lastWrite = File.GetLastWriteTimeUtc(file); } catch { }

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Prefetch: spawn-abuse executable executed — {exeName}",
                Risk = RiskLevel.High,
                Location = file,
                FileName = exeName + ".exe",
                Reason = $"Windows Prefetch file indicates execution of spawn-abuse tool '{exeName}.exe'. " +
                         $"Matched keyword: '{hit}'. " +
                         "Prefetch entries persist even after the executable has been deleted, " +
                         "providing forensic evidence of prior spawn-abuse tool usage on this system.",
                Detail = $"Prefetch file: {file} | Executable: {exeName}.exe | " +
                         $"Last prefetch update: {(lastWrite.HasValue ? lastWrite.Value.ToString("yyyy-MM-dd HH:mm:ss") + " UTC" : "unknown")}",
            });
        }
    }, ct);

    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            if (c >= 'A' && c <= 'Z')
                sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z')
                sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else
                sb.Append(c);
        }
        return sb.ToString();
    }
}
