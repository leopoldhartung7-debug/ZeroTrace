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

public sealed class AltVCrasherDetectionScanModule : IScanModule
{
    public string Name => "alt:V Crasher & Griefing Tool Forensic Scan";
    public double Weight => 4.2;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] CrasherExecutables =
    [
        "altv_crash.exe", "altv_crasher.exe", "altv_ddos.exe", "altv_kick.exe",
        "altv_grief.exe", "altv_troll.exe", "altv_freeze.exe", "altv_lag.exe",
        "altv_spam.exe", "altv_flood.exe", "altv_event_spam.exe", "altv_event_flood.exe",
        "altv_exploit.exe", "altv_rce.exe", "altv_dos.exe", "crash_altv.exe",
        "crasher_altv.exe", "ddos_altv.exe", "kick_altv.exe", "grief_altv.exe",
        "troll_altv.exe", "freeze_altv.exe", "lag_altv.exe", "spam_altv.exe",
        "flood_altv.exe", "event_spam.exe", "event_flood.exe", "altv_crash_tool.exe",
        "altv_grief_tool.exe", "altv_ddos_tool.exe", "altv_kick_tool.exe",
        "altv_freeze_tool.exe", "altv_crash_v2.exe", "server_crash.exe",
        "server_crasher.exe", "server_ddos.exe", "server_flood.exe", "server_kick.exe",
        "server_grief.exe", "server_troll.exe", "player_crash.exe", "player_crasher.exe",
        "player_kick.exe", "player_freeze.exe", "altv_nuke.exe", "altv_wipe.exe",
        "altv_lag_switch.exe", "altv_packet_flood.exe", "altv_packet_crash.exe",
        "altv_native_crash.exe", "altv_overflow.exe", "altv_buffer_overflow.exe",
        "altv_heap_overflow.exe", "altv_null_crash.exe", "altv_crash_exploit.exe",
        "altv_crash_tool_v2.exe", "altv_crash_tool_v3.exe", "crasher_v2.exe",
        "grief_v2.exe", "ddos_v2.exe", "kick_v2.exe", "troll_v2.exe",
        "freeze_v2.exe", "lag_v2.exe",
    ];

    private static readonly string[] CrasherDlls =
    [
        "crash_inject.dll", "crasher_hook.dll", "grief_hook.dll", "ddos_hook.dll",
        "kick_hook.dll", "freeze_hook.dll", "spam_hook.dll", "flood_hook.dll",
        "altv_crash.dll", "altv_crasher.dll", "altv_grief.dll", "altv_ddos.dll",
        "altv_kick.dll", "altv_freeze.dll", "altv_spam.dll", "altv_flood.dll",
        "crash_exploit.dll", "grief_exploit.dll", "ddos_exploit.dll", "altv_nuke.dll",
        "altv_wipe.dll", "packet_flood.dll", "event_flood.dll", "native_crash.dll",
        "overflow_crash.dll", "crash_bypass.dll", "grief_bypass.dll", "crasher_v2.dll",
        "crasher_v3.dll", "grief_v2.dll", "ddos_v2.dll", "kick_v2.dll",
        "freeze_v2.dll", "spam_v2.dll", "flood_v2.dll", "lag_switch.dll",
        "packet_crash.dll", "buffer_overflow.dll", "heap_overflow.dll", "null_crash.dll",
    ];

    private static readonly string[] CrasherResourceFolderNames =
    [
        "crash", "crasher", "griefmenu", "troll", "ddos", "freeze_all", "kick_all",
        "spam", "event_flood", "event_spam", "altv_crash", "altv_crasher",
        "altv_grief", "altv_ddos", "altv_kick", "altv_freeze", "altv_troll",
        "altv_spam", "altv_flood", "server_crash", "server_grief", "server_ddos",
        "player_crash", "player_kick", "crash_exploit", "grief_exploit", "ddos_exploit",
        "nuke", "wipe", "lag_switch", "packet_flood", "packet_crash", "native_crash",
        "overflow", "buffer_overflow", "heap_overflow", "null_crash", "crash_tool",
        "grief_tool", "ddos_tool", "kick_tool", "freeze_tool", "troll_tool",
        "spam_tool", "flood_tool", "crash_v2", "crasher_v2", "grief_v2",
        "ddos_v2", "kick_v2", "freeze_v2", "troll_v2", "spam_v2", "flood_v2", "lag_v2",
    ];

    private static readonly string[] CrasherLuaKeywords =
    [
        "AddExplosion", "NetworkExplodeVehicle", "TriggerNetworkEvent", "TriggerServerEvent",
        "native.invoke", "crash", "grief", "troll", "ddos", "kick", "freeze",
        "spam", "flood", "event_spam", "event_flood", "nuke", "wipe", "lag_switch",
        "packet_flood", "native_crash", "overflow", "buffer_overflow",
    ];

    private static readonly string[] CrasherJsKeywords =
    [
        "alt.emit", "alt.emitServer", "crashPlayer", "kickPlayer", "freezePlayer",
        "grief", "ddos", "spam", "flood", "event_spam", "event_flood",
        "native.invoke crash", "packet_flood", "crash_exploit", "grief_exploit",
        "ddos_exploit", "nuke", "wipe", "lag_switch", "overflow",
        "buffer_overflow", "heap_overflow", "null_crash",
    ];

    private static readonly string[] CrasherClientLogPatterns =
    [
        "crash attempt", "grief detected", "ddos detected", "kick player",
        "freeze player", "spam detected", "flood detected", "event spam",
        "event flood", "native crash", "packet flood", "crash exploit",
        "grief exploit", "ddos exploit", "player nuked", "player wiped",
        "lag switch", "buffer overflow", "heap overflow", "null crash",
        "overflow detected", "crasher detected", "griefer detected",
        "ddoser detected", "crash tool detected", "grief tool detected",
        "ddos tool detected", "ban for crash", "ban for grief", "ban for ddos",
        "kick for crash", "kick for grief", "kick for ddos",
        "anti-grief triggered", "anti-crash triggered", "anti-ddos triggered",
        "crash rate limit", "grief rate limit", "ddos rate limit",
        "event rate limit", "packet rate limit", "native rate limit",
        "overflow rate limit",
    ];

    private static readonly string[] CrasherServerLogPatterns =
    [
        "player crashed server", "player griefing", "ddos detected",
        "event flood detected", "event spam detected", "native crash detected",
        "packet flood detected", "ban for crasher", "ban for griefer",
        "ban for ddoser", "kick for crash", "kick for grief", "kick for ddos",
        "crash exploit detected", "grief exploit detected", "ddos exploit detected",
        "overflow detected", "buffer overflow", "heap overflow", "null crash",
        "crash rate exceeded", "grief rate exceeded", "ddos rate exceeded",
        "event rate exceeded", "packet rate exceeded", "native rate exceeded",
        "suspicious event pattern", "suspicious packet pattern",
        "crash pattern detected", "grief pattern detected", "ddos pattern detected",
        "server overload detected", "lag switch detected", "anti-cheat crash",
        "ac: crash", "ac: grief", "ac: ddos", "illegal native call",
    ];

    private static readonly string[] CrasherDownloadArtifacts =
    [
        "altv_crasher.zip", "altv_crash_tool.zip", "altv_grief_tool.zip",
        "altv_ddos_tool.zip", "altv_kick_tool.zip", "altv_freeze_tool.zip",
        "altv_crash.zip", "altv_grief.zip", "altv_ddos.zip", "altv_kick.zip",
        "altv_troll.zip", "altv_spam.zip", "altv_flood.zip",
        "crasher_altv.zip", "grief_tool_altv.zip", "ddos_altv.zip",
        "altv_nuke.zip", "altv_wipe.zip", "altv_lag_switch.zip",
        "altv_packet_flood.zip", "altv_event_flood.zip", "altv_event_spam.zip",
        "altv_crasher.rar", "altv_crash_tool.rar", "altv_grief_tool.rar",
        "altv_ddos_tool.rar", "altv_crash.rar", "altv_grief.rar",
        "altv_ddos.rar", "altv_kick.rar", "crasher_altv.rar",
        "altv_crasher.7z", "altv_crash_tool.7z", "altv_grief_tool.7z",
        "altv_crash_setup.exe", "altv_crasher_setup.exe", "altv_grief_setup.exe",
        "altv_ddos_setup.exe", "crash_tool_setup.exe", "grief_tool_setup.exe",
        "altv_crash_v2.zip", "altv_crasher_v2.zip", "altv_grief_v2.zip",
        "altv_ddos_v2.zip", "altv_overflow.zip", "altv_null_crash.zip",
        "altv_buffer_overflow.zip",
    ];

    private static readonly string[] CrasherRegistryKeys =
    [
        @"SOFTWARE\AltVCrasher", @"SOFTWARE\AltVCrash", @"SOFTWARE\AltVGrief",
        @"SOFTWARE\AltVDDoS", @"SOFTWARE\AltVKick", @"SOFTWARE\AltVFreeze",
        @"SOFTWARE\AltVTroll", @"SOFTWARE\AltVSpam", @"SOFTWARE\AltVFlood",
        @"SOFTWARE\ServerCrasher", @"SOFTWARE\PlayerCrasher",
    ];

    private static readonly string[] CrasherUserAssistNames =
    [
        "altv crash", "altv crasher", "altv ddos", "altv kick", "altv grief",
        "altv troll", "altv freeze", "altv spam", "altv flood", "altv nuke",
        "altv wipe", "server crash", "server ddos", "player crash", "player kick",
        "crash tool", "grief tool", "ddos tool", "kick tool", "freeze tool",
        "altv_crash", "altv_crasher", "altv_ddos", "altv_kick", "altv_grief",
        "altv_troll", "altv_freeze", "altv_spam", "altv_flood", "altv_nuke",
        "lag_switch", "packet_flood", "event_flood",
    ];

    private static readonly string[] CrasherMuiCacheNames =
    [
        "altv crash", "altv crasher", "altv ddos", "altv kick", "altv grief",
        "altv troll", "altv freeze", "altv spam", "altv flood", "altv nuke",
        "server crash", "server ddos", "player crash", "crash tool",
        "grief tool", "ddos tool", "kick tool", "freeze tool",
        "lag switch", "packet flood", "event flood", "event spam",
        "altv_crash", "altv_crasher", "altv_ddos", "altv_grief",
        "buffer_overflow", "null_crash",
    ];

    private static readonly string[] AltVDataPaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "altv"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "alt-v"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "alt-v"),
    ];

    private static readonly string[] AltVServerPaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "altv-server"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "alt-v-server"),
        @"C:\altv-server",
        @"C:\alt-v-server",
        @"C:\altv",
    ];

    private static readonly string[] CrasherCacheSubDirs =
    [
        "cache", "data", "storage", "local", "plugins", "modules", "temp",
    ];

    private static readonly string[] CrasherBinaryKeywords =
    [
        "crash_inject", "crasher_hook", "grief_hook", "ddos_hook", "kick_hook",
        "freeze_hook", "spam_hook", "flood_hook", "crash_exploit", "grief_exploit",
        "ddos_exploit", "altv_nuke", "altv_wipe", "packet_flood", "event_flood",
        "native_crash", "overflow_crash", "crash_bypass", "grief_bypass",
        "lag_switch", "packet_crash", "buffer_overflow", "heap_overflow", "null_crash",
    ];

    private static readonly string[] CrasherAmcacheKeywords =
    [
        "altv_crash", "altv_crasher", "altv_ddos", "altv_kick", "altv_grief",
        "altv_troll", "altv_freeze", "altv_spam", "altv_flood", "altv_nuke",
        "altv_wipe", "server_crash", "server_ddos", "server_grief", "server_kick",
        "player_crash", "player_kick", "crash_tool", "grief_tool", "ddos_tool",
        "kick_tool", "freeze_tool", "lag_switch", "packet_flood", "event_flood",
        "event_spam", "native_crash", "overflow_crash", "crasher_v2", "grief_v2",
    ];

    private static readonly string[] CrasherNetworkKeywords =
    [
        "ddos", "flood", "packet_flood", "event_flood", "altv_crash", "altv_grief",
        "altv_ddos", "crasher", "griefer", "ddoser", "lag_switch",
    ];

    private static readonly string[] CrasherManifestKeywords =
    [
        "crash", "crasher", "grief", "ddos", "kick-all", "freeze-all", "spam",
        "event-flood", "event-spam", "altv-crash", "altv-crasher", "altv-grief",
        "altv-ddos", "server-crash", "player-crash", "nuke", "wipe", "lag-switch",
        "packet-flood", "packet-crash", "native-crash", "overflow",
        "buffer-overflow", "heap-overflow", "null-crash",
    ];

    private static readonly string[] CrasherConfigFileNames =
    [
        "crash_config.json", "grief_config.json", "ddos_config.json",
        "kick_config.json", "freeze_config.json", "crasher_config.json",
        "griefer_config.json", "ddoser_config.json", "crash_settings.json",
        "grief_settings.json", "ddos_settings.json", "crash_targets.txt",
        "grief_targets.txt", "ddos_targets.txt", "crash_offsets.txt",
        "grief_offsets.txt", "ddos_offsets.txt",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckAltVCrasherExecutables(ctx, ct),
            CheckAltVCrasherDlls(ctx, ct),
            CheckAltVCrasherResourceFolders(ctx, ct),
            CheckAltVCrasherLuaFiles(ctx, ct),
            CheckAltVCrasherJsFiles(ctx, ct),
            CheckAltVCrasherClientLogs(ctx, ct),
            CheckAltVCrasherServerLogs(ctx, ct),
            CheckAltVCrasherDownloadArtifacts(ctx, ct),
            CheckRegistryForAltVCrashers(ctx, ct),
            CheckAltVCrasherInstallerRecords(ctx, ct)
        );
    }

    private Task CheckAltVCrasherExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(AltVDataPaths)
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (CrasherExecutables.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V crasher/griefing executable: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known alt:V crasher or griefing tool executable '{fn}' found. " +
                                     "This tool is used to crash players, servers, or flood/spam events on alt:V multiplayer.",
                            Detail = $"Path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVCrasherDlls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(AltVDataPaths)
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (CrasherDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V crasher/griefing DLL: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known alt:V crasher or griefing tool DLL '{fn}' found. " +
                                     "This library is injected or loaded to crash players, kick users, or flood events on alt:V.",
                            Detail = $"Path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVCrasherResourceFolders(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var root in AltVDataPaths)
        {
            var resourcesDirs = new[]
            {
                Path.Combine(root, "resources"),
                Path.Combine(root, "packages"),
                Path.Combine(root, "client_packages"),
            };

            foreach (var baseDir in resourcesDirs)
            {
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(baseDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        var folderName = Path.GetFileName(dir);
                        if (CrasherResourceFolderNames.Any(n => folderName.Equals(n, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V crasher resource folder: {folderName}",
                                Risk = RiskLevel.High,
                                Location = baseDir,
                                FileName = folderName,
                                Reason = $"alt:V resource or package folder '{folderName}' matches a known crasher/griefing tool name. " +
                                         "These resources are loaded by alt:V and crash, kick, or grief other players.",
                                Detail = $"Path: {dir}",
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckAltVCrasherLuaFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var resourceDirs = new List<string>();
        foreach (var root in AltVDataPaths)
        {
            resourceDirs.Add(Path.Combine(root, "resources"));
            resourceDirs.Add(Path.Combine(root, "packages"));
            resourceDirs.Add(Path.Combine(root, "client_packages"));
        }

        foreach (var dir in resourceDirs)
        {
            if (!Directory.Exists(dir)) continue;
            IEnumerable<string> luaFiles;
            try
            {
                luaFiles = Directory.EnumerateFiles(dir, "*.lua", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in luaFiles)
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

                int hits = 0;
                var matchedKeywords = new List<string>();
                foreach (var keyword in CrasherLuaKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        hits++;
                        matchedKeywords.Add(keyword);
                    }
                }

                if (hits >= 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V crasher Lua script: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = Path.GetDirectoryName(file) ?? dir,
                        FileName = Path.GetFileName(file),
                        Reason = $"Lua script contains {hits} crasher/griefing API patterns " +
                                 $"({string.Join(", ", matchedKeywords.Take(5))}). " +
                                 "Such scripts use native invocations and event triggers to crash or grief alt:V players.",
                        Detail = $"Path: {file} | Matched: {string.Join("|", matchedKeywords)}",
                    });
                }
            }
        }
    }, ct);

    private Task CheckAltVCrasherJsFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var resourceDirs = new List<string>();
        foreach (var root in AltVDataPaths)
        {
            resourceDirs.Add(Path.Combine(root, "resources"));
            resourceDirs.Add(Path.Combine(root, "packages"));
            resourceDirs.Add(Path.Combine(root, "client_packages"));
        }

        var jsExtensions = new[] { "*.js", "*.mjs", "*.cjs", "*.ts" };

        foreach (var dir in resourceDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var ext in jsExtensions)
            {
                IEnumerable<string> jsFiles;
                try
                {
                    jsFiles = Directory.EnumerateFiles(dir, ext, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in jsFiles)
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

                    int hits = 0;
                    var matchedKeywords = new List<string>();
                    foreach (var keyword in CrasherJsKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            hits++;
                            matchedKeywords.Add(keyword);
                        }
                    }

                    if (hits >= 4)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V crasher JS script: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = Path.GetFileName(file),
                            Reason = $"JavaScript resource file contains {hits} crasher/griefing patterns " +
                                     $"({string.Join(", ", matchedKeywords.Take(5))}). " +
                                     "These scripts use alt.emit, event flooding, and crash-inducing native calls.",
                            Detail = $"Path: {file} | Matched: {string.Join("|", matchedKeywords)}",
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckAltVCrasherClientLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var altVDir in AltVDataPaths)
        {
            if (!Directory.Exists(altVDir)) continue;
            IEnumerable<string> logFiles;
            try
            {
                logFiles = Directory.EnumerateFiles(altVDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(altVDir, "*.txt", SearchOption.AllDirectories));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

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

                var lower = content.ToLowerInvariant();
                foreach (var pattern in CrasherClientLogPatterns)
                {
                    if (lower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V client log: crasher/griefing evidence",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(logFile) ?? altVDir,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"alt:V client log contains crasher/griefing pattern '{pattern}'. " +
                                     "This indicates the client was involved in crashing, kicking, or griefing other players.",
                            Detail = $"Log: {logFile} | Pattern: {pattern}",
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckAltVCrasherServerLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var serverLogDirs = new List<string>();
        foreach (var serverPath in AltVServerPaths)
        {
            serverLogDirs.Add(Path.Combine(serverPath, "logs"));
            serverLogDirs.Add(serverPath);
        }

        foreach (var logDir in serverLogDirs)
        {
            if (!Directory.Exists(logDir)) continue;
            IEnumerable<string> logFiles;
            try
            {
                logFiles = Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(logDir, "*.txt", SearchOption.AllDirectories));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

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

                var lower = content.ToLowerInvariant();
                foreach (var pattern in CrasherServerLogPatterns)
                {
                    if (lower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V server log: crasher/griefing evidence",
                            Risk = RiskLevel.High,
                            Location = logDir,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"alt:V server log records crasher/griefing activity: '{pattern}'. " +
                                     "Server-side logs recording this pattern indicate the player used crash or grief tools.",
                            Detail = $"Log: {logFile} | Pattern: {pattern}",
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckAltVCrasherDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (CrasherDownloadArtifacts.Any(a => fn.Equals(a, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V crasher download artifact: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Crasher or griefing tool archive '{fn}' found in user download/desktop area. " +
                                     "This is a known alt:V crash tool, DDoS tool, or griefing menu package.",
                            Detail = $"Path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRegistryForAltVCrashers(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var keyPath in CrasherRegistryKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V crasher registry key: {keyPath}",
                        Risk = RiskLevel.High,
                        Location = @"HKCU\" + keyPath,
                        FileName = string.Empty,
                        Reason = $"Registry key '{keyPath}' under HKCU was left by an alt:V crasher or griefing tool installation.",
                        Detail = $"Key: HKCU\\{keyPath}",
                    });
                }
            }
            catch (Exception) { }

            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                if (key != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V crasher registry key (HKLM): {keyPath}",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\" + keyPath,
                        FileName = string.Empty,
                        Reason = $"Registry key '{keyPath}' under HKLM was left by an alt:V crasher or griefing tool.",
                        Detail = $"Key: HKLM\\{keyPath}",
                    });
                }
            }
            catch (Exception) { }
        }

        // UserAssist ROT13 check for crasher execution history
        const string uaPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        try
        {
            using var ua = Registry.CurrentUser.OpenSubKey(uaPath);
            if (ua != null)
            {
                foreach (var guidName in ua.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var count = Registry.CurrentUser.OpenSubKey($@"{uaPath}\{guidName}\Count");
                        if (count == null) continue;
                        foreach (var valName in count.GetValueNames())
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();
                            var decoded = Rot13Decode(valName).ToLowerInvariant();
                            bool isCrasher = CrasherUserAssistNames.Any(n => decoded.Contains(n, StringComparison.OrdinalIgnoreCase))
                                || CrasherExecutables.Any(e => decoded.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase));
                            if (isCrasher)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "alt:V crasher execution (UserAssist)",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKCU\{uaPath}\{guidName}\Count",
                                    FileName = decoded,
                                    Reason = $"UserAssist registry records execution of alt:V crasher or griefing tool: '{decoded}'. " +
                                             "UserAssist entries prove the executable was launched by this user account.",
                                    Detail = $"ROT13 decoded: {decoded} | Raw: {valName}",
                                });
                            }
                        }
                    }
                    catch (Exception) { }
                }
            }
        }
        catch (Exception) { }

        // MUICache check for griefing tool execution
        var muiPaths = new[]
        {
            @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            @"SOFTWARE\Microsoft\Windows\ShellNoRoam\MUICache",
        };
        foreach (var muiPath in muiPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var mui = Registry.CurrentUser.OpenSubKey(muiPath);
                if (mui == null) continue;
                foreach (var valName in mui.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    var lower = valName.ToLowerInvariant();
                    bool isCrasher = CrasherMuiCacheNames.Any(n => lower.Contains(n, StringComparison.OrdinalIgnoreCase))
                        || CrasherExecutables.Any(e => lower.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase));
                    if (isCrasher)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V crasher execution (MUICache)",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\" + muiPath,
                            FileName = Path.GetFileName(valName),
                            Reason = $"MUICache records execution of alt:V crasher or griefing tool: '{Path.GetFileName(valName)}'. " +
                                     "MUICache stores application display names for recently launched executables.",
                            Detail = $"Entry: {valName}",
                        });
                    }
                }
            }
            catch (Exception) { }
        }

        // Run/RunOnce persistence check
        var runPaths = new[]
        {
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.CurrentUser),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.CurrentUser),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.LocalMachine),
        };

        foreach (var (runPath, hive) in runPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ctx.IncrementRegistryKeys();
                using var run = hive.OpenSubKey(runPath);
                if (run == null) continue;
                foreach (var valName in run.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var data = run.GetValue(valName)?.ToString() ?? string.Empty;
                    var lower = data.ToLowerInvariant();
                    bool isCrasher = CrasherExecutables.Any(e => lower.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase))
                        || lower.Contains("altv crash") || lower.Contains("altv grief")
                        || lower.Contains("altv ddos") || lower.Contains("altv kick")
                        || lower.Contains("server crash") || lower.Contains("player crash")
                        || lower.Contains("grief tool") || lower.Contains("crash tool");
                    if (isCrasher)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V crasher autostart (Run key)",
                            Risk = RiskLevel.High,
                            Location = (hive == Registry.CurrentUser ? "HKCU" : "HKLM") + @"\" + runPath,
                            FileName = valName,
                            Reason = $"Run registry key '{valName}' references an alt:V crasher or griefing tool. " +
                                     "The tool was configured to auto-start at logon.",
                            Detail = $"Value: {valName} = {data}",
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckAltVCrasherInstallerRecords(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        var cheatNameKeywords = new[]
        {
            "altv crash", "altv crasher", "altv ddos", "altv kick", "altv grief",
            "altv troll", "altv freeze", "altv spam", "altv flood", "altv nuke",
            "altv wipe", "server crash", "server ddos", "server grief", "server kick",
            "player crash", "player kick", "crash tool", "grief tool", "ddos tool",
            "kick tool", "freeze tool", "troll tool", "spam tool", "flood tool",
            "crasher altv", "griefer altv", "ddoser altv", "crash exploit",
            "grief exploit", "ddos exploit", "lag switch", "packet flood",
            "event flood", "event spam", "native crash", "overflow crash",
        };

        foreach (var uninstallPath in uninstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var uninst = Registry.LocalMachine.OpenSubKey(uninstallPath);
                if (uninst == null) continue;
                foreach (var subKeyName in uninst.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var sub = uninst.OpenSubKey(subKeyName);
                        if (sub == null) continue;
                        var displayName = sub.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        var lower = displayName.ToLowerInvariant();
                        if (cheatNameKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V crasher installer record: {displayName}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                FileName = displayName,
                                Reason = $"Windows uninstall record found for alt:V crasher or griefing software '{displayName}'. " +
                                         "This proves the crash/grief tool was formally installed on this system.",
                                Detail = $"Key: {subKeyName} | DisplayName: {displayName}",
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckAltVCrasherConfigFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>(AltVDataPaths)
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);
                    if (!CrasherConfigFileNames.Any(n => fn.Equals(n, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    ctx.IncrementFiles();
                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var lower = content.ToLowerInvariant();
                    var foundKeywords = CrasherBinaryKeywords
                        .Where(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (foundKeywords.Count >= 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V crasher config file: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Configuration file '{fn}' contains crasher/griefing tool keywords " +
                                     $"({string.Join(", ", foundKeywords.Take(3))}). " +
                                     "These files configure crash targets, offsets, or grief parameters.",
                            Detail = $"Path: {file} | Keywords: {string.Join("|", foundKeywords)}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVCrasherCacheDirs(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var root in AltVDataPaths)
        {
            foreach (var sub in CrasherCacheSubDirs)
            {
                var subDir = Path.Combine(root, sub);
                if (!Directory.Exists(subDir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(subDir, "*.dll", SearchOption.AllDirectories)
                        .Concat(Directory.EnumerateFiles(subDir, "*.exe", SearchOption.AllDirectories)))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        bool isCrasher = CrasherExecutables.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase))
                            || CrasherDlls.Any(d => fn.Equals(d, StringComparison.OrdinalIgnoreCase))
                            || CrasherBinaryKeywords.Any(k => fn.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (isCrasher)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V crasher binary in cache: {fn}",
                                Risk = RiskLevel.High,
                                Location = subDir,
                                FileName = fn,
                                Reason = $"Crasher/griefing binary '{fn}' found in alt:V cache or data subdirectory '{sub}'. " +
                                         "Crash tools are sometimes staged in cache directories to evade file-level detection.",
                                Detail = $"Path: {file}",
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckAltVCrasherPrefetchArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir)) return;

        try
        {
            foreach (var pf in Directory.EnumerateFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileNameWithoutExtension(pf).ToLowerInvariant();
                bool isCrasher = CrasherExecutables.Any(e =>
                    fn.StartsWith(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase))
                    || CrasherBinaryKeywords.Any(k => fn.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (isCrasher)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V crasher prefetch artifact: {Path.GetFileName(pf)}",
                        Risk = RiskLevel.High,
                        Location = prefetchDir,
                        FileName = Path.GetFileName(pf),
                        Reason = $"Windows Prefetch file '{Path.GetFileName(pf)}' indicates past execution of an alt:V crasher or griefing tool. " +
                                 "Prefetch files are created by Windows for each launched executable and persist after deletion.",
                        Detail = $"Prefetch: {pf}",
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckAltVCrasherRecentDocuments(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var recentDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "Windows", "Recent");

        if (!Directory.Exists(recentDir)) return;

        try
        {
            foreach (var lnk in Directory.EnumerateFiles(recentDir, "*.lnk", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileNameWithoutExtension(lnk).ToLowerInvariant();
                bool isCrasher = CrasherExecutables.Any(e => fn.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase))
                    || CrasherDownloadArtifacts.Any(a =>
                        fn.Contains(a.Replace(".zip", "").Replace(".rar", "").Replace(".7z", "").Replace(".exe", ""),
                            StringComparison.OrdinalIgnoreCase))
                    || CrasherBinaryKeywords.Any(k => fn.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (isCrasher)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V crasher recent document: {Path.GetFileName(lnk)}",
                        Risk = RiskLevel.Medium,
                        Location = recentDir,
                        FileName = Path.GetFileName(lnk),
                        Reason = $"Recent Documents shortcut '{fn}' points to an alt:V crasher or griefing tool file. " +
                                 "Recent Documents links are created when a file is opened by the user.",
                        Detail = $"Shortcut: {lnk}",
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckAltVCrasherTempArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var tempDirs = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        foreach (var tempDir in tempDirs)
        {
            if (!Directory.Exists(tempDir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(tempDir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    bool isCrasher = CrasherExecutables.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase))
                        || CrasherDlls.Any(d => fn.Equals(d, StringComparison.OrdinalIgnoreCase))
                        || CrasherDownloadArtifacts.Any(a => fn.Equals(a, StringComparison.OrdinalIgnoreCase));

                    if (isCrasher)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V crasher artifact in Temp: {fn}",
                            Risk = RiskLevel.High,
                            Location = tempDir,
                            FileName = fn,
                            Reason = $"Known alt:V crasher or griefing tool artifact '{fn}' found in system Temp directory. " +
                                     "Crash tools often extract or stage components in Temp directories before injection.",
                            Detail = $"Path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVCrasherPackageManifests(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var manifestFileNames = new[] { "resource.cfg", "resource.toml", "manifest.json", "package.json" };

        foreach (var root in AltVDataPaths)
        {
            var searchDirs = new[]
            {
                Path.Combine(root, "resources"),
                Path.Combine(root, "packages"),
                Path.Combine(root, "client_packages"),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var manifestName in manifestFileNames)
                {
                    IEnumerable<string> manifests;
                    try
                    {
                        manifests = Directory.EnumerateFiles(dir, manifestName, SearchOption.AllDirectories);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var manifest in manifests)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        string content;
                        try
                        {
                            using var fs = new FileStream(manifest, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }

                        var lower = content.ToLowerInvariant();
                        var matched = CrasherManifestKeywords
                            .Where(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matched.Count >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V crasher manifest: {Path.GetFileName(manifest)}",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(manifest) ?? dir,
                                FileName = Path.GetFileName(manifest),
                                Reason = $"Resource manifest '{Path.GetFileName(manifest)}' contains {matched.Count} crasher/griefing references " +
                                         $"({string.Join(", ", matched.Take(3))}). " +
                                         "Crash tool resources declare themselves in manifest files loaded by the alt:V runtime.",
                                Detail = $"Path: {manifest} | Patterns: {string.Join("|", matched)}",
                            });
                        }
                    }
                }
            }
        }
    }, ct);

    private Task CheckAltVCrasherAmcacheArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        // Scan HKCU Software for crasher tool registrations
        try
        {
            ctx.IncrementRegistryKeys();
            using var softKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE");
            if (softKey != null)
            {
                foreach (var subName in softKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var lower = subName.ToLowerInvariant();
                    if (CrasherAmcacheKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V crasher HKCU Software key: {subName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\SOFTWARE\{subName}",
                            FileName = subName,
                            Reason = $"HKCU\\SOFTWARE\\{subName} matches a known alt:V crasher or griefing tool name. " +
                                     "Crash tools often write configuration or activation keys under HKCU\\Software.",
                            Detail = $"Key: HKCU\\SOFTWARE\\{subName}",
                        });
                    }
                }
            }
        }
        catch (Exception) { }

        // Scan HKLM Software for crasher tool registrations
        try
        {
            ctx.IncrementRegistryKeys();
            using var softKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE");
            if (softKey != null)
            {
                foreach (var subName in softKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var lower = subName.ToLowerInvariant();
                    if (CrasherAmcacheKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V crasher HKLM Software key: {subName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\SOFTWARE\{subName}",
                            FileName = subName,
                            Reason = $"HKLM\\SOFTWARE\\{subName} matches a known alt:V crasher or griefing tool name. " +
                                     "System-wide HKLM registrations indicate a privileged or persistent crash tool installation.",
                            Detail = $"Key: HKLM\\SOFTWARE\\{subName}",
                        });
                    }
                }
            }
        }
        catch (Exception) { }

        // AppCompatCache (ShimCache) check
        var shimCachePaths = new[]
        {
            @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
            @"SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache",
        };

        foreach (var shimPath in shimCachePaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.LocalMachine.OpenSubKey(shimPath);
                if (key == null) continue;

                var cacheData = key.GetValue("AppCompatCache") as byte[];
                if (cacheData == null) continue;

                var cacheText = System.Text.Encoding.Unicode.GetString(cacheData).ToLowerInvariant();
                foreach (var keyword in CrasherAmcacheKeywords)
                {
                    if (cacheText.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V crasher in AppCompatCache (ShimCache)",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{shimPath}",
                            FileName = keyword,
                            Reason = $"AppCompatCache (ShimCache) contains reference to alt:V crasher keyword '{keyword}'. " +
                                     "ShimCache records all executables that have run on the system, surviving reboots and deletions.",
                            Detail = $"Key: HKLM\\{shimPath} | Keyword: {keyword}",
                        });
                        break;
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckAltVCrasherFirewallExceptions(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        // Check Windows Firewall rules for crasher tool exceptions
        try
        {
            ctx.IncrementRegistryKeys();
            using var fwKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
            if (fwKey != null)
            {
                foreach (var valName in fwKey.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    var data = fwKey.GetValue(valName)?.ToString() ?? string.Empty;
                    var lower = data.ToLowerInvariant();
                    bool isCrasher = CrasherNetworkKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                        || CrasherBinaryKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                        || CrasherExecutables.Any(e => lower.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase));
                    if (isCrasher)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V crasher firewall exception",
                            Risk = RiskLevel.High,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
                            FileName = valName,
                            Reason = "Windows Firewall contains an exception rule referencing an alt:V crasher or griefing tool. " +
                                     "DDoS and flood tools add firewall exceptions to allow outbound attack traffic.",
                            Detail = $"Rule: {valName} = {data.Substring(0, Math.Min(200, data.Length))}",
                        });
                    }
                }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckAltVCrasherWindowsDefenderExclusions(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var exclusionPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
        };

        foreach (var exPath in exclusionPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.LocalMachine.OpenSubKey(exPath);
                if (key == null) continue;
                foreach (var valName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    var lower = valName.ToLowerInvariant();
                    bool isCrasher = CrasherBinaryKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                        || CrasherExecutables.Any(e => lower.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase))
                        || lower.Contains("crasher") || lower.Contains("griefer") || lower.Contains("ddoser");
                    if (isCrasher)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V crasher in Defender exclusions",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{exPath}",
                            FileName = Path.GetFileName(valName),
                            Reason = $"Windows Defender exclusion references alt:V crasher or griefing tool path or process '{valName}'. " +
                                     "Adding Defender exclusions is a standard cheat evasion technique.",
                            Detail = $"Exclusion: {valName}",
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckAltVCrasherJumplistArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var recentDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", "Windows", "Recent", "AutomaticDestinations"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", "Windows", "Recent", "CustomDestinations"),
        };

        foreach (var dir in recentDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fi = new FileInfo(file);
                    if (fi.Length < 100) continue;

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        var buf = new byte[Math.Min(4096, fi.Length)];
                        int read = fs.Read(buf, 0, buf.Length);
                        var text = System.Text.Encoding.Unicode.GetString(buf, 0, read);
                        var lower = text.ToLowerInvariant();
                        bool hasCrasherRef = CrasherBinaryKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                            || CrasherExecutables.Any(e => lower.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase));
                        if (hasCrasherRef)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V crasher jumplist artifact: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Medium,
                                Location = dir,
                                FileName = Path.GetFileName(file),
                                Reason = "Windows Jumplist/AutomaticDestinations file references alt:V crasher or griefing tool strings. " +
                                         "Jumplist files record recently opened files and applications and survive executable deletion.",
                                Detail = $"Path: {file}",
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private static string Rot13Decode(string s)
    {
        return new string(s.Select(c =>
            c >= 'a' && c <= 'z' ? (char)('a' + (c - 'a' + 13) % 26) :
            c >= 'A' && c <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) : c).ToArray());
    }
}
