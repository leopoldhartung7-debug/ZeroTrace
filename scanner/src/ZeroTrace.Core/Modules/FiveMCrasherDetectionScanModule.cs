using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMCrasherDetectionScanModule : IScanModule
{
    public string Name => "FiveM Crasher & Griefing Tool Forensic Scan";
    public double Weight => 4.0;
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

    private static readonly string[] FiveMAppDataPaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FiveM"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM Application Data"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "FiveM Application Data"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CitizenFX"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CitizenFX"),
    ];

    private static readonly string[] FiveMCrasherExecutables =
    [
        "fivem_crasher.exe",
        "fivem_crash.exe",
        "fivem_crash_menu.exe",
        "fivem_crash_all.exe",
        "cfx_crasher.exe",
        "citizen_crasher.exe",
        "fivem_grief.exe",
        "fivem_griefer.exe",
        "fivem_troll.exe",
        "fivem_ddos.exe",
        "fivem_lag.exe",
        "fivem_lag_switch.exe",
        "fivem_lagswitch.exe",
        "fivem_freeze_all.exe",
        "fivem_kick_all.exe",
        "fivem_spectate_crash.exe",
        "crash_fivem.exe",
        "crash_cfx.exe",
        "cfx_crash.exe",
        "citizen_crash.exe",
        "fivem_vehicle_crash.exe",
        "fivem_entity_crash.exe",
        "fivem_spawn_crash.exe",
        "fivem_explosion_crash.exe",
        "fivem_event_crash.exe",
        "fivem_event_spam.exe",
        "cfx_event_spam.exe",
        "fivem_event_flood.exe",
        "fivem_native_crash.exe",
        "fivem_entity_flood.exe",
        "fivem_ped_crash.exe",
        "fivem_object_crash.exe",
        "fivem_net_crash.exe",
        "fivem_disconnect_all.exe",
        "fivem_timeout_crash.exe",
        "fivem_packet_flood.exe",
        "fivem_onesync_crash.exe",
        "fivem_state_crash.exe",
        "fivem_nui_crash.exe",
        "fivem_cef_crash.exe",
        "fivem_resource_crash.exe",
        "fivem_player_crash.exe",
        "fivem_all_crash.exe",
        "cfx_griefing.exe",
        "cfx_grief.exe",
        "cfx_troll.exe",
        "cfx_freeze.exe",
        "cfx_kick.exe",
        "cfx_ddos.exe",
        "cfx_lag.exe",
        "fivem_crasher_v2.exe",
        "fivem_crash_tool.exe",
        "fivem_crash_injector.exe",
        "fivem_grief_tool.exe",
    ];

    private static readonly string[] FiveMCrasherDlls =
    [
        "fivem_crash.dll",
        "fivem_crasher.dll",
        "cfx_crasher.dll",
        "crash_inject.dll",
        "crash_native.dll",
        "fivem_grief.dll",
        "fivem_griefer.dll",
        "fivem_troll.dll",
        "fivem_freeze.dll",
        "fivem_kick.dll",
        "fivem_lag.dll",
        "fivem_ddos.dll",
        "fivem_event_crash.dll",
        "fivem_event_spam.dll",
        "fivem_explosion_crash.dll",
        "fivem_vehicle_crash.dll",
        "fivem_entity_crash.dll",
        "fivem_native_crash.dll",
        "fivem_packet_flood.dll",
        "cfx_crash.dll",
        "cfx_grief.dll",
        "cfx_lag.dll",
        "cfx_freeze.dll",
        "citizen_crash.dll",
        "citizen_grief.dll",
        "crash_inject.dll",
        "griefing_inject.dll",
        "troll_inject.dll",
        "fivem_onesync_crash.dll",
        "fivem_state_crash.dll",
        "fivem_net_crash.dll",
    ];

    private static readonly string[] FiveMCrasherResourceNames =
    [
        "crash",
        "crasher",
        "griefmenu",
        "grief",
        "griefer",
        "troll",
        "trollmenu",
        "ddos",
        "freeze_all",
        "freezeall",
        "kick_all",
        "kickall",
        "spam",
        "exploiter",
        "lagswitch",
        "lag_switch",
        "eventspam",
        "event_spam",
        "event_flood",
        "entityspam",
        "entity_spam",
        "entityflood",
        "vehicle_spam",
        "vehiclespam",
        "explosion_spam",
        "explosionspam",
        "native_crash",
        "nativecrash",
        "player_crash",
        "playercrash",
        "onesync_crash",
        "onesyncrash",
        "packet_flood",
        "packetflood",
        "nui_crash",
        "nuicrash",
        "state_crash",
        "statecrash",
        "resource_crash",
        "resourcecrash",
        "disconnect_all",
        "disconnectall",
        "timeout_crash",
        "timeoutcrash",
        "cfx_crash",
        "cfxcrash",
        "cfx_grief",
        "cfxgrief",
        "grief_menu",
        "griefingmenu",
        "trolling",
        "troll_menu",
        "trollmenu",
        "net_crash",
        "netcrash",
    ];

    private static readonly string[] FiveMClientLogCrasherPatterns =
    [
        "crasher",
        "crash all",
        "grief menu",
        "griefing",
        "troll menu",
        "trolling",
        "freeze all",
        "kick all",
        "event spam",
        "event flood",
        "entity flood",
        "explosion spam",
        "vehicle spam",
        "packet flood",
        "ddos fivem",
        "ddos cfx",
        "lag switch",
        "crash tool",
        "crash injector",
        "crash native",
        "native crash",
        "onesync crash",
        "state bag crash",
        "nui crash",
        "cef crash",
        "net crash",
        "player crash",
        "crash player",
        "crash exploit",
        "exploit crash",
        "crash menu loaded",
        "griefmenu loaded",
        "crash module",
        "crasher module",
        "freeze exploit",
        "kick exploit",
        "disconnect exploit",
        "timeout exploit",
        "resource crash",
        "resource flood",
        "script crash",
        "cfx exploit",
        "citizen exploit",
    ];

    private static readonly string[] FiveMServerLogCrasherPatterns =
    [
        "player crash",
        "crash exploit",
        "crash detected",
        "griefing detected",
        "grief detected",
        "event spam",
        "event flood",
        "event rate limit exceeded",
        "explosion spam",
        "entity spam",
        "entity flood",
        "vehicle spam",
        "vehicle flood",
        "resource exploit",
        "resource crash",
        "onesync exploit",
        "onesync crash",
        "state bag exploit",
        "state bag crash",
        "native exploit",
        "native crash",
        "nui exploit",
        "nui crash",
        "net crash",
        "packet flood",
        "kicked for crash",
        "banned for crash",
        "banned for griefing",
        "kicked for griefing",
        "banned for exploit",
        "kicked for exploit",
        "crash ban",
        "grief ban",
        "anti-grief",
        "anticheat: crash",
        "anticheat: grief",
        "crash script",
        "crash resource",
        "kicked for event spam",
        "banned for event spam",
        "disconnect exploit",
        "timeout exploit",
        "connection exploit",
        "cfx exploit",
        "citizen exploit",
        "freeze all players",
        "kick all players",
        "crash all players",
    ];

    private static readonly string[] FiveMResourceLuaCheatPatterns =
    [
        "AddExplosion(",
        "AddOwnedExplosion(",
        "NetworkExplodeVehicle(",
        "TriggerNetworkEvent(",
        "TriggerServerEvent(",
        "TriggerClientEvent(",
        "CreateVehicle(",
        "CreatePed(",
        "CreateObject(",
        "SetEntityCoords(",
        "SetEntityVelocity(",
        "SetEntityHealth(0",
        "SetPlayerInvincible(",
        "GiveWeaponToPed(",
        "SetEntityOnFire(",
        "StartNetworkFiring(",
        "NetworkRequestControlOfEntity(",
        "SetEntityMaxSpeed(",
        "TaskLeaveVehicle(",
        "NetworkFadeInEntity(",
        "NetworkRegisterEntityAsNetworked(",
        "RemoveAllPedWeapons(",
        "KillPed(",
        "DeleteEntity(",
        "DeleteVehicle(",
        "SendNUIMessage(",
        "RegisterNetEvent(",
        "PerformHttpRequestInternal(",
        "ExecuteCommand(",
        "crashPlayer",
        "kickPlayer",
        "freezePlayer",
        "grief(",
        "spam(",
        "flood(",
        "exploitCrash(",
        "nativeCrash(",
        "eventFlood(",
    ];

    private static readonly string[] FiveMResourceJsCheatPatterns =
    [
        "AddExplosion(",
        "NetworkExplodeVehicle(",
        "TriggerNetworkEvent(",
        "TriggerServerEvent(",
        "TriggerClientEvent(",
        "CreateVehicle(",
        "CreatePed(",
        "CreateObject(",
        "SetEntityCoords(",
        "SetEntityVelocity(",
        "SetEntityHealth(",
        "SetPlayerInvincible(",
        "GiveWeaponToPed(",
        "invokeNative(",
        "callNative(",
        "global.exports",
        "on('crash'",
        "on(\"crash\"",
        "emit('crash'",
        "emit(\"crash\"",
        "on('grief'",
        "on(\"grief\"",
        "emit('grief'",
        "emit(\"grief\"",
        "crashPlayer(",
        "kickAllPlayers(",
        "freezeAllPlayers(",
        "eventFlood(",
        "entitySpam(",
        "explosionSpam(",
        "vehicleSpam(",
        "packetFlood(",
        "nuiCrash(",
        "statecrash(",
        "onesyncCrash(",
        "netCrash(",
        "resourceCrash(",
    ];

    private static readonly string[] FiveMCrasherDownloadArtifacts =
    [
        "fivem_crasher.zip",
        "fivem_crash.zip",
        "fivem_crasher.rar",
        "fivem_crash.rar",
        "fivem_crasher.7z",
        "fivem_crash.7z",
        "fivem_grief.zip",
        "fivem_grief.rar",
        "fivem_grief.7z",
        "fivem_griefer.zip",
        "fivem_griefer.rar",
        "fivem_troll.zip",
        "fivem_troll.rar",
        "fivem_crash_menu.zip",
        "fivem_crash_menu.rar",
        "cfx_crasher.zip",
        "cfx_crasher.rar",
        "cfx_crasher.7z",
        "crash_fivem.zip",
        "crash_fivem.rar",
        "crash_cfx.zip",
        "crash_cfx.rar",
        "fivem_ddos.zip",
        "fivem_ddos.rar",
        "fivem_ddos.7z",
        "fivem_lag.zip",
        "fivem_lag.rar",
        "fivem_freeze_all.zip",
        "fivem_freeze_all.rar",
        "fivem_kick_all.zip",
        "fivem_kick_all.rar",
        "fivem_event_crash.zip",
        "fivem_event_spam.zip",
        "fivem_explosion_crash.zip",
        "fivem_vehicle_crash.zip",
        "fivem_crasher_v2.zip",
        "fivem_crash_tool.zip",
        "fivem_grief_tool.zip",
        "fivem_crasher_setup.exe",
        "fivem_crash_setup.exe",
        "fivem_grief_setup.exe",
        "cfx_crasher_setup.exe",
    ];

    private static readonly string[] FiveMCrasherRegistryCheatKeys =
    [
        @"SOFTWARE\FiveMCrasher",
        @"SOFTWARE\FiveMCrash",
        @"SOFTWARE\FiveMGrief",
        @"SOFTWARE\FiveMGriefer",
        @"SOFTWARE\FiveMTroll",
        @"SOFTWARE\FiveMDDoS",
        @"SOFTWARE\FiveMFreeze",
        @"SOFTWARE\FiveMKick",
        @"SOFTWARE\CFXCrasher",
        @"SOFTWARE\CFXCrash",
        @"SOFTWARE\CFXGrief",
        @"SOFTWARE\CitizenCrasher",
        @"SOFTWARE\FiveMEventSpam",
        @"SOFTWARE\FiveMExplosionSpam",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckFiveMCrasherExecutables(ctx, ct),
            CheckFiveMCrasherDlls(ctx, ct),
            CheckFiveMCrasherResourceFolders(ctx, ct),
            CheckFiveMClientLogsForCrasherEvidence(ctx, ct),
            CheckFiveMServerLogsForCrashExploits(ctx, ct),
            CheckFiveMResourceLuaFilesForCrashPatterns(ctx, ct),
            CheckFiveMResourceJsFilesForCrashPatterns(ctx, ct),
            CheckFiveMCrasherDownloadArtifacts(ctx, ct),
            CheckRegistryKeysForFiveMCrashers(ctx, ct),
            CheckUserAssistForFiveMCrashers(ctx, ct),
            CheckMuiCacheForFiveMCrashers(ctx, ct),
            CheckFiveMCrasherInstallerRecords(ctx, ct),
            CheckFiveMCrasherRecentDocuments(ctx, ct),
            CheckFiveMRunKeysForCrashers(ctx, ct),
            CheckFiveMCacheForCrasherDlls(ctx, ct),
            CheckFiveMCrasherConfigFiles(ctx, ct)
        );
    }

    private Task CheckFiveMCrasherExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(FiveMAppDataPaths)
        {
            Path.Combine(UserProfile, "Downloads"),
            Desktop,
            Path.Combine(LocalAppData, "Temp"),
            Path.Combine(UserProfile, "Documents"),
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
                    if (FiveMCrasherExecutables.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM crasher/griefing executable detected",
                            Risk = RiskLevel.Critical,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known FiveM crasher or griefing tool executable '{fn}' found on disk. These tools are designed to crash or grief other players on FiveM/CFX servers by flooding the game with exploitative native calls, events, or network packets.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckFiveMCrasherDlls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(FiveMAppDataPaths)
        {
            Path.Combine(UserProfile, "Downloads"),
            Desktop,
            Path.Combine(LocalAppData, "Temp"),
            Path.Combine(UserProfile, "Documents"),
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
                    if (FiveMCrasherDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM crasher DLL detected",
                            Risk = RiskLevel.Critical,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known FiveM crasher DLL '{fn}' found on disk. Crasher DLLs are injected into the FiveM process to send exploitative native calls or network events that crash or freeze other players on the server.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckFiveMCrasherResourceFolders(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var fiveMDir in FiveMAppDataPaths)
        {
            var fiveMAppDir = Path.Combine(fiveMDir, "FiveM.app");
            var resourceCandidates = new[]
            {
                Path.Combine(fiveMDir, "resources"),
                Path.Combine(fiveMAppDir, "resources"),
                Path.Combine(fiveMDir, "citizen", "resources"),
                Path.Combine(fiveMAppDir, "citizen", "resources"),
                Path.Combine(fiveMDir, "plugins"),
            };

            foreach (var resourceDir in resourceCandidates)
            {
                if (!Directory.Exists(resourceDir)) continue;
                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(resourceDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        var folderName = Path.GetFileName(dir);
                        if (FiveMCrasherResourceNames.Any(k =>
                            folderName.Equals(k, StringComparison.OrdinalIgnoreCase) ||
                            folderName.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Suspicious FiveM resource folder (crasher/griefing)",
                                Risk = RiskLevel.High,
                                Location = resourceDir,
                                FileName = folderName,
                                Reason = $"FiveM resource folder '{folderName}' matches known crasher or griefing resource naming patterns. Crasher resources are Lua/JS FiveM resources that flood explosions, events, or entities to crash or grief other players.",
                                Detail = $"Resource path: {dir}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckFiveMClientLogsForCrasherEvidence(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var fiveMDir in FiveMAppDataPaths)
        {
            if (!Directory.Exists(fiveMDir)) continue;
            try
            {
                var logFiles = Directory.EnumerateFiles(fiveMDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(fiveMDir, "*.txt", SearchOption.AllDirectories));

                foreach (var logFile in logFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        foreach (var pattern in FiveMClientLogCrasherPatterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "FiveM client log: crasher/griefing tool artifact",
                                    Risk = RiskLevel.High,
                                    Location = Path.GetDirectoryName(logFile) ?? fiveMDir,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"FiveM client log contains crasher/griefing tool evidence: '{pattern}'. Client logs may record crasher module load messages, griefing menu activations, or exploit tool startup output.",
                                    Detail = $"Log file: {logFile}, matched pattern: {pattern}"
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckFiveMServerLogsForCrashExploits(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var serverLogDirs = new[]
        {
            Path.Combine(UserProfile, "FXServer", "server-data", "logs"),
            Path.Combine(UserProfile, "cfx-server-data", "logs"),
            Path.Combine(UserProfile, "fivem-server", "logs"),
            Path.Combine(UserProfile, "fivem_server", "logs"),
            Path.Combine(UserProfile, "Documents", "FXServer", "logs"),
            Path.Combine(UserProfile, "Documents", "cfx-server-data", "logs"),
            Path.Combine(UserProfile, "Documents", "fivem-server", "logs"),
            @"C:\FXServer\server-data\logs",
            @"C:\cfx-server-data\logs",
            @"C:\fivem-server\logs",
            @"C:\fivem_server\logs",
            @"C:\txData\logs",
        };

        foreach (var logDir in serverLogDirs)
        {
            if (!Directory.Exists(logDir)) continue;
            try
            {
                var logFiles = Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(logDir, "*.txt", SearchOption.AllDirectories));

                foreach (var logFile in logFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        foreach (var pattern in FiveMServerLogCrasherPatterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "FiveM server log: crash exploit record",
                                    Risk = RiskLevel.High,
                                    Location = logDir,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"FiveM server log contains a crash exploit detection record: '{pattern}'. Server logs record crash exploit detections, anti-grief triggers, and bans/kicks for crasher or griefing tool use.",
                                    Detail = $"Log file: {logFile}, matched pattern: {pattern}"
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckFiveMResourceLuaFilesForCrashPatterns(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var fiveMDir in FiveMAppDataPaths)
        {
            var fiveMAppDir = Path.Combine(fiveMDir, "FiveM.app");
            var resourceCandidates = new[]
            {
                Path.Combine(fiveMDir, "resources"),
                Path.Combine(fiveMAppDir, "resources"),
                Path.Combine(fiveMDir, "citizen", "resources"),
            };

            foreach (var resourceDir in resourceCandidates)
            {
                if (!Directory.Exists(resourceDir)) continue;
                try
                {
                    var luaFiles = Directory.EnumerateFiles(resourceDir, "*.lua", SearchOption.AllDirectories)
                        .Concat(Directory.EnumerateFiles(resourceDir, "*.luac", SearchOption.AllDirectories));

                    foreach (var luaFile in luaFiles)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            var lower = content.ToLowerInvariant();
                            int hits = 0;
                            string firstMatch = string.Empty;
                            foreach (var pattern in FiveMResourceLuaCheatPatterns)
                            {
                                if (lower.Contains(pattern.ToLowerInvariant()))
                                {
                                    hits++;
                                    if (firstMatch.Length == 0) firstMatch = pattern;
                                }
                            }
                            if (hits >= 3)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "FiveM Lua resource with crash/grief patterns",
                                    Risk = RiskLevel.Critical,
                                    Location = Path.GetDirectoryName(luaFile) ?? resourceDir,
                                    FileName = Path.GetFileName(luaFile),
                                    Reason = $"FiveM Lua resource file contains {hits} crash or griefing patterns (first match: '{firstMatch}'). Crasher Lua scripts abuse AddExplosion, NetworkExplodeVehicle, TriggerNetworkEvent and similar natives in rapid loops to crash or grief other players.",
                                    Detail = $"File: {luaFile}, pattern hits: {hits}"
                                });
                            }
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckFiveMResourceJsFilesForCrashPatterns(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var fiveMDir in FiveMAppDataPaths)
        {
            var fiveMAppDir = Path.Combine(fiveMDir, "FiveM.app");
            var resourceCandidates = new[]
            {
                Path.Combine(fiveMDir, "resources"),
                Path.Combine(fiveMAppDir, "resources"),
                Path.Combine(fiveMDir, "citizen", "resources"),
            };

            foreach (var resourceDir in resourceCandidates)
            {
                if (!Directory.Exists(resourceDir)) continue;
                try
                {
                    var jsFiles = Directory.EnumerateFiles(resourceDir, "*.js", SearchOption.AllDirectories)
                        .Concat(Directory.EnumerateFiles(resourceDir, "*.mjs", SearchOption.AllDirectories))
                        .Concat(Directory.EnumerateFiles(resourceDir, "*.ts", SearchOption.AllDirectories));

                    foreach (var jsFile in jsFiles)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            var lower = content.ToLowerInvariant();
                            int hits = 0;
                            string firstMatch = string.Empty;
                            foreach (var pattern in FiveMResourceJsCheatPatterns)
                            {
                                if (lower.Contains(pattern.ToLowerInvariant()))
                                {
                                    hits++;
                                    if (firstMatch.Length == 0) firstMatch = pattern;
                                }
                            }
                            if (hits >= 3)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "FiveM JS resource with crash/grief patterns",
                                    Risk = RiskLevel.Critical,
                                    Location = Path.GetDirectoryName(jsFile) ?? resourceDir,
                                    FileName = Path.GetFileName(jsFile),
                                    Reason = $"FiveM JavaScript resource file contains {hits} crash or griefing patterns (first match: '{firstMatch}'). Crasher JS scripts invoke game natives through FiveM's JavaScript runtime to send explosion floods, event spam, or entity floods that crash or grief players.",
                                    Detail = $"File: {jsFile}, pattern hits: {hits}"
                                });
                            }
                        }
                        catch (IOException) { }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckFiveMCrasherDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (FiveMCrasherDownloadArtifacts.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM crasher/griefing tool download artifact",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"FiveM crasher or griefing tool archive/installer '{fn}' found in {dir}. Downloaded crasher packages provide forensic evidence of prior acquisition of tools designed to crash or grief FiveM/CFX servers.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRegistryKeysForFiveMCrashers(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var keyPath in FiveMCrasherRegistryCheatKeys)
        {
            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM crasher registry key",
                        Risk = RiskLevel.High,
                        Location = @"HKCU\" + keyPath,
                        FileName = string.Empty,
                        Reason = $"Registry key '{keyPath}' was left behind by a FiveM crasher or griefing tool installation. These keys indicate a crasher tool was run on this machine and may have written configuration or license data.",
                        Detail = $"Key: HKCU\\{keyPath}"
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
                        Title = "FiveM crasher registry key (HKLM)",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\" + keyPath,
                        FileName = string.Empty,
                        Reason = $"System-level registry key '{keyPath}' was left behind by a FiveM crasher tool. System-level keys indicate the crasher ran with administrator privileges, which is common for injector-based crash tools.",
                        Detail = $"Key: HKLM\\{keyPath}"
                    });
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckUserAssistForFiveMCrashers(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        const string uaPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        try
        {
            using var ua = Registry.CurrentUser.OpenSubKey(uaPath);
            if (ua == null) return;
            foreach (var guidName in ua.GetSubKeyNames())
            {
                try
                {
                    using var count = Registry.CurrentUser.OpenSubKey($@"{uaPath}\{guidName}\Count");
                    if (count == null) continue;
                    foreach (var valName in count.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();
                        var decoded = Rot13Decode(valName);
                        var lower = decoded.ToLowerInvariant();
                        bool isCrasher = FiveMCrasherExecutables.Any(k =>
                                lower.Contains(k.Replace(".exe", string.Empty), StringComparison.OrdinalIgnoreCase))
                            || lower.Contains("fivem crash")
                            || lower.Contains("fivem crasher")
                            || lower.Contains("fivem grief")
                            || lower.Contains("fivem troll")
                            || lower.Contains("fivem ddos")
                            || lower.Contains("fivem lag")
                            || lower.Contains("fivem freeze")
                            || lower.Contains("fivem kick")
                            || lower.Contains("cfx crash")
                            || lower.Contains("cfx crasher")
                            || lower.Contains("cfx grief")
                            || lower.Contains("crash fivem")
                            || lower.Contains("crash cfx");
                        if (isCrasher)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM crasher execution (UserAssist)",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{uaPath}\{guidName}\Count",
                                FileName = decoded,
                                Reason = $"Windows UserAssist registry records execution of a FiveM crasher or griefing tool: '{decoded}'. UserAssist tracks every GUI program ever launched by the user and is a reliable forensic indicator of prior crash tool execution.",
                                Detail = $"Decoded entry: {decoded}"
                            });
                        }
                    }
                }
                catch (Exception) { }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckMuiCacheForFiveMCrashers(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                using var mui = Registry.CurrentUser.OpenSubKey(muiPath);
                if (mui == null) continue;
                foreach (var valName in mui.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    var lower = valName.ToLowerInvariant();
                    bool isCrasher = FiveMCrasherExecutables.Any(k =>
                            lower.Contains(k.Replace(".exe", string.Empty), StringComparison.OrdinalIgnoreCase))
                        || lower.Contains("fivem crash")
                        || lower.Contains("fivem crasher")
                        || lower.Contains("fivem grief")
                        || lower.Contains("fivem troll")
                        || lower.Contains("fivem ddos")
                        || lower.Contains("fivem lag")
                        || lower.Contains("fivem freeze")
                        || lower.Contains("cfx crash")
                        || lower.Contains("cfx crasher")
                        || lower.Contains("cfx grief")
                        || lower.Contains("crash fivem")
                        || lower.Contains("crash cfx");
                    if (isCrasher)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM crasher execution (MUICache)",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\" + muiPath,
                            FileName = Path.GetFileName(valName),
                            Reason = $"Windows MUICache records a FiveM crasher or griefing tool was executed: '{valName}'. MUICache persists the name of every EXE run on the system and is a forensic artifact that survives file deletion.",
                            Detail = $"MUICache entry: {valName}"
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckFiveMCrasherInstallerRecords(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                using var uninst = Registry.LocalMachine.OpenSubKey(uninstallPath);
                if (uninst == null) continue;
                foreach (var subKeyName in uninst.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var sub = uninst.OpenSubKey(subKeyName);
                        var displayName = sub?.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        var installLocation = sub?.GetValue("InstallLocation")?.ToString() ?? string.Empty;
                        var lower = displayName.ToLowerInvariant();
                        var locLower = installLocation.ToLowerInvariant();
                        bool isCrasher = lower.Contains("fivem crash")
                            || lower.Contains("fivem crasher")
                            || lower.Contains("fivem grief")
                            || lower.Contains("fivem troll")
                            || lower.Contains("fivem ddos")
                            || lower.Contains("cfx crash")
                            || lower.Contains("cfx crasher")
                            || lower.Contains("cfx grief")
                            || lower.Contains("crash fivem")
                            || locLower.Contains("fivem crash")
                            || locLower.Contains("fivem crasher")
                            || locLower.Contains("cfx crash");
                        if (isCrasher)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM crasher installer record",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                FileName = displayName,
                                Reason = $"Uninstall registry record found for FiveM crasher or griefing software: '{displayName}'. This indicates a crash tool was formally installed on this system via an installer package.",
                                Detail = $"Key: {subKeyName}, DisplayName: {displayName}, Location: {installLocation}"
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckFiveMCrasherRecentDocuments(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var recentDir = Path.Combine(AppData, "Microsoft", "Windows", "Recent");
        if (!Directory.Exists(recentDir)) return;
        try
        {
            foreach (var lnk in Directory.EnumerateFiles(recentDir, "*.lnk", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileNameWithoutExtension(lnk).ToLowerInvariant();
                bool isCrasher = fn.Contains("fivem crash")
                    || fn.Contains("fivem crasher")
                    || fn.Contains("fivem grief")
                    || fn.Contains("fivem troll")
                    || fn.Contains("fivem ddos")
                    || fn.Contains("fivem lag")
                    || fn.Contains("fivem freeze")
                    || fn.Contains("cfx crash")
                    || fn.Contains("cfx crasher")
                    || fn.Contains("cfx grief")
                    || fn.Contains("crash fivem")
                    || fn.Contains("crash cfx")
                    || FiveMCrasherDownloadArtifacts.Any(k =>
                        fn.Contains(k.Replace(".exe", string.Empty)
                            .Replace(".zip", string.Empty)
                            .Replace(".rar", string.Empty)
                            .Replace(".7z", string.Empty), StringComparison.OrdinalIgnoreCase));
                if (isCrasher)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM crasher recent document artifact",
                        Risk = RiskLevel.Medium,
                        Location = recentDir,
                        FileName = Path.GetFileName(lnk),
                        Reason = $"Windows Recent Documents folder contains a shortcut to a FiveM crasher or griefing tool file: '{fn}'. Recent Documents tracks file access history and is a forensic artifact indicating prior interaction with crash tool files.",
                        Detail = $"Shortcut: {lnk}"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckFiveMRunKeysForCrashers(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var runKeyPaths = new[]
        {
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine, "HKLM"),
        };

        foreach (var (keyPath, hive, hiveName) in runKeyPaths)
        {
            try
            {
                ctx.IncrementRegistryKeys();
                using var run = hive.OpenSubKey(keyPath);
                if (run == null) continue;
                foreach (var val in run.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var data = run.GetValue(val)?.ToString() ?? string.Empty;
                    var lower = data.ToLowerInvariant();
                    bool isCrasher = lower.Contains("fivem crash")
                        || lower.Contains("fivem crasher")
                        || lower.Contains("fivem grief")
                        || lower.Contains("fivem troll")
                        || lower.Contains("fivem ddos")
                        || lower.Contains("fivem lag")
                        || lower.Contains("fivem freeze")
                        || lower.Contains("cfx crash")
                        || lower.Contains("cfx crasher")
                        || lower.Contains("cfx grief")
                        || lower.Contains("crash fivem")
                        || lower.Contains("crash cfx")
                        || FiveMCrasherExecutables.Any(k =>
                            lower.Contains(k.Replace(".exe", string.Empty), StringComparison.OrdinalIgnoreCase));
                    if (isCrasher)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM crasher autostart (Run key)",
                            Risk = RiskLevel.High,
                            Location = $@"{hiveName}\{keyPath}",
                            FileName = val,
                            Reason = $"FiveM crasher or griefing tool configured to auto-start via Windows Run registry key. Value '{val}' points to: '{data}'. Autostart entries indicate persistent installation of a crash tool.",
                            Detail = $"Value: {val} = {data}"
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckFiveMCacheForCrasherDlls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var fiveMDir in FiveMAppDataPaths)
        {
            var fiveMAppDir = Path.Combine(fiveMDir, "FiveM.app");
            var cacheDirs = new[]
            {
                Path.Combine(fiveMDir, "cache"),
                Path.Combine(fiveMAppDir, "cache"),
                Path.Combine(fiveMDir, "data"),
                Path.Combine(fiveMAppDir, "data"),
                Path.Combine(fiveMDir, "plugins"),
                Path.Combine(fiveMAppDir, "plugins"),
                Path.Combine(fiveMDir, "citizen"),
                Path.Combine(fiveMAppDir, "citizen"),
            };

            foreach (var cacheDir in cacheDirs)
            {
                if (!Directory.Exists(cacheDir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(cacheDir, "*.dll", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        if (FiveMCrasherDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Crasher DLL inside FiveM cache/data folder",
                                Risk = RiskLevel.Critical,
                                Location = Path.GetDirectoryName(file) ?? cacheDir,
                                FileName = fn,
                                Reason = $"Known FiveM crasher DLL '{fn}' found inside the FiveM application cache or plugin folder. Crasher tools sometimes store their DLLs inside the FiveM directory for persistent loading and to evade simple file-path-based detection.",
                                Detail = $"Full path: {file}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckFiveMCrasherConfigFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var crasherConfigNames = new[]
        {
            "fivem_crasher_config.json",
            "fivem_crash_config.json",
            "fivem_grief_config.json",
            "fivem_griefing_config.json",
            "fivem_troll_config.json",
            "fivem_ddos_config.json",
            "fivem_lag_config.json",
            "fivem_freeze_config.json",
            "fivem_kick_config.json",
            "fivem_event_spam_config.json",
            "fivem_explosion_config.json",
            "fivem_entity_flood_config.json",
            "cfx_crasher_config.json",
            "cfx_crash_config.json",
            "cfx_grief_config.json",
            "crash_config.json",
            "griefmenu_config.json",
            "grief_config.json",
            "troll_config.json",
            "crasher_settings.json",
            "crasher_settings.ini",
            "griefmenu_settings.json",
            "griefmenu_settings.ini",
            "fivem_crasher.cfg",
            "fivem_crash.cfg",
            "cfx_crasher.cfg",
            "crasher.cfg",
            "griefmenu.cfg",
            "fivem_crasher_offsets.txt",
            "fivem_crash_offsets.txt",
            "fivem_crash_natives.json",
            "fivem_grief_natives.json",
        };

        var scanDirs = new List<string>(FiveMAppDataPaths)
        {
            Path.Combine(UserProfile, "Downloads"),
            Desktop,
            Path.Combine(LocalAppData, "Temp"),
            Path.Combine(UserProfile, "Documents"),
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
                    if (crasherConfigNames.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM crasher configuration file",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"FiveM crasher or griefing tool configuration file '{fn}' found. These files store crasher settings including target server IPs, explosion types, event flood rates, entity spawn parameters, or native crash sequences used by the tool.",
                            Detail = $"Full path: {file}"
                        });
                    }
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
