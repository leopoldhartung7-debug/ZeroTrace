using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class RageMPDeepForensicScanModule : IScanModule
{
    public string Name => "RageMP Deep Cheat Forensic Scan";
    public double Weight => 4.1;
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

    private static readonly string[] RageMPAppDataPaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RAGEMP"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RAGEMP"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ragemp"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ragemp"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "rage-multiplayer"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "rage-multiplayer"),
    ];

    private static readonly string[] RageMPCheatExecutables =
    [
        "ragemp_cheat.exe",
        "ragemp_hack.exe",
        "ragemp_menu.exe",
        "ragemp_modmenu.exe",
        "ragemp_trainer.exe",
        "ragemp_esp.exe",
        "ragemp_aimbot.exe",
        "ragemp_wallhack.exe",
        "ragemp_godmode.exe",
        "ragemp_noclip.exe",
        "ragemp_speed.exe",
        "ragemp_speedhack.exe",
        "ragemp_teleport.exe",
        "ragemp_money.exe",
        "ragemp_bypass.exe",
        "ragemp_inject.exe",
        "ragemp_injector.exe",
        "ragemp_internal.exe",
        "ragemp_external.exe",
        "gta5_ragemp_cheat.exe",
        "gta5_ragemp_hack.exe",
        "rage_cheat.exe",
        "rage_hack.exe",
        "rage_menu.exe",
        "rage_modmenu.exe",
        "rage_trainer.exe",
        "rage_esp.exe",
        "rage_aimbot.exe",
        "rage_wallhack.exe",
        "rage_godmode.exe",
        "rage_noclip.exe",
        "rage_bypass.exe",
        "rage_inject.exe",
        "ragemp_exploit.exe",
        "ragemp_recovery.exe",
        "ragemp_native_exec.exe",
        "ragemp_lua_exec.exe",
        "ragemp_js_exec.exe",
        "ragemp_client_exec.exe",
        "ragemp_dumper.exe",
        "ragemp_vehicle.exe",
        "ragemp_weapon.exe",
        "ragemp_spawnmenu.exe",
        "ragemp_fly.exe",
        "ragemp_flasher.exe",
        "ragemp_evader.exe",
        "ragemp_anticheat_bypass.exe",
        "ragemp_radar.exe",
        "ragemp_maphack.exe",
        "ragemp_cash.exe",
        "ragemp_rp_boost.exe",
        "ragemp_freeze.exe",
        "ragemp_kick.exe",
        "ragemp_crasher.exe",
        "ragemp_spinbot.exe",
        "ragemp_triggerbot.exe",
        "ragemp_bunnyhop.exe",
    ];

    private static readonly string[] RageMPCheatDlls =
    [
        "ragemp_bypass.dll",
        "ragemp_anticheat_bypass.dll",
        "ragemp_evader.dll",
        "ragemp_hook.dll",
        "ragemp_cheat.dll",
        "ragemp_hack.dll",
        "ragemp_inject.dll",
        "ragemp_esp.dll",
        "ragemp_aimbot.dll",
        "ragemp_wallhack.dll",
        "ragemp_godmode.dll",
        "ragemp_noclip.dll",
        "ragemp_speed.dll",
        "ragemp_teleport.dll",
        "ragemp_fly.dll",
        "ragemp_money.dll",
        "ragemp_vehicle.dll",
        "ragemp_weapon.dll",
        "ragemp_crash.dll",
        "ragemp_native.dll",
        "ragemp_lua.dll",
        "ragemp_js.dll",
        "ragemp_script.dll",
        "ragemp_internal.dll",
        "ragemp_external.dll",
        "ragemp_d3d.dll",
        "ragemp_overlay.dll",
        "ragemp_radar.dll",
        "ragemp_maphack.dll",
        "ragemp_bypasser.dll",
        "ragemp_evader.dll",
        "ragemp_antiac.dll",
        "rage_bypass.dll",
        "rage_hook.dll",
        "rage_inject.dll",
        "rage_cheat.dll",
    ];

    private static readonly string[] RageMPPackageInjectionFiles =
    [
        "ragemp_packages_inject.exe",
        "ragemp_node_inject.exe",
        "ragemp_clientscript_inject.dll",
        "ragemp_package_loader.exe",
        "ragemp_cef_inject.exe",
        "ragemp_cef_bypass.dll",
        "ragemp_node_bypass.dll",
        "ragemp_package_inject.dll",
        "ragemp_npm_inject.exe",
        "ragemp_script_inject.dll",
        "ragemp_clientpackage_inject.exe",
    ];

    private static readonly string[] RageMPConfigArtifacts =
    [
        "ragemp_cheat_config.json",
        "ragemp_offsets.json",
        "ragemp_addresses.txt",
        "ragemp_offsets.txt",
        "ragemp_patterns.txt",
        "ragemp_natives.json",
        "ragemp_native_list.txt",
        "ragemp_functions.json",
        "ragemp_structs.txt",
        "ragemp_cheat_settings.json",
        "ragemp_hack_config.json",
        "ragemp_aimbot_config.json",
        "ragemp_esp_config.json",
        "ragemp_bypass_config.json",
        "ragemp_menu_config.json",
        "ragemp_trainer_config.json",
        "ragemp_modmenu_config.json",
        "ragemp_sdk_offsets.txt",
        "ragemp_class_list.txt",
        "gta5_ragemp_offsets.txt",
        "gta5_ragemp_addresses.json",
        "rage_offsets.json",
        "rage_addresses.txt",
        "rage_patterns.txt",
    ];

    private static readonly string[] RageMPCheatPackageNames =
    [
        "ragemp-cheat",
        "ragemp-hack",
        "ragemp-menu",
        "ragemp-modmenu",
        "ragemp-trainer",
        "ragemp-godmode",
        "ragemp-noclip",
        "ragemp-speedhack",
        "ragemp-aimbot",
        "ragemp-esp",
        "ragemp-teleport",
        "ragemp-fly",
        "ragemp-money",
        "ragemp-vehicle",
        "ragemp-weapon",
        "ragemp-crasher",
        "ragemp-bypass",
        "ragemp-evader",
        "ragemp-inject",
        "ragemp-exploit",
        "ragemp-recovery",
        "ragemp-native-exec",
        "ragemp-lua-exec",
        "ragemp-js-exec",
        "ragemp-anticheat-bypass",
        "ragemp-radar",
        "ragemp-maphack",
        "rage-cheat",
        "rage-hack",
        "rage-menu",
        "rage-bypass",
        "cheat",
        "hack",
        "modmenu",
        "trainer",
        "godmode",
        "noclip",
        "speedhack",
        "aimbot",
        "esp",
        "wallhack",
        "bypass",
        "evader",
        "exploiter",
        "money_drop",
        "weapon_give",
        "vehicle_spawn",
        "teleport_menu",
        "fly_hack",
        "anticheat_bypass",
    ];

    private static readonly string[] RageMPClientLogCheatPatterns =
    [
        "ragemp cheat",
        "ragemp hack",
        "ragemp bypass",
        "ragemp exploit",
        "cheat menu",
        "mod menu",
        "godmode enabled",
        "noclip enabled",
        "speedhack enabled",
        "aimbot enabled",
        "esp enabled",
        "wallhack enabled",
        "teleport hack",
        "fly hack",
        "money cheat",
        "vehicle spam",
        "native exec",
        "native bypass",
        "anticheat bypass",
        "bypass anticheat",
        "evader loaded",
        "evade rage",
        "rage bypass",
        "packages injected",
        "client script injected",
        "cef injected",
        "node injected",
        "inject success",
        "hooked rage",
        "hook installed",
        "rage hook",
        "spinbot",
        "triggerbot",
        "bunnyhop",
        "aim assist",
        "player esp",
        "vehicle esp",
        "bone aim",
        "silent aim",
        "rage cheat",
    ];

    private static readonly string[] RageMPServerLogCheatPatterns =
    [
        "cheat detected",
        "hack detected",
        "exploit detected",
        "godmode detected",
        "speedhack detected",
        "teleport detected",
        "aimbot detected",
        "esp detected",
        "noclip detected",
        "vehicle spawn spam",
        "weapon spawn spam",
        "money cheat detected",
        "invalid native",
        "native blocked",
        "illegal native call",
        "native exploit",
        "package exploit",
        "script exploit",
        "event exploit",
        "event spam",
        "event flood",
        "event rate limit",
        "client crash",
        "player crash",
        "crash exploit",
        "ban for cheating",
        "kick for cheating",
        "ban reason: cheat",
        "kick reason: cheat",
        "detected cheat",
        "banned cheater",
        "package injection",
        "injected package",
        "unauthorized package",
        "package blacklisted",
        "package blocked",
        "cef bypass",
        "node bypass",
        "rage bypass detected",
        "ragemp bypass",
        "anticheat triggered",
        "trigger anticheat",
        "rage anticheat",
    ];

    private static readonly string[] RageMPNodeJsCheatPatterns =
    [
        "mp.players.forEachFast",
        "mp.events.add('cheat'",
        "mp.events.add(\"cheat\"",
        "bypassAnticheat",
        "disableAnticheat",
        "evadeAnticheat",
        "callNative(",
        "invokeNative(",
        "executeNative(",
        "mp.game.invoke(",
        "setEntityHealth(0",
        "giveWeaponToPed(",
        "createVehicle(",
        "setEntityCoords(",
        "setEntityVelocity(",
        "setEntityInvincible(",
        "aimbot",
        "wallhack",
        "esp",
        "speedhack",
        "noclip",
        "godmode",
        "moneyCheat",
        "vehicleSpawn",
        "weaponGive",
        "teleportPlayer",
        "crashPlayer",
        "kickPlayer",
        "freezePlayer",
        "spectatePlayer",
        "packageInject",
        "injectPackage",
        "cefBypass",
        "nodeBypass",
        "hookRage",
        "patchRage",
        "bypass(",
        "exploit(",
    ];

    private static readonly string[] RageMPDownloadArtifacts =
    [
        "ragemp_cheat.zip",
        "ragemp_hack.zip",
        "ragemp_menu.zip",
        "ragemp_modmenu.zip",
        "ragemp_cheat.rar",
        "ragemp_hack.rar",
        "ragemp_menu.rar",
        "ragemp_modmenu.rar",
        "ragemp_cheat.7z",
        "ragemp_hack.7z",
        "ragemp_cheat_setup.exe",
        "ragemp_hack_setup.exe",
        "ragemp_menu_setup.exe",
        "ragemp_bypass_setup.exe",
        "ragemp_injector_setup.exe",
        "ragemp_modmenu_v2.exe",
        "ragemp_trainer_v2.exe",
        "ragemp_cheat_v2.exe",
        "ragemp_hack_v2.exe",
        "ragemp_evader.zip",
        "ragemp_bypass.zip",
        "ragemp_anticheat_bypass.zip",
        "ragemp_anticheat_bypass.rar",
        "rage_cheat.zip",
        "rage_hack.zip",
        "rage_menu.zip",
        "rage_modmenu.zip",
        "rage_cheat.rar",
        "rage_hack.rar",
        "ragemp_esp.zip",
        "ragemp_aimbot.zip",
        "ragemp_godmode.zip",
        "ragemp_noclip.zip",
        "ragemp_loader.exe",
        "ragemp_cheats_loader.exe",
    ];

    private static readonly string[] RageMPRegistryCheatKeys =
    [
        @"SOFTWARE\RageMPCheat",
        @"SOFTWARE\RageMPHack",
        @"SOFTWARE\RageMPMenu",
        @"SOFTWARE\RageMPBypass",
        @"SOFTWARE\RageMPModMenu",
        @"SOFTWARE\RageMPTrainer",
        @"SOFTWARE\RageMPGodmode",
        @"SOFTWARE\RageMPInjector",
        @"SOFTWARE\RageMPEvader",
        @"SOFTWARE\RageBypass",
        @"SOFTWARE\RageHack",
        @"SOFTWARE\RageCheat",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckRageMPCheatExecutables(ctx, ct),
            CheckRageMPCheatDlls(ctx, ct),
            CheckRageMPPackageInjectionFiles(ctx, ct),
            CheckRageMPConfigArtifacts(ctx, ct),
            CheckRageMPPackageFolders(ctx, ct),
            CheckRageMPClientLogs(ctx, ct),
            CheckRageMPServerLogs(ctx, ct),
            CheckRageMPNodeJsCheatScripts(ctx, ct),
            CheckRageMPDownloadArtifacts(ctx, ct),
            CheckRegistryKeysForRageMPCheats(ctx, ct),
            CheckUserAssistForRageMPCheats(ctx, ct),
            CheckMuiCacheForRageMPCheats(ctx, ct),
            CheckRageMPInstallerRecords(ctx, ct),
            CheckRageMPCacheForCheatDlls(ctx, ct),
            CheckRageMPRecentDocuments(ctx, ct),
            CheckRageMPRunKeys(ctx, ct)
        );
    }

    private Task CheckRageMPCheatExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(RageMPAppDataPaths)
        {
            Path.Combine(UserProfile, "Downloads"),
            Desktop,
            Path.Combine(LocalAppData, "Temp"),
            Path.Combine(UserProfile, "Documents"),
            Path.Combine(UserProfile, "Desktop"),
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
                    if (RageMPCheatExecutables.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP cheat executable detected",
                            Risk = RiskLevel.Critical,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known RageMP cheat executable '{fn}' found on disk. This is a forensic artifact indicating the presence of cheat software targeting the RageMP GTA:V multiplayer framework.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRageMPCheatDlls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(RageMPAppDataPaths)
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
                    if (RageMPCheatDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP cheat DLL detected",
                            Risk = RiskLevel.Critical,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known RageMP cheat DLL '{fn}' found on disk. Cheat DLLs are typically injected into the GTA:V or RageMP process to enable aimbot, ESP, godmode, or anticheat bypass functionality.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRageMPPackageInjectionFiles(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(RageMPAppDataPaths)
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
                    if (RageMPPackageInjectionFiles.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP package/CEF/Node.js injection tool",
                            Risk = RiskLevel.Critical,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"RageMP package injection tool '{fn}' found. These tools inject unauthorized client-side packages, Node.js modules, or CEF scripts into the RageMP client to enable cheat functionality while evading server-side detection.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRageMPConfigArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(RageMPAppDataPaths)
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
                    if (RageMPConfigArtifacts.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP cheat config/offset file",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"RageMP cheat configuration or offset file '{fn}' found. These files contain memory offsets, GTA:V native function addresses, or cheat settings used by RageMP cheats for memory manipulation and feature configuration.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRageMPPackageFolders(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var rageMPDir in RageMPAppDataPaths)
        {
            var packagesDir = Path.Combine(rageMPDir, "packages");
            if (!Directory.Exists(packagesDir)) continue;
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(packagesDir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var folderName = Path.GetFileName(dir);
                    if (RageMPCheatPackageNames.Any(k => folderName.Equals(k, StringComparison.OrdinalIgnoreCase)
                        || folderName.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Suspicious RageMP package folder",
                            Risk = RiskLevel.High,
                            Location = packagesDir,
                            FileName = folderName,
                            Reason = $"RageMP package folder '{folderName}' has a cheat-related name. RageMP packages are client-side JavaScript/Node.js modules that run inside the game client; cheat packages abuse this to run unauthorized scripts.",
                            Detail = $"Package path: {dir}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            var clientPackagesDir = Path.Combine(rageMPDir, "client_packages");
            if (!Directory.Exists(clientPackagesDir)) continue;
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(clientPackagesDir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var folderName = Path.GetFileName(dir);
                    if (RageMPCheatPackageNames.Any(k => folderName.Equals(k, StringComparison.OrdinalIgnoreCase)
                        || folderName.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Suspicious RageMP client_packages folder",
                            Risk = RiskLevel.High,
                            Location = clientPackagesDir,
                            FileName = folderName,
                            Reason = $"RageMP client_packages folder '{folderName}' has a cheat-related name. Client packages run as privileged Node.js code inside the RageMP process with access to native GTA:V functions.",
                            Detail = $"Package path: {dir}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var downloadsDir = Path.Combine(UserProfile, "Downloads");
        if (Directory.Exists(downloadsDir))
        {
            try
            {
                foreach (var dir in Directory.EnumerateDirectories(downloadsDir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var folderName = Path.GetFileName(dir);
                    if (RageMPCheatPackageNames.Any(k => folderName.Equals(k, StringComparison.OrdinalIgnoreCase))
                        || folderName.Contains("ragemp", StringComparison.OrdinalIgnoreCase) && (
                            folderName.Contains("cheat", StringComparison.OrdinalIgnoreCase) ||
                            folderName.Contains("hack", StringComparison.OrdinalIgnoreCase) ||
                            folderName.Contains("menu", StringComparison.OrdinalIgnoreCase) ||
                            folderName.Contains("bypass", StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Suspicious RageMP-related folder in Downloads",
                            Risk = RiskLevel.High,
                            Location = downloadsDir,
                            FileName = folderName,
                            Reason = $"Downloads folder contains a directory '{folderName}' that matches known RageMP cheat package naming patterns.",
                            Detail = $"Folder path: {dir}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRageMPClientLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var rageMPDir in RageMPAppDataPaths)
        {
            if (!Directory.Exists(rageMPDir)) continue;
            try
            {
                var logFiles = Directory.EnumerateFiles(rageMPDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(rageMPDir, "*.txt", SearchOption.AllDirectories));

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
                        foreach (var pattern in RageMPClientLogCheatPatterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "RageMP client log: cheat activity artifact",
                                    Risk = RiskLevel.High,
                                    Location = Path.GetDirectoryName(logFile) ?? rageMPDir,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"RageMP client log contains cheat-related pattern: '{pattern}'. Client logs may record cheat tool startup messages, hook confirmations, or module load events.",
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

    private Task CheckRageMPServerLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var serverLogDirs = new[]
        {
            Path.Combine(UserProfile, "ragemp-server", "logs"),
            Path.Combine(UserProfile, "rage-server", "logs"),
            Path.Combine(UserProfile, "ragemp_server", "logs"),
            Path.Combine(UserProfile, "Documents", "ragemp-server", "logs"),
            Path.Combine(UserProfile, "Documents", "rage-server", "logs"),
            @"C:\ragemp-server\logs",
            @"C:\ragemp_server\logs",
            @"C:\rage-server\logs",
            @"C:\ragemp\server\logs",
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
                        foreach (var pattern in RageMPServerLogCheatPatterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "RageMP server log: cheat detection record",
                                    Risk = RiskLevel.High,
                                    Location = logDir,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"RageMP server log contains cheat detection record: '{pattern}'. Server logs record detected cheat events, bans, and anticheat triggers that indicate the user ran cheat software on this machine.",
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

    private Task CheckRageMPNodeJsCheatScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var rageMPDir in RageMPAppDataPaths)
        {
            var packagesDir = Path.Combine(rageMPDir, "packages");
            var clientPackagesDir = Path.Combine(rageMPDir, "client_packages");

            foreach (var searchRoot in new[] { packagesDir, clientPackagesDir })
            {
                if (!Directory.Exists(searchRoot)) continue;
                try
                {
                    var jsFiles = Directory.EnumerateFiles(searchRoot, "*.js", SearchOption.AllDirectories)
                        .Concat(Directory.EnumerateFiles(searchRoot, "*.mjs", SearchOption.AllDirectories))
                        .Concat(Directory.EnumerateFiles(searchRoot, "*.cjs", SearchOption.AllDirectories))
                        .Concat(Directory.EnumerateFiles(searchRoot, "*.ts", SearchOption.AllDirectories));

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
                            foreach (var pattern in RageMPNodeJsCheatPatterns)
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
                                    Title = "RageMP Node.js/JS package with cheat patterns",
                                    Risk = RiskLevel.Critical,
                                    Location = Path.GetDirectoryName(jsFile) ?? searchRoot,
                                    FileName = Path.GetFileName(jsFile),
                                    Reason = $"RageMP JavaScript package file contains {hits} cheat-related patterns (first match: '{firstMatch}'). Node.js packages in RageMP run with elevated privileges and can invoke GTA:V natives directly, enabling aimbot, ESP, godmode, and anticheat bypass.",
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

    private Task CheckRageMPDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                    if (RageMPDownloadArtifacts.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP cheat download artifact",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"RageMP cheat package or installer file '{fn}' found in {dir}. Downloaded cheat archives and setup executables indicate prior acquisition of cheat software targeting RageMP.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRegistryKeysForRageMPCheats(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var keyPath in RageMPRegistryCheatKeys)
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
                        Title = "RageMP cheat registry key",
                        Risk = RiskLevel.High,
                        Location = @"HKCU\" + keyPath,
                        FileName = string.Empty,
                        Reason = $"Registry key '{keyPath}' was left behind by a RageMP cheat tool installation or configuration. These keys are typically written by cheat loaders to store settings or license data.",
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
                        Title = "RageMP cheat registry key (HKLM)",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\" + keyPath,
                        FileName = string.Empty,
                        Reason = $"System-level registry key '{keyPath}' was left behind by a RageMP cheat tool. Keys written to HKLM indicate the cheat ran with administrator privileges.",
                        Detail = $"Key: HKLM\\{keyPath}"
                    });
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckUserAssistForRageMPCheats(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                        bool isCheat = RageMPCheatExecutables.Any(k =>
                                lower.Contains(k.Replace(".exe", string.Empty), StringComparison.OrdinalIgnoreCase))
                            || lower.Contains("ragemp cheat")
                            || lower.Contains("ragemp hack")
                            || lower.Contains("ragemp bypass")
                            || lower.Contains("ragemp modmenu")
                            || lower.Contains("ragemp trainer")
                            || lower.Contains("ragemp injector")
                            || lower.Contains("ragemp evader")
                            || lower.Contains("rage cheat")
                            || lower.Contains("rage hack")
                            || lower.Contains("rage bypass");
                        if (isCheat)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP cheat execution (UserAssist)",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{uaPath}\{guidName}\Count",
                                FileName = decoded,
                                Reason = $"Windows UserAssist registry records execution of a RageMP cheat tool: '{decoded}'. UserAssist tracks every GUI program launched by the user and is a reliable forensic indicator of prior execution.",
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

    private Task CheckMuiCacheForRageMPCheats(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                    bool isCheat = RageMPCheatExecutables.Any(k =>
                            lower.Contains(k.Replace(".exe", string.Empty), StringComparison.OrdinalIgnoreCase))
                        || lower.Contains("ragemp cheat")
                        || lower.Contains("ragemp hack")
                        || lower.Contains("ragemp bypass")
                        || lower.Contains("ragemp modmenu")
                        || lower.Contains("ragemp trainer")
                        || lower.Contains("ragemp injector")
                        || lower.Contains("ragemp evader")
                        || lower.Contains("rage cheat")
                        || lower.Contains("rage hack");
                    if (isCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP cheat execution (MUICache)",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\" + muiPath,
                            FileName = Path.GetFileName(valName),
                            Reason = $"Windows MUICache records a RageMP cheat executable was run: '{valName}'. MUICache stores the friendly name of every EXE ever executed and persists even after the file is deleted.",
                            Detail = $"MUICache entry: {valName}"
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckRageMPInstallerRecords(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                        bool isCheat = lower.Contains("ragemp cheat")
                            || lower.Contains("ragemp hack")
                            || lower.Contains("ragemp bypass")
                            || lower.Contains("ragemp modmenu")
                            || lower.Contains("ragemp trainer")
                            || lower.Contains("rage cheat")
                            || lower.Contains("rage hack")
                            || locLower.Contains("ragemp cheat")
                            || locLower.Contains("ragemp hack")
                            || locLower.Contains("ragemp bypass");
                        if (isCheat)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP cheat installer record",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                FileName = displayName,
                                Reason = $"Uninstall registry record found for RageMP cheat software: '{displayName}'. This indicates a cheat tool was formally installed on this system.",
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

    private Task CheckRageMPCacheForCheatDlls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var rageMPDir in RageMPAppDataPaths)
        {
            var cacheDirs = new[]
            {
                Path.Combine(rageMPDir, "cache"),
                Path.Combine(rageMPDir, "data"),
                Path.Combine(rageMPDir, "temp"),
                Path.Combine(rageMPDir, "bin"),
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
                        if (RageMPCheatDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Cheat DLL inside RageMP cache/data folder",
                                Risk = RiskLevel.Critical,
                                Location = Path.GetDirectoryName(file) ?? cacheDir,
                                FileName = fn,
                                Reason = $"Known RageMP cheat DLL '{fn}' found inside the RageMP application cache or data folder. Cheat tools sometimes store their DLLs inside the game framework directory to evade detection and enable auto-loading.",
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

    private Task CheckRageMPRecentDocuments(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                bool isRageMPCheat = fn.Contains("ragemp cheat")
                    || fn.Contains("ragemp hack")
                    || fn.Contains("ragemp bypass")
                    || fn.Contains("ragemp modmenu")
                    || fn.Contains("ragemp trainer")
                    || fn.Contains("ragemp inject")
                    || fn.Contains("ragemp evader")
                    || fn.Contains("rage cheat")
                    || fn.Contains("rage hack")
                    || RageMPDownloadArtifacts.Any(k =>
                        fn.Contains(k.Replace(".exe", string.Empty)
                            .Replace(".zip", string.Empty)
                            .Replace(".rar", string.Empty)
                            .Replace(".7z", string.Empty), StringComparison.OrdinalIgnoreCase));
                if (isRageMPCheat)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "RageMP cheat recent document artifact",
                        Risk = RiskLevel.Medium,
                        Location = recentDir,
                        FileName = Path.GetFileName(lnk),
                        Reason = $"Windows Recent Documents folder contains a shortcut to a RageMP cheat file: '{fn}'. Recent Documents tracks files opened or accessed by the user and provides forensic evidence of cheat file interaction.",
                        Detail = $"Shortcut: {lnk}"
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckRageMPRunKeys(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                    bool isCheat = lower.Contains("ragemp cheat")
                        || lower.Contains("ragemp hack")
                        || lower.Contains("ragemp bypass")
                        || lower.Contains("ragemp modmenu")
                        || lower.Contains("ragemp trainer")
                        || lower.Contains("ragemp inject")
                        || lower.Contains("ragemp evader")
                        || lower.Contains("rage cheat")
                        || lower.Contains("rage hack")
                        || RageMPCheatExecutables.Any(k => lower.Contains(k.Replace(".exe", string.Empty), StringComparison.OrdinalIgnoreCase));
                    if (isCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP cheat autostart (Run key)",
                            Risk = RiskLevel.High,
                            Location = $@"{hiveName}\{keyPath}",
                            FileName = val,
                            Reason = $"RageMP cheat tool configured to auto-start via Windows Run registry key. Value '{val}' points to: '{data}'. Auto-start entries indicate persistent cheat installation.",
                            Detail = $"Value: {val} = {data}"
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private static string Rot13Decode(string s)
    {
        return new string(s.Select(c =>
            c >= 'a' && c <= 'z' ? (char)('a' + (c - 'a' + 13) % 26) :
            c >= 'A' && c <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) : c).ToArray());
    }
}
