using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMESXHackForensicScanModule : IScanModule
{
    public string Name => "FiveM ESX/QBCore Framework Exploit Forensic Scan";
    public double Weight => 4.1;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static string AppData => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static string Desktop => Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static string Downloads => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
    private static string Temp => Path.GetTempPath();
    private static string UserProfile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

    private static IEnumerable<string> GetFiveMDataDirs()
    {
        var candidates = new List<string>
        {
            Path.Combine(LocalAppData, "FiveM"),
            Path.Combine(LocalAppData, "FiveM", "FiveM.app"),
            Path.Combine(LocalAppData, "FiveM", "FiveM.app", "data"),
            Path.Combine(AppData, "CitizenFX"),
            Path.Combine(LocalAppData, "CitizenFX"),
        };
        return candidates.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> GetFiveMResourceDirs()
    {
        var roots = new List<string>();
        foreach (var fivemDir in GetFiveMDataDirs())
        {
            roots.Add(Path.Combine(fivemDir, "resources"));
            roots.Add(Path.Combine(fivemDir, "citizen", "resources"));
            roots.Add(Path.Combine(fivemDir, "data", "resources"));
            roots.Add(Path.Combine(fivemDir, "plugins"));
        }

        var commonServerPaths = new[]
        {
            Path.Combine(UserProfile, "FXServer", "resources"),
            Path.Combine(UserProfile, "fxserver", "resources"),
            Path.Combine(UserProfile, "server-data", "resources"),
            @"C:\FXServer\resources",
            @"C:\fxserver\resources",
            @"C:\server-data\resources",
            @"C:\txData\default\resources",
        };
        roots.AddRange(commonServerPaths);

        return roots.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private static readonly string[] ESXHackExecutables =
    [
        "esx_hack.exe", "esx_exploit.exe", "esx_bypass.exe", "esx_cheat.exe",
        "esx_money.exe", "esx_job.exe", "esx_prop.exe", "esx_vehicle.exe",
        "esx_weapon.exe", "esx_admin.exe", "esx_grant.exe", "esx_give.exe",
        "esx_menu.exe", "qbcore_hack.exe", "qb_hack.exe", "qb_exploit.exe",
        "qb_bypass.exe", "qb_cheat.exe", "qb_money.exe", "qb_job.exe",
        "qb_item.exe", "qb_vehicle.exe", "qb_weapon.exe", "qb_admin.exe",
        "qb_grant.exe", "qb_give.exe", "qb_menu.exe", "fivem_esx.exe",
        "fivem_qb.exe", "fivem_framework.exe", "framework_hack.exe",
        "framework_exploit.exe", "framework_bypass.exe", "framework_cheat.exe",
        "server_hack.exe", "server_exploit.exe", "server_bypass.exe",
        "server_cheat.exe", "lua_exec.exe", "lua_inject.exe", "lua_exploit.exe",
        "lua_bypass.exe", "lua_hack.exe", "net_exec.exe", "net_inject.exe",
        "net_exploit.exe", "net_bypass.exe", "net_hack.exe", "nui_exec.exe",
        "nui_inject.exe", "nui_exploit.exe", "nui_bypass.exe",
        "resource_exec.exe", "resource_exploit.exe", "resource_bypass.exe",
        "resource_hack.exe", "citizen_exec.exe", "citizen_inject.exe",
        "citizen_exploit.exe", "citizen_bypass.exe",
    ];

    private static readonly string[] ESXHackDlls =
    [
        "esx_hack.dll", "esx_exploit.dll", "esx_bypass.dll", "esx_cheat.dll",
        "esx_inject.dll", "esx_money.dll", "esx_job.dll", "esx_vehicle.dll",
        "esx_weapon.dll", "esx_admin.dll", "esx_grant.dll", "esx_give.dll",
        "qb_hack.dll", "qb_exploit.dll", "qb_bypass.dll", "qb_cheat.dll",
        "qb_inject.dll", "qb_money.dll", "qb_item.dll", "qb_vehicle.dll",
        "qb_weapon.dll", "qb_admin.dll", "qb_grant.dll", "qb_give.dll",
        "fivem_esx.dll", "fivem_qb.dll", "fivem_framework.dll",
        "framework_hack.dll", "framework_exploit.dll", "framework_bypass.dll",
        "server_hack.dll", "server_exploit.dll", "server_bypass.dll",
        "lua_exec.dll", "lua_inject.dll", "lua_exploit.dll", "lua_hack.dll",
        "net_exec.dll", "net_inject.dll", "net_exploit.dll", "net_hack.dll",
        "nui_exec.dll", "nui_inject.dll", "nui_exploit.dll",
        "resource_exec.dll", "resource_exploit.dll", "resource_hack.dll",
        "citizen_exec.dll", "citizen_inject.dll", "citizen_exploit.dll",
    ];

    private static readonly string[] ESXHackResourceFolderNames =
    [
        "esx_hack", "esx_exploit", "esx_bypass", "esx_cheat", "esx_money",
        "qb_hack", "qb_exploit", "qb_bypass", "qb_cheat", "qb_money",
        "framework_hack", "framework_exploit", "server_hack", "server_exploit",
        "lua_exec", "lua_inject", "net_exec", "net_inject", "nui_exec",
        "nui_inject", "resource_exec", "resource_inject", "esx_give",
        "esx_grant", "esx_admin", "qb_give", "qb_grant", "qb_admin",
        "esx_weapon_give", "esx_vehicle_give", "esx_job_set",
        "qb_weapon_give", "qb_vehicle_give", "qb_job_set",
        "esx_money_give", "qb_money_give", "esx_account_hack",
        "qb_account_hack", "esx_level_up", "qb_reputation_hack",
        "framework_bypass_v2", "server_exploit_v2", "lua_exec_v2",
        "net_exec_v2", "citizen_exploit", "citizen_bypass",
        "noclip_esx", "godmode_esx", "teleport_esx",
        "noclip_qb", "godmode_qb", "teleport_qb",
        "esx_tpl", "qb_tpl", "esx_trainer", "qb_trainer",
    ];

    private static readonly string[] ESXHackLuaPatterns =
    [
        "TriggerServerEvent", "TriggerNetworkEvent", "exports['es_extended']",
        "ESX.GetPlayerData", "ESX.SetMoney", "ESX.AddMoney", "ESX.SetJob",
        "exports['qb-core']", "QBCore.Functions", "QBCore.Functions.GetPlayer",
        "SetMoney", "AddMoney", "SetJob", "GiveWeapon", "SpawnVehicle",
        "ExecuteCommand", "Citizen.InvokeNative", "hack", "exploit",
        "bypass", "cheat", "admin_bypass", "anticheat_bypass",
        "ace_bypass", "permission_bypass", "role_bypass",
    ];

    private static readonly string[] ESXHackJsPatterns =
    [
        "TriggerServerEvent", "TriggerNetworkEvent", "exports['es_extended']",
        "ESX.GetPlayerData", "ESX.SetMoney", "ESX.AddMoney", "ESX.SetJob",
        "exports['qb-core']", "QBCore.Functions", "QBCore.Functions.GetPlayer",
        "SetMoney", "AddMoney", "SetJob", "GiveWeapon", "SpawnVehicle",
        "ExecuteCommand", "invokeNative", "hack", "exploit",
        "bypass", "cheat", "admin_bypass", "anticheat_bypass",
        "ace_bypass", "permission_bypass", "role_bypass",
    ];

    private static readonly string[] ESXHackClientLogPatterns =
    [
        "ESX exploit", "QBCore exploit", "framework exploit", "server bypass",
        "esx hack", "qb hack", "lua exec detected", "net exec detected",
        "nui exec detected", "citizen exec", "resource exec",
        "give item exploit", "give money exploit", "set job exploit",
        "give weapon exploit", "spawn vehicle exploit", "anticheat bypass",
        "ace bypass", "permission bypass", "admin bypass",
        "esx cheat", "qb cheat", "framework cheat", "esx bypass", "qb bypass",
        "framework bypass", "ban for esx hack", "ban for qb hack",
        "kick for exploit", "ban for exploit", "esx_money exploit",
        "qb_money exploit", "illegal item grant", "illegal money grant",
        "illegal weapon grant", "illegal vehicle spawn", "illegal job set",
        "anticheat_bypass", "ace_bypass", "permission_bypass",
        "admin_bypass", "exploit detected", "hack detected",
    ];

    private static readonly string[] ESXHackServerLogPatterns =
    [
        "ESX exploit detected", "QBCore exploit detected", "framework exploit",
        "server bypass detected", "lua exec detected", "net exec detected",
        "nui exec detected", "citizen exec detected", "resource exec detected",
        "illegal money grant", "illegal item grant", "illegal weapon grant",
        "illegal vehicle spawn", "illegal job set", "anticheat bypass attempt",
        "ace bypass attempt", "permission bypass", "admin bypass",
        "banned for exploit", "kicked for exploit",
        "rate limit exceeded: esx", "rate limit exceeded: qb",
        "suspicious ESX call", "suspicious QB call", "suspicious framework call",
        "server event abuse", "client event abuse", "esx_money exploit",
        "qb_money exploit", "invalid ace permission", "unauthorized ace",
        "resource injection detected", "lua injection detected",
        "net injection detected", "citizen injection detected",
        "player exploit", "player cheat detected", "player hack detected",
        "triggerevent abuse", "rate limit exceeded", "illegal triggerserverevent",
        "illegal callback", "illegal rpc", "unauthorized server event",
        "unauthorized net event", "exploit attempt blocked",
        "cheat prevention triggered", "anticheat triggered",
    ];

    private static readonly string[] ESXHackDownloadArtifacts =
    [
        "esx_hack.zip", "esx_exploit.zip", "esx_bypass.zip", "esx_cheat.zip",
        "esx_hack.rar", "esx_exploit.rar", "esx_bypass.rar", "esx_cheat.rar",
        "esx_money_hack.zip", "esx_money_hack.rar", "esx_money_exploit.zip",
        "qb_hack.zip", "qb_exploit.zip", "qb_bypass.zip", "qb_cheat.zip",
        "qb_hack.rar", "qb_exploit.rar", "qb_bypass.rar", "qb_cheat.rar",
        "qb_money_hack.zip", "qb_money_hack.rar", "qb_money_exploit.zip",
        "fivem_esx_hack.zip", "fivem_qb_hack.zip", "fivem_exploit.zip",
        "fivem_framework_hack.zip", "fivem_framework_exploit.zip",
        "fivem_framework_bypass.zip", "fivem_hack.zip", "fivem_cheat.zip",
        "fivem_hack.rar", "fivem_cheat.rar", "fivem_exploit.rar",
        "lua_exec_fivem.zip", "lua_exec_fivem.rar", "lua_exec_exploit.zip",
        "net_exec_fivem.zip", "net_exec_fivem.rar", "net_exec_exploit.zip",
        "nui_exec_fivem.zip", "resource_exploit.zip", "resource_hack.zip",
        "citizen_exec.zip", "citizen_inject.zip", "citizen_bypass.zip",
        "server_hack_fivem.zip", "server_exploit_fivem.zip",
        "esx_money_drop.zip", "qb_money_drop.zip",
        "esx_item_grant.zip", "qb_item_grant.zip",
        "esx_weapon_give.zip", "qb_weapon_give.zip",
    ];

    private static readonly string[] ESXHackUserAssistKeywords =
    [
        "esx_hack", "esx_exploit", "esx_bypass", "esx_cheat", "esx_money",
        "qb_hack", "qb_exploit", "qb_bypass", "qb_cheat", "qb_money",
        "qbcore_hack", "framework_hack", "framework_exploit", "server_hack",
        "lua_exec", "lua_inject", "lua_exploit", "lua_hack",
        "net_exec", "net_inject", "net_exploit", "net_hack",
        "nui_exec", "nui_inject", "citizen_exec", "citizen_inject",
        "resource_exec", "resource_exploit", "fivem_esx", "fivem_qb",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckESXHackExecutables(ctx, ct),
            CheckESXHackDlls(ctx, ct),
            CheckESXHackResourceFolders(ctx, ct),
            CheckESXHackLuaFiles(ctx, ct),
            CheckESXHackJsFiles(ctx, ct),
            CheckESXHackClientLogs(ctx, ct),
            CheckESXHackServerLogs(ctx, ct),
            CheckESXHackDownloadArtifacts(ctx, ct),
            CheckRegistryForESXHacks(ctx, ct)
        );
    }

    private Task CheckESXHackExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var exeSet = new HashSet<string>(ESXHackExecutables, StringComparer.OrdinalIgnoreCase);

        var scanDirs = new List<string>
        {
            Desktop, Downloads, Temp,
            Path.Combine(LocalAppData, "Temp"),
            AppData, LocalAppData,
        };
        scanDirs.AddRange(GetFiveMDataDirs());

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
                    if (exeSet.Contains(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM ESX/QBCore exploit executable detected: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known FiveM ESX/QBCore framework exploit executable found: '{fn}'. " +
                                     "These tools are used to illegally grant money, items, weapons or jobs on FiveM servers " +
                                     "by abusing ESX or QBCore framework server events and permissions.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckESXHackDlls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var dllSet = new HashSet<string>(ESXHackDlls, StringComparer.OrdinalIgnoreCase);

        var scanDirs = new List<string>
        {
            Desktop, Downloads, Temp,
            Path.Combine(LocalAppData, "Temp"),
            AppData, LocalAppData,
        };
        scanDirs.AddRange(GetFiveMDataDirs());

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
                    if (dllSet.Contains(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM ESX/QBCore exploit DLL detected: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known FiveM ESX/QBCore framework exploit DLL found: '{fn}'. " +
                                     "These injection DLLs are used to hook into FiveM client processes and " +
                                     "exploit ESX/QBCore framework server-side events or bypass anti-cheat protections.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckESXHackResourceFolders(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var folderSet = new HashSet<string>(ESXHackResourceFolderNames, StringComparer.OrdinalIgnoreCase);

        foreach (var resourceRoot in GetFiveMResourceDirs())
        {
            if (!Directory.Exists(resourceRoot)) continue;
            try
            {
                foreach (var subDir in Directory.EnumerateDirectories(resourceRoot, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var folderName = Path.GetFileName(subDir);
                    bool directMatch = folderSet.Contains(folderName);
                    bool keywordMatch = !directMatch && ESXHackResourceFolderNames.Any(k =>
                        folderName.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (directMatch || keywordMatch)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM ESX/QBCore exploit resource folder: {folderName}",
                            Risk = RiskLevel.High,
                            Location = resourceRoot,
                            FileName = folderName,
                            Reason = $"FiveM resource directory '{folderName}' matches known ESX/QBCore exploit resource name. " +
                                     "Exploit resources are installed as FiveM server-side or client-side resources to " +
                                     "gain unauthorized money, items, weapons or administrative access via framework abuse.",
                            Detail = $"Resource path: {subDir}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var citizenDirs = GetFiveMDataDirs()
            .SelectMany(d => new[] { Path.Combine(d, "citizen"), Path.Combine(d, "FiveM.app", "citizen") })
            .Where(Directory.Exists);

        foreach (var citizenDir in citizenDirs)
        {
            try
            {
                foreach (var subDir in Directory.EnumerateDirectories(citizenDir, "*", SearchOption.AllDirectories)
                    .Where(d => !d.Contains("system", StringComparison.OrdinalIgnoreCase)))
                {
                    ct.ThrowIfCancellationRequested();
                    var folderName = Path.GetFileName(subDir);
                    bool match = ESXHackResourceFolderNames.Any(k =>
                        folderName.Equals(k, StringComparison.OrdinalIgnoreCase));
                    if (match)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ESX/QBCore exploit folder in FiveM citizen dir: {folderName}",
                            Risk = RiskLevel.High,
                            Location = citizenDir,
                            FileName = folderName,
                            Reason = $"Exploit resource folder '{folderName}' found in FiveM citizen directory. " +
                                     "Citizen-embedded resources are loaded automatically by the FiveM client.",
                            Detail = $"Path: {subDir}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckESXHackLuaFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var resourceDirs = GetFiveMResourceDirs().ToList();
        if (resourceDirs.Count == 0) return;

        foreach (var resourceRoot in resourceDirs)
        {
            if (!Directory.Exists(resourceRoot)) continue;
            try
            {
                foreach (var luaFile in Directory.EnumerateFiles(resourceRoot, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        int matchCount = ESXHackLuaPatterns.Count(p =>
                            content.Contains(p, StringComparison.OrdinalIgnoreCase));

                        if (matchCount >= 4)
                        {
                            var matchedPatterns = ESXHackLuaPatterns
                                .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                                .Take(6)
                                .ToList();

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious Lua script with ESX/QBCore exploit patterns: {Path.GetFileName(luaFile)}",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(luaFile) ?? resourceRoot,
                                FileName = Path.GetFileName(luaFile),
                                Reason = $"Lua file contains {matchCount} ESX/QBCore exploit-related patterns. " +
                                         "Exploit Lua scripts abuse FiveM server event triggers and framework APIs to " +
                                         "illegally grant money, items, weapons, or jobs, or to bypass anti-cheat and ACE permissions. " +
                                         $"Matched patterns: {string.Join(", ", matchedPatterns.Select(p => $"'{p}'"))}",
                                Detail = $"File: {luaFile} | Pattern matches: {matchCount}/{ESXHackLuaPatterns.Length}",
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

    private Task CheckESXHackJsFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var resourceDirs = GetFiveMResourceDirs().ToList();
        if (resourceDirs.Count == 0) return;

        foreach (var resourceRoot in resourceDirs)
        {
            if (!Directory.Exists(resourceRoot)) continue;
            try
            {
                foreach (var jsFile in Directory.EnumerateFiles(resourceRoot, "*.js", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        int matchCount = ESXHackJsPatterns.Count(p =>
                            content.Contains(p, StringComparison.OrdinalIgnoreCase));

                        if (matchCount >= 4)
                        {
                            var matchedPatterns = ESXHackJsPatterns
                                .Where(p => content.Contains(p, StringComparison.OrdinalIgnoreCase))
                                .Take(6)
                                .ToList();

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious JS file with ESX/QBCore exploit patterns: {Path.GetFileName(jsFile)}",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(jsFile) ?? resourceRoot,
                                FileName = Path.GetFileName(jsFile),
                                Reason = $"JavaScript file contains {matchCount} ESX/QBCore exploit-related patterns. " +
                                         "Exploit JS files are used in FiveM NUI (browser-based UI) or client-side scripts " +
                                         "to trigger server events, invoke natives, or bypass framework permission checks. " +
                                         $"Matched patterns: {string.Join(", ", matchedPatterns.Select(p => $"'{p}'"))}",
                                Detail = $"File: {jsFile} | Pattern matches: {matchCount}/{ESXHackJsPatterns.Length}",
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

    private Task CheckESXHackClientLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var clientLogDirs = new List<string>();
        foreach (var fivemDir in GetFiveMDataDirs())
        {
            clientLogDirs.Add(Path.Combine(fivemDir, "logs"));
            clientLogDirs.Add(Path.Combine(fivemDir, "FiveM.app", "logs"));
            clientLogDirs.Add(Path.Combine(fivemDir, "data", "logs"));
            clientLogDirs.Add(fivemDir);
        }
        clientLogDirs.Add(Path.Combine(AppData, "CitizenFX"));
        clientLogDirs.Add(Path.Combine(LocalAppData, "CitizenFX"));

        var patterns = ESXHackClientLogPatterns;

        foreach (var logDir in clientLogDirs.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                foreach (var logFile in Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(logDir, "*.txt", SearchOption.AllDirectories)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();

                        foreach (var pattern in patterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "FiveM client log contains ESX/QBCore exploit activity",
                                    Risk = RiskLevel.High,
                                    Location = logDir,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"FiveM client log file contains ESX/QBCore exploit indicator: '{pattern}'. " +
                                             "Client log entries document exploit tool execution, framework abuse, " +
                                             "anti-cheat bypass attempts, and ban/kick events tied to exploit use.",
                                    Detail = $"Log: {logFile} | Pattern: {pattern}",
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

    private Task CheckESXHackServerLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var serverLogDirs = new List<string>
        {
            Path.Combine(UserProfile, "FXServer", "logs"),
            Path.Combine(UserProfile, "FXServer", "server-data", "logs"),
            Path.Combine(UserProfile, "fxserver", "logs"),
            Path.Combine(UserProfile, "server-data", "logs"),
            Path.Combine(UserProfile, "txData", "default", "logs"),
            @"C:\FXServer\logs",
            @"C:\FXServer\server-data\logs",
            @"C:\fxserver\logs",
            @"C:\server-data\logs",
            @"C:\txData\default\logs",
            @"C:\txData\logs",
        };

        var patterns = ESXHackServerLogPatterns;

        foreach (var logDir in serverLogDirs.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                foreach (var logFile in Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(logDir, "*.txt", SearchOption.AllDirectories)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();

                        foreach (var pattern in patterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "FiveM server log contains ESX/QBCore exploit evidence",
                                    Risk = RiskLevel.High,
                                    Location = logDir,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"FiveM server log file contains ESX/QBCore exploit indicator: '{pattern}'. " +
                                             "Server logs record exploit detections, illegal grants, ban events and " +
                                             "server-side anti-cheat triggers caused by framework exploit tools.",
                                    Detail = $"Server log: {logFile} | Pattern: {pattern}",
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

        foreach (var fivemDir in GetFiveMDataDirs())
        {
            var logPath = Path.Combine(fivemDir, "FiveM.app", "logs");
            if (!Directory.Exists(logPath)) continue;
            try
            {
                foreach (var logFile in Directory.EnumerateFiles(logPath, "*CitizenFX*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(logPath, "CitizenFX_log_*.txt", SearchOption.AllDirectories)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        foreach (var pattern in patterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "CitizenFX log contains ESX/QBCore server exploit evidence",
                                    Risk = RiskLevel.High,
                                    Location = logPath,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"CitizenFX log contains server-side ESX/QBCore exploit indicator: '{pattern}'. " +
                                             "Server-side exploit activity is logged in CitizenFX log files alongside client messages.",
                                    Detail = $"CitizenFX log: {logFile} | Pattern: {pattern}",
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

    private Task CheckESXHackDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var artifactSet = new HashSet<string>(ESXHackDownloadArtifacts, StringComparer.OrdinalIgnoreCase);
        var esxKeywords = new[]
        {
            "esx_hack", "esx_exploit", "esx_bypass", "esx_cheat", "esx_money",
            "qb_hack", "qb_exploit", "qb_bypass", "qb_cheat", "qb_money",
            "qbcore_hack", "fivem_esx", "fivem_qb", "framework_hack",
            "framework_exploit", "framework_bypass", "lua_exec", "net_exec",
            "nui_exec", "resource_exec", "citizen_exec", "server_hack",
        };
        var archiveExtensions = new HashSet<string>(new[] { ".zip", ".rar", ".7z", ".gz", ".tar" },
            StringComparer.OrdinalIgnoreCase);

        var scanDirs = new[] { Downloads, Desktop };

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
                    var ext = Path.GetExtension(file);

                    if (!archiveExtensions.Contains(ext)) continue;

                    bool directMatch = artifactSet.Contains(fn);
                    bool keywordMatch = !directMatch && esxKeywords.Any(k =>
                        fn.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (directMatch || keywordMatch)
                    {
                        var matchedKeyword = directMatch ? fn : esxKeywords.First(k =>
                            fn.Contains(k, StringComparison.OrdinalIgnoreCase));
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM ESX/QBCore exploit archive in Downloads: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Archive file matching ESX/QBCore exploit tool pattern found in Downloads/Desktop: '{fn}'. " +
                                     $"Matched keyword: '{matchedKeyword}'. " +
                                     "These archives typically contain exploit scripts, injector tools or resource packages " +
                                     "for abusing FiveM ESX or QBCore framework permissions.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRegistryForESXHacks(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        CheckUserAssistForESXHacks(ctx, ct);
        CheckMuiCacheForESXHacks(ctx, ct);
        CheckRunKeysForESXHacks(ctx, ct);
        CheckUninstallKeysForESXHacks(ctx, ct);
    }, ct);

    private void CheckUserAssistForESXHacks(ScanContext ctx, CancellationToken ct)
    {
        const string userAssistBase = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        var keywords = ESXHackUserAssistKeywords;

        try
        {
            using var baseKey = Registry.CurrentUser.OpenSubKey(userAssistBase, writable: false);
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
                        var decoded = Rot13Decode(encodedName).ToLowerInvariant();
                        var hit = keywords.FirstOrDefault(k => decoded.Contains(k, StringComparison.OrdinalIgnoreCase));
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
                                if (fileTime > 0) lastRun = DateTime.FromFileTimeUtc(fileTime);
                            }
                        }
                        catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"UserAssist: FiveM ESX/QBCore exploit tool executed — {Path.GetFileName(decoded)}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason = $"Windows UserAssist registry entry shows execution of ESX/QBCore exploit tool: '{Path.GetFileName(decoded)}' " +
                                     $"({runCount}x run" +
                                     (lastRun.HasValue ? $", last seen {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                     $"). Keyword match: '{hit}'. " +
                                     "UserAssist entries persist even after the executable is deleted, providing forensic evidence of past execution.",
                            Detail = $"Decoded: {decoded} | Runs: {runCount} | Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}",
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void CheckMuiCacheForESXHacks(ScanContext ctx, CancellationToken ct)
    {
        const string muiCachePath = @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
        var esxKeywords = new[]
        {
            "esx_hack", "esx_exploit", "esx_bypass", "esx_cheat",
            "qb_hack", "qb_exploit", "qb_bypass", "qb_cheat",
            "qbcore_hack", "fivem_esx", "fivem_qb", "framework_hack",
            "framework_exploit", "lua_exec", "net_exec", "nui_exec",
            "resource_exec", "citizen_exec", "server_hack",
            "esx_money", "qb_money", "esx_give", "qb_give",
        };

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(muiCachePath, writable: false);
            if (key is null) return;

            foreach (var valName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                var lower = valName.ToLowerInvariant();
                var hit = esxKeywords.FirstOrDefault(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase));
                if (hit is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"MUICache: FiveM ESX/QBCore exploit tool execution trace — {hit}",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{muiCachePath}",
                    FileName = Path.GetFileName(valName.Split('\0')[0]),
                    Reason = $"MUICache registry entry indicates execution of FiveM ESX/QBCore exploit tool containing keyword '{hit}'. " +
                             "MUICache stores the display names of recently launched executables and persists after file deletion.",
                    Detail = $"Registry value: {valName}",
                });
            }
        }
        catch { }
    }

    private void CheckRunKeysForESXHacks(ScanContext ctx, CancellationToken ct)
    {
        var runKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        };
        var esxKeywords = new[]
        {
            "esx_hack", "esx_exploit", "esx_bypass", "esx_cheat", "esx_money",
            "qb_hack", "qb_exploit", "qb_bypass", "qb_cheat", "qb_money",
            "qbcore_hack", "fivem_esx", "fivem_qb", "framework_hack",
            "framework_exploit", "lua_exec", "net_exec", "nui_exec",
            "resource_exec", "citizen_exec", "server_hack",
        };

        foreach (var keyPath in runKeys)
        {
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var key = hive.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    foreach (var valName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();
                        var valData = key.GetValue(valName)?.ToString() ?? string.Empty;
                        var combined = (valName + " " + valData).ToLowerInvariant();
                        var hit = esxKeywords.FirstOrDefault(k => combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hit is null) continue;

                        var hiveName = hive == Registry.CurrentUser ? "HKCU" : "HKLM";
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM ESX/QBCore exploit tool auto-start registry entry: {valName}",
                            Risk = RiskLevel.High,
                            Location = $@"{hiveName}\{keyPath}",
                            FileName = Path.GetFileName(valData.Trim('"').Split(' ')[0]),
                            Reason = $"FiveM ESX/QBCore exploit tool found in auto-start registry key. " +
                                     $"Value '{valName}' with data '{valData}' matches exploit keyword '{hit}'. " +
                                     "Auto-start entries indicate persistent or scheduled exploit tool execution.",
                            Detail = $"Key: {hiveName}\\{keyPath} | Value: {valName} | Data: {valData}",
                        });
                    }
                }
                catch { }
            }
        }
    }

    private void CheckUninstallKeysForESXHacks(ScanContext ctx, CancellationToken ct)
    {
        const string uninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        const string uninstallPath32 = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
        var esxKeywords = new[]
        {
            "esx hack", "esx exploit", "esx bypass", "esx cheat",
            "qb hack", "qb exploit", "qb bypass", "qb cheat",
            "qbcore hack", "fivem esx", "fivem qb", "framework hack",
            "framework exploit", "lua exec", "net exec", "nui exec",
            "resource exploit", "citizen exec", "server hack",
            "fivem exploit", "fivem cheat", "fivem hack",
        };

        foreach (var uninstPath in new[] { uninstallPath, uninstallPath32 })
        {
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var baseKey = hive.OpenSubKey(uninstPath, writable: false);
                    if (baseKey is null) continue;

                    foreach (var subName in baseKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();
                        try
                        {
                            using var subKey = baseKey.OpenSubKey(subName, writable: false);
                            var displayName = subKey?.GetValue("DisplayName")?.ToString() ?? string.Empty;
                            var publisher = subKey?.GetValue("Publisher")?.ToString() ?? string.Empty;
                            var combined = (displayName + " " + publisher + " " + subName).ToLowerInvariant();
                            var hit = esxKeywords.FirstOrDefault(k => combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (hit is null) continue;

                            var hiveName = hive == Registry.CurrentUser ? "HKCU" : "HKLM";
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"FiveM ESX/QBCore exploit installer record: {displayName}",
                                Risk = RiskLevel.High,
                                Location = $@"{hiveName}\{uninstPath}\{subName}",
                                Reason = $"FiveM ESX/QBCore exploit tool installer entry found in Uninstall registry. " +
                                         $"Display name '{displayName}' matches exploit keyword '{hit}'. " +
                                         "Uninstall entries persist as forensic evidence even after tool removal.",
                                Detail = $"DisplayName: {displayName} | Publisher: {publisher} | Key: {subName}",
                            });
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
    }

    private static string Rot13Decode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (c >= 'A' && c <= 'Z') sb.Append((char)('A' + (c - 'A' + 13) % 26));
            else if (c >= 'a' && c <= 'z') sb.Append((char)('a' + (c - 'a' + 13) % 26));
            else sb.Append(c);
        }
        return sb.ToString();
    }
}
