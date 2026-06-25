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

public sealed class RageMPAdminAbuseForensicScanModule : IScanModule
{
    public string Name => "RageMP Admin Abuse & Permission Exploit Forensic Scan";
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

    private static readonly string[] RageMPBasePaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RAGEMP"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RAGEMP"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ragemp"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ragemp"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "RAGE Multiplayer"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RAGE Multiplayer"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "rage-multiplayer"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "rage-multiplayer"),
        @"C:\RAGEMP",
        @"C:\Program Files\RAGE Multiplayer",
        @"C:\Program Files (x86)\RAGE Multiplayer",
    ];

    private static readonly string[] AdminToolExecutables =
    [
        "ragemp_admin.exe",
        "ragemp_admin_tool.exe",
        "ragemp_superadmin.exe",
        "ragemp_sudo.exe",
        "ragemp_oper.exe",
        "ragemp_admin_bypass.exe",
        "ragemp_perm_bypass.exe",
        "ragemp_permission_bypass.exe",
        "ragemp_admin_hack.exe",
        "ragemp_admin_exploit.exe",
        "admin_ragemp.exe",
        "admin_tool_ragemp.exe",
        "superadmin_ragemp.exe",
        "sudo_ragemp.exe",
        "oper_ragemp.exe",
        "admin_bypass_ragemp.exe",
        "perm_bypass_ragemp.exe",
        "permission_bypass_ragemp.exe",
        "admin_hack_ragemp.exe",
        "admin_exploit_ragemp.exe",
        "rage_admin.exe",
        "rage_admin_tool.exe",
        "rage_superadmin.exe",
        "rage_sudo.exe",
        "rage_oper.exe",
        "rage_admin_bypass.exe",
        "rage_perm_bypass.exe",
        "rage_admin_hack.exe",
        "rage_admin_exploit.exe",
        "mp_admin.exe",
        "mp_admin_tool.exe",
        "mp_superadmin.exe",
        "mp_sudo.exe",
        "mp_oper.exe",
        "mp_admin_bypass.exe",
        "mp_perm_bypass.exe",
        "mp_admin_hack.exe",
        "mp_admin_exploit.exe",
        "admin_menu_ragemp.exe",
        "admin_menu_rage.exe",
        "ragemp_admin_menu.exe",
        "rage_admin_menu.exe",
        "mp_admin_menu.exe",
        "admin_cmd_ragemp.exe",
        "admin_cmd_rage.exe",
        "ragemp_admin_cmd.exe",
        "rage_admin_cmd.exe",
        "ragemp_god.exe",
        "ragemp_noclip.exe",
        "ragemp_teleport.exe",
        "ragemp_ban_bypass.exe",
        "ragemp_kick_bypass.exe",
        "ragemp_mute_bypass.exe",
        "ragemp_warn_bypass.exe",
        "ragemp_freeze_bypass.exe",
        "ragemp_spectate.exe",
        "ragemp_invisible.exe",
        "ragemp_fly.exe",
        "admin_fly_ragemp.exe",
        "admin_god_ragemp.exe",
        "admin_noclip_ragemp.exe",
        "admin_teleport_ragemp.exe",
        "admin_ban_bypass_ragemp.exe",
        "admin_invisible_ragemp.exe",
    ];

    private static readonly string[] AdminToolDlls =
    [
        "ragemp_admin.dll",
        "ragemp_admin_tool.dll",
        "ragemp_admin_bypass.dll",
        "ragemp_perm_bypass.dll",
        "ragemp_permission_bypass.dll",
        "ragemp_admin_hack.dll",
        "ragemp_admin_exploit.dll",
        "ragemp_admin_hook.dll",
        "ragemp_sudo.dll",
        "ragemp_superadmin.dll",
        "ragemp_oper.dll",
        "admin_bypass_ragemp.dll",
        "admin_hack_ragemp.dll",
        "admin_exploit_ragemp.dll",
        "rage_admin.dll",
        "rage_admin_bypass.dll",
        "rage_admin_hack.dll",
        "rage_admin_hook.dll",
        "rage_perm_bypass.dll",
        "mp_admin.dll",
        "mp_admin_bypass.dll",
        "mp_perm_bypass.dll",
        "mp_admin_hack.dll",
        "ragemp_acl_bypass.dll",
        "ragemp_ace_bypass.dll",
        "ragemp_role_bypass.dll",
        "acl_bypass_ragemp.dll",
        "ace_bypass_ragemp.dll",
        "role_bypass_ragemp.dll",
        "ragemp_admin_menu.dll",
        "admin_menu_ragemp.dll",
        "ragemp_god_mode.dll",
        "ragemp_noclip_hack.dll",
        "ragemp_teleport_hack.dll",
        "ragemp_invisible_hack.dll",
        "ragemp_spectate_hack.dll",
        "ragemp_ban_bypass.dll",
        "ragemp_kick_bypass.dll",
        "ragemp_mute_bypass.dll",
        "ragemp_freeze_bypass.dll",
        "admin_god_ragemp.dll",
        "admin_noclip_ragemp.dll",
        "admin_teleport_ragemp.dll",
        "admin_invisible_ragemp.dll",
    ];

    private static readonly string[] AdminScriptPatterns =
    [
        "mp.players.forEach",
        "mp.players.forEachFast",
        "mp.call",
        "mp.events.addProc",
        "admin",
        "superadmin",
        "sudo",
        "oper",
        "permission",
        "bypass",
        "god_mode",
        "noclip",
        "teleport_all",
        "ban_bypass",
        "kick_bypass",
        "mute_bypass",
        "invisible",
        "spectate",
        "freeze_all",
        "kick_all",
        "ban_all",
        "explode_all",
        "warp",
        "setPosition",
        "setHealth",
        "setArmour",
        "giveWeapon",
        "spawnVehicle",
        "admin_command",
        "perm_bypass",
        "role_bypass",
        "acl_bypass",
    ];

    private static readonly string[] AdminConfigFileNames =
    [
        "admin_config.json",
        "admin_settings.json",
        "admin_menu.json",
        "superadmin.json",
        "permission_config.json",
        "acl_bypass.json",
        "admin_bypass.json",
        "perm_bypass.json",
        "admin_perms.json",
        "admin_roles.json",
        "admin_commands.json",
        "superadmin_config.json",
        "sudo_config.json",
        "oper_config.json",
        "admin_acl.json",
        "admin_ace.json",
    ];

    private static readonly string[] ClientLogPatterns =
    [
        "admin bypass",
        "permission bypass",
        "sudo exploit",
        "superadmin exploit",
        "admin command exploit",
        "ace bypass",
        "acl bypass",
        "perm bypass",
        "role bypass",
        "ban bypass",
        "kick bypass",
        "mute bypass",
        "freeze bypass",
        "admin god mode",
        "admin noclip",
        "admin teleport",
        "admin invisible",
        "admin spectate",
        "admin fly",
        "admin explode",
        "admin crash",
        "admin kick all",
        "admin ban all",
        "admin warp",
        "admin setpos",
        "cheat: admin",
        "bypass: admin",
        "exploit: admin",
        "hack: admin",
        "ban for admin abuse",
        "kick for admin abuse",
        "suspicious admin command",
        "illegal admin command",
        "unauthorized admin",
        "illegal permission",
        "unauthorized permission",
        "admin abuse detected",
        "permission exploit",
        "acl exploit",
        "ace exploit",
        "admin privilege escalation",
        "unauthorized privilege",
        "admin role spoof",
        "permission spoof",
        "sudo escalation",
        "superadmin spoof",
        "oper abuse",
    ];

    private static readonly string[] ServerLogPatterns =
    [
        "admin bypass detected",
        "permission bypass detected",
        "sudo exploit detected",
        "superadmin exploit detected",
        "admin command exploit",
        "ace bypass detected",
        "acl bypass detected",
        "perm bypass detected",
        "role bypass detected",
        "ban bypass detected",
        "kick bypass detected",
        "mute bypass detected",
        "freeze bypass detected",
        "admin god mode detected",
        "admin noclip detected",
        "admin teleport detected",
        "admin invisible detected",
        "admin spectate detected",
        "admin fly detected",
        "admin explode detected",
        "admin crash detected",
        "admin kick all detected",
        "admin ban all detected",
        "admin warp detected",
        "admin setpos detected",
        "cheat: admin",
        "bypass: admin",
        "exploit: admin",
        "hack: admin",
        "ban for admin abuse",
        "kick for admin abuse",
        "suspicious admin command",
        "illegal admin command",
        "unauthorized admin",
        "illegal permission",
        "unauthorized permission",
        "admin abuse detected",
        "permission exploit detected",
        "acl exploit detected",
        "ace exploit detected",
        "admin privilege escalation",
        "unauthorized privilege",
        "admin role spoof",
        "permission spoof",
        "sudo escalation detected",
        "superadmin spoof detected",
    ];

    private static readonly string[] AdminResourceFolderNames =
    [
        "admin_bypass",
        "admin_hack",
        "admin_exploit",
        "admin_tool",
        "superadmin_bypass",
        "sudo_exploit",
        "perm_bypass",
        "permission_bypass",
        "acl_bypass",
        "role_bypass",
        "admin_menu",
        "admin_cmd",
        "admin_god",
        "admin_noclip",
        "admin_teleport",
        "admin_invisible",
        "admin_spectate",
        "admin_fly",
        "admin_ban_bypass",
        "admin_kick_bypass",
        "admin_mute_bypass",
        "ban_bypass_admin",
        "kick_bypass_admin",
        "admin_freeze_all",
        "admin_kick_all",
        "admin_ban_all",
        "admin_explode_all",
        "admin_crash",
        "admin_warp",
        "admin_setpos",
        "admin_give",
        "admin_spawn",
        "admin_hack_v2",
        "admin_exploit_v2",
        "admin_bypass_v2",
        "admin_tool_v2",
        "admin_menu_v2",
        "perm_bypass_v2",
        "permission_bypass_v2",
        "acl_bypass_v2",
        "role_bypass_v2",
        "admin_cheat",
        "admin_griefing",
        "admin_abuse",
        "admin_grief",
        "admin_troll",
        "admin_nuke",
        "admin_wipe",
        "rage_admin_tool",
        "mp_admin_tool",
        "ragemp_admin_menu",
    ];

    private static readonly string[] DownloadArchiveNames =
    [
        "ragemp_admin.zip",
        "ragemp_admin_tool.zip",
        "ragemp_admin_bypass.zip",
        "ragemp_perm_bypass.zip",
        "ragemp_admin_hack.zip",
        "ragemp_admin_exploit.zip",
        "ragemp_superadmin.zip",
        "ragemp_sudo.zip",
        "ragemp_admin.rar",
        "ragemp_admin_tool.rar",
        "ragemp_admin_bypass.rar",
        "ragemp_perm_bypass.rar",
        "ragemp_admin_hack.rar",
        "ragemp_admin_exploit.rar",
        "ragemp_superadmin.rar",
        "ragemp_admin.7z",
        "ragemp_admin_tool.7z",
        "ragemp_admin_bypass.7z",
        "admin_bypass_ragemp.zip",
        "admin_hack_ragemp.zip",
        "admin_exploit_ragemp.zip",
        "admin_bypass_ragemp.rar",
        "admin_hack_ragemp.rar",
        "rage_admin.zip",
        "rage_admin_tool.zip",
        "rage_admin_bypass.zip",
        "rage_admin_hack.zip",
        "rage_admin.rar",
        "rage_admin_tool.rar",
        "rage_admin_bypass.rar",
        "mp_admin.zip",
        "mp_admin_tool.zip",
        "mp_admin_bypass.zip",
        "mp_admin_hack.zip",
        "ragemp_admin_setup.exe",
        "ragemp_admin_tool_setup.exe",
        "ragemp_admin_bypass_setup.exe",
        "ragemp_perm_bypass_setup.exe",
        "ragemp_admin_hack_setup.exe",
        "ragemp_superadmin_setup.exe",
        "admin_tool_ragemp_setup.exe",
        "rage_admin_setup.exe",
        "rage_admin_tool_setup.exe",
        "ragemp_admin_v2.exe",
        "ragemp_admin_tool_v2.exe",
        "ragemp_admin_bypass_v2.exe",
        "ragemp_admin_menu_setup.exe",
        "admin_menu_ragemp_setup.exe",
        "ragemp_acl_bypass_setup.exe",
        "ragemp_ace_bypass_setup.exe",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckRageMPAdminToolExecutables(ctx, ct),
            CheckRageMPAdminToolDlls(ctx, ct),
            CheckRageMPAdminScriptFiles(ctx, ct),
            CheckRageMPAdminConfigFiles(ctx, ct),
            CheckRageMPAdminClientLogs(ctx, ct),
            CheckRageMPAdminServerLogs(ctx, ct),
            CheckRageMPAdminResourceFolders(ctx, ct),
            CheckRageMPAdminDownloadArtifacts(ctx, ct),
            CheckRegistryForRageMPAdminAbuse(ctx, ct)
        );
    }

    private Task CheckRageMPAdminToolExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>(RageMPBasePaths)
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
                foreach (var file in EnumerateFilesRecursive(dir, maxDepth: 5, ct))
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);
                    if (!fn.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.IncrementFiles();
                    if (AdminToolExecutables.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP admin abuse tool executable detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known RageMP admin abuse or permission exploit executable '{fn}' found on disk. " +
                                     "These tools are used to impersonate server admins, bypass permission checks, escalate privileges, " +
                                     "or exploit admin command systems on RageMP GTA:V multiplayer servers.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckRageMPAdminToolDlls(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>(RageMPBasePaths)
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
                foreach (var file in EnumerateFilesRecursive(dir, maxDepth: 5, ct))
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);
                    if (!fn.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) continue;
                    ctx.IncrementFiles();
                    if (AdminToolDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP admin abuse DLL detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known RageMP admin abuse or permission exploit DLL '{fn}' found on disk. " +
                                     "Admin abuse DLLs are typically injected into the RageMP client or server process to intercept " +
                                     "permission checks, forge admin credentials, or enable unauthorized admin commands.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckRageMPAdminScriptFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var baseDir in RageMPBasePaths)
        {
            foreach (var subDir in new[] { "packages", "client_packages" })
            {
                var searchRoot = Path.Combine(baseDir, subDir);
                if (!Directory.Exists(searchRoot)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(searchRoot, maxDepth: 6, ct))
                    {
                        var ext = Path.GetExtension(file);
                        bool isScript = ext.Equals(".js", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".mjs", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".cjs", StringComparison.OrdinalIgnoreCase);
                        if (!isScript) continue;

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
                        string firstMatch = string.Empty;
                        foreach (var pattern in AdminScriptPatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                hits++;
                                if (firstMatch.Length == 0) firstMatch = pattern;
                            }
                        }

                        if (hits >= 4)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"RageMP admin abuse script: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(file) ?? searchRoot,
                                FileName = Path.GetFileName(file),
                                Reason = $"RageMP script file contains {hits} admin abuse or permission exploit patterns " +
                                         $"(first match: '{firstMatch}'). Scripts with 4+ of these patterns strongly indicate admin bypass, " +
                                         "privilege escalation, or unauthorized admin command abuse targeting RageMP servers.",
                                Detail = $"File: {file} | Pattern hits: {hits} | First match: {firstMatch}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckRageMPAdminConfigFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>(RageMPBasePaths)
        {
            Desktop,
            Path.Combine(UserProfile, "Downloads"),
            Path.Combine(UserProfile, "Documents"),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in EnumerateFilesRecursive(dir, maxDepth: 4, ct))
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);
                    ctx.IncrementFiles();
                    if (AdminConfigFileNames.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        string? preview = null;
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            preview = content.Length > 300 ? content[..300] : content;
                            preview = preview.Replace('\n', ' ').Replace('\r', ' ');
                        }
                        catch (IOException) { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP admin abuse config file: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Admin abuse configuration file '{fn}' found. These files are generated by RageMP admin exploit tools " +
                                     "to store target server addresses, bypassed permission lists, spoofed admin roles, or exploit parameters.",
                            Detail = preview is not null ? $"Preview: {preview}" : $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }, ct);

    private Task CheckRageMPAdminClientLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var baseDir in RageMPBasePaths)
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
                                Title = $"RageMP client log: admin abuse artifact",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(logFile) ?? baseDir,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"RageMP client log contains admin abuse pattern: '{pattern}'. " +
                                         "Client logs record cheat tool activity including admin bypass attempts, " +
                                         "permission exploit confirmations, and unauthorized admin command usage.",
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

    private Task CheckRageMPAdminServerLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var serverLogDirs = new[]
        {
            Path.Combine(UserProfile, "ragemp-server", "logs"),
            Path.Combine(UserProfile, "ragemp-server", "log"),
            Path.Combine(UserProfile, "rage-server", "logs"),
            Path.Combine(UserProfile, "rage-server", "log"),
            Path.Combine(UserProfile, "ragemp_server", "logs"),
            Path.Combine(UserProfile, "Documents", "ragemp-server", "logs"),
            Path.Combine(UserProfile, "Documents", "rage-server", "logs"),
            @"C:\ragemp-server\logs",
            @"C:\ragemp_server\logs",
            @"C:\rage-server\logs",
            @"C:\ragemp\server\logs",
            @"C:\ragemp-server\log",
            @"C:\ragemp_server\log",
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
                                Title = "RageMP server log: admin abuse detection record",
                                Risk = RiskLevel.High,
                                Location = logDir,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"RageMP server log contains admin abuse detection record: '{pattern}'. " +
                                         "Server logs record ban/kick events, detected permission exploits, and ACL/ACE bypass attempts " +
                                         "that indicate the user employed admin abuse tools on RageMP multiplayer servers.",
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

    private Task CheckRageMPAdminResourceFolders(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var baseDir in RageMPBasePaths)
        {
            foreach (var subDir in new[] { "packages", "client_packages" })
            {
                var searchRoot = Path.Combine(baseDir, subDir);
                if (!Directory.Exists(searchRoot)) continue;
                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(searchRoot, "*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        var folderName = Path.GetFileName(dir);
                        if (AdminResourceFolderNames.Any(k =>
                            folderName.Equals(k, StringComparison.OrdinalIgnoreCase)
                            || folderName.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"RageMP admin abuse resource folder: {folderName}",
                                Risk = RiskLevel.High,
                                Location = searchRoot,
                                FileName = folderName,
                                Reason = $"RageMP {subDir} folder '{folderName}' matches known admin abuse or permission exploit naming patterns. " +
                                         "Admin exploit packages installed as RageMP resources can bypass server permission checks, " +
                                         "impersonate admin roles, and execute unauthorized admin commands directly in-game.",
                                Detail = $"Folder path: {dir}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckRageMPAdminDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
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
                            Title = $"RageMP admin abuse tool download artifact: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"RageMP admin abuse tool archive or installer '{fn}' found in {dir}. " +
                                     "Downloaded admin exploit archives and setup executables indicate prior acquisition of " +
                                     "admin bypass software targeting RageMP multiplayer servers.",
                            Detail = $"Full path: {file}"
                        });
                    }
                    else
                    {
                        var fnLower = fn.ToLowerInvariant();
                        bool isSuspicious =
                            (fnLower.Contains("ragemp") || fnLower.Contains("rage_mp") || fnLower.Contains("rage-mp"))
                            && (fnLower.Contains("admin") || fnLower.Contains("superadmin") || fnLower.Contains("perm_bypass")
                                || fnLower.Contains("permission_bypass") || fnLower.Contains("acl_bypass")
                                || fnLower.Contains("ace_bypass") || fnLower.Contains("role_bypass")
                                || fnLower.Contains("sudo") || fnLower.Contains("oper"));
                        if (isSuspicious)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"RageMP admin abuse download artifact (heuristic): {fn}",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(file) ?? dir,
                                FileName = fn,
                                Reason = $"File '{fn}' in {dir} contains both RageMP-related and admin abuse-related terms in its name. " +
                                         "Heuristic match indicates a likely admin exploit tool or permission bypass archive.",
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

    private Task CheckRegistryForRageMPAdminAbuse(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        CheckUserAssistForAdminAbuse(ctx, ct);
        CheckMuiCacheForAdminAbuse(ctx, ct);
        CheckRunKeysForAdminAbuse(ctx, ct);
        CheckUninstallKeysForAdminAbuse(ctx, ct);
    }, ct);

    private void CheckUserAssistForAdminAbuse(ScanContext ctx, CancellationToken ct)
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
                        bool isAdminAbuse =
                            AdminToolExecutables.Any(k => lower.Contains(
                                k.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase),
                                StringComparison.OrdinalIgnoreCase))
                            || (lower.Contains("ragemp") && lower.Contains("admin"))
                            || (lower.Contains("ragemp") && lower.Contains("perm_bypass"))
                            || (lower.Contains("ragemp") && lower.Contains("permission_bypass"))
                            || (lower.Contains("ragemp") && lower.Contains("acl_bypass"))
                            || (lower.Contains("ragemp") && lower.Contains("ace_bypass"))
                            || (lower.Contains("ragemp") && lower.Contains("superadmin"))
                            || (lower.Contains("ragemp") && lower.Contains("sudo"))
                            || (lower.Contains("rage") && lower.Contains("admin_bypass"))
                            || (lower.Contains("rage") && lower.Contains("admin_hack"))
                            || (lower.Contains("rage") && lower.Contains("admin_exploit"));
                        if (isAdminAbuse)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP admin abuse tool execution (UserAssist)",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{uaPath}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"Windows UserAssist registry records execution of a RageMP admin abuse tool: '{decoded}'. " +
                                         "UserAssist tracks every GUI program launched by the user and is a reliable forensic indicator " +
                                         "of prior execution of admin exploit or permission bypass software.",
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

    private void CheckMuiCacheForAdminAbuse(ScanContext ctx, CancellationToken ct)
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
                    bool isAdminAbuse =
                        AdminToolExecutables.Any(k => lower.Contains(
                            k.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase),
                            StringComparison.OrdinalIgnoreCase))
                        || (lower.Contains("ragemp") && lower.Contains("admin"))
                        || (lower.Contains("ragemp") && lower.Contains("perm_bypass"))
                        || (lower.Contains("ragemp") && lower.Contains("permission_bypass"))
                        || (lower.Contains("ragemp") && lower.Contains("acl_bypass"))
                        || (lower.Contains("ragemp") && lower.Contains("superadmin"))
                        || (lower.Contains("ragemp") && lower.Contains("sudo"))
                        || (lower.Contains("rage") && lower.Contains("admin_bypass"))
                        || (lower.Contains("rage") && lower.Contains("admin_hack"));
                    if (isAdminAbuse)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP admin abuse tool execution (MUICache)",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\" + muiPath,
                            FileName = Path.GetFileName(valName),
                            Reason = $"Windows MUICache records a RageMP admin abuse executable was run: '{valName}'. " +
                                     "MUICache stores the friendly name of every EXE ever executed and persists " +
                                     "even after the file is deleted, providing durable forensic evidence.",
                            Detail = $"MUICache entry: {valName}"
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }

    private void CheckRunKeysForAdminAbuse(ScanContext ctx, CancellationToken ct)
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
                    bool isAdminAbuse =
                        AdminToolExecutables.Any(k => lower.Contains(
                            k.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase),
                            StringComparison.OrdinalIgnoreCase))
                        || (lower.Contains("ragemp") && lower.Contains("admin"))
                        || (lower.Contains("ragemp") && lower.Contains("perm_bypass"))
                        || (lower.Contains("ragemp") && lower.Contains("permission_bypass"))
                        || (lower.Contains("ragemp") && lower.Contains("acl_bypass"))
                        || (lower.Contains("ragemp") && lower.Contains("superadmin"))
                        || (lower.Contains("ragemp") && lower.Contains("sudo"))
                        || (lower.Contains("rage") && lower.Contains("admin_bypass"))
                        || (lower.Contains("rage") && lower.Contains("admin_exploit"));
                    if (isAdminAbuse)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP admin abuse tool autostart (Run key)",
                            Risk = RiskLevel.High,
                            Location = $@"{hiveName}\{keyPath}",
                            FileName = val,
                            Reason = $"RageMP admin abuse tool configured to auto-start via Windows Run registry key. " +
                                     $"Value '{val}' points to: '{data}'. " +
                                     "Auto-start entries indicate persistent installation of admin exploit or permission bypass software.",
                            Detail = $"Value: {val} = {data}"
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }

    private void CheckUninstallKeysForAdminAbuse(ScanContext ctx, CancellationToken ct)
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
                        bool isAdminAbuse =
                            (lower.Contains("ragemp") || lower.Contains("rage multiplayer"))
                            && (lower.Contains("admin") || lower.Contains("perm bypass")
                                || lower.Contains("permission bypass") || lower.Contains("acl bypass")
                                || lower.Contains("superadmin") || lower.Contains("sudo") || lower.Contains("oper"))
                            || (locLower.Contains("ragemp") && locLower.Contains("admin"))
                            || (locLower.Contains("ragemp") && locLower.Contains("perm_bypass"))
                            || (locLower.Contains("ragemp") && locLower.Contains("admin_bypass"));
                        if (isAdminAbuse)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP admin abuse tool installer record",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                FileName = displayName,
                                Reason = $"Uninstall registry record found for RageMP admin abuse software: '{displayName}'. " +
                                         "This indicates an admin exploit or permission bypass tool was formally installed on this system.",
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
                    bool isAdminAbuse =
                        (lower.Contains("ragemp") || lower.Contains("rage multiplayer"))
                        && (lower.Contains("admin") || lower.Contains("perm bypass")
                            || lower.Contains("permission bypass") || lower.Contains("acl bypass")
                            || lower.Contains("superadmin") || lower.Contains("sudo"));
                    if (isAdminAbuse)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP admin abuse tool installer record (HKCU)",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{subKeyName}",
                            FileName = displayName,
                            Reason = $"User-level uninstall registry record found for RageMP admin abuse software: '{displayName}'. " +
                                     "This indicates an admin exploit tool was installed or run with user-level privileges.",
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
