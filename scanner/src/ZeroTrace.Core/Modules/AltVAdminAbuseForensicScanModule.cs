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

public sealed class AltVAdminAbuseForensicScanModule : IScanModule
{
    public string Name => "alt:V Admin Abuse & Permission Exploit Forensic Scan";
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

    private static readonly string[] AdminToolExecutables =
    [
        "altv_admin.exe",
        "altv_admin_tool.exe",
        "altv_superadmin.exe",
        "altv_sudo.exe",
        "altv_oper.exe",
        "altv_admin_bypass.exe",
        "altv_perm_bypass.exe",
        "altv_permission_bypass.exe",
        "altv_admin_hack.exe",
        "altv_admin_exploit.exe",
        "admin_altv.exe",
        "admin_tool_altv.exe",
        "superadmin_altv.exe",
        "sudo_altv.exe",
        "oper_altv.exe",
        "admin_bypass_altv.exe",
        "perm_bypass_altv.exe",
        "permission_bypass_altv.exe",
        "admin_hack_altv.exe",
        "admin_exploit_altv.exe",
        "alt_admin.exe",
        "alt_admin_tool.exe",
        "alt_superadmin.exe",
        "alt_sudo.exe",
        "alt_admin_bypass.exe",
        "alt_perm_bypass.exe",
        "alt_admin_hack.exe",
        "alt_admin_exploit.exe",
        "altv_admin_menu.exe",
        "alt_admin_menu.exe",
        "altv_admin_cmd.exe",
        "alt_admin_cmd.exe",
        "altv_god.exe",
        "altv_noclip.exe",
        "altv_teleport.exe",
        "altv_ban_bypass.exe",
        "altv_kick_bypass.exe",
        "altv_mute_bypass.exe",
        "altv_warn_bypass.exe",
        "altv_freeze_bypass.exe",
        "altv_spectate.exe",
        "altv_invisible.exe",
        "altv_fly.exe",
        "admin_fly_altv.exe",
        "admin_god_altv.exe",
        "admin_noclip_altv.exe",
        "admin_teleport_altv.exe",
        "admin_ban_bypass_altv.exe",
        "admin_invisible_altv.exe",
        "altv_acl_bypass.exe",
        "altv_ace_bypass.exe",
        "altv_role_bypass.exe",
        "altv_permission_exploit.exe",
        "altv_admin_exploit_v2.exe",
        "altv_admin_hack_v2.exe",
        "altv_admin_bypass_v2.exe",
        "altv_perm_exploit.exe",
        "altv_perm_hack.exe",
        "altv_sudo_exploit.exe",
        "altv_superadmin_exploit.exe",
        "altv_oper_exploit.exe",
        "altv_admin_grief.exe",
        "altv_admin_troll.exe",
        "altv_admin_nuke.exe",
    ];

    private static readonly string[] AdminToolDlls =
    [
        "altv_admin.dll",
        "altv_admin_tool.dll",
        "altv_admin_bypass.dll",
        "altv_perm_bypass.dll",
        "altv_permission_bypass.dll",
        "altv_admin_hack.dll",
        "altv_admin_exploit.dll",
        "altv_admin_hook.dll",
        "altv_sudo.dll",
        "altv_superadmin.dll",
        "altv_oper.dll",
        "admin_bypass_altv.dll",
        "admin_hack_altv.dll",
        "admin_exploit_altv.dll",
        "alt_admin.dll",
        "alt_admin_bypass.dll",
        "alt_admin_hack.dll",
        "alt_admin_hook.dll",
        "alt_perm_bypass.dll",
        "altv_acl_bypass.dll",
        "altv_ace_bypass.dll",
        "altv_role_bypass.dll",
        "acl_bypass_altv.dll",
        "ace_bypass_altv.dll",
        "role_bypass_altv.dll",
        "altv_admin_menu.dll",
        "admin_menu_altv.dll",
        "altv_god_mode.dll",
        "altv_noclip_hack.dll",
        "altv_teleport_hack.dll",
        "altv_invisible_hack.dll",
        "altv_spectate_hack.dll",
        "altv_ban_bypass.dll",
        "altv_kick_bypass.dll",
        "altv_mute_bypass.dll",
        "altv_freeze_bypass.dll",
        "admin_god_altv.dll",
        "admin_noclip_altv.dll",
        "admin_teleport_altv.dll",
        "admin_invisible_altv.dll",
        "altv_perm_exploit.dll",
        "altv_permission_exploit.dll",
        "altv_sudo_exploit.dll",
    ];

    private static readonly string[] AdminScriptPatterns =
    [
        "alt.emit",
        "alt.emitServer",
        "alt.Player.all",
        "alt.Vehicle.all",
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
        "setPos",
        "setHealth",
        "setArmour",
        "giveWeapon",
        "spawnVehicle",
        "admin_command",
        "perm_bypass",
        "role_bypass",
        "acl_bypass",
        "ace_bypass",
    ];

    private static readonly string[] AdminConfigFileNames =
    [
        "admin_config.json",
        "admin_settings.json",
        "admin_menu.json",
        "superadmin.json",
        "permission_config.json",
        "acl_bypass.json",
        "ace_bypass.json",
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
        "altv_admin_config.json",
        "altv_admin_settings.json",
    ];

    private static readonly string[] ClientLogPatterns =
    [
        "admin bypass",
        "permission bypass",
        "sudo exploit",
        "superadmin exploit",
        "ace bypass",
        "acl bypass",
        "perm bypass",
        "role bypass",
        "ban bypass",
        "kick bypass",
        "admin god mode",
        "admin noclip",
        "admin teleport",
        "admin invisible",
        "admin spectate",
        "admin fly",
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
        "forbidden resource",
        "resource banned: admin_exploit",
        "resource kicked: admin_hack",
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
        "ace bypass detected",
        "acl bypass detected",
        "perm bypass detected",
        "role bypass detected",
        "ban bypass detected",
        "kick bypass detected",
        "admin god mode detected",
        "admin noclip detected",
        "admin teleport detected",
        "admin invisible detected",
        "admin spectate detected",
        "admin fly detected",
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
        "forbidden resource",
        "resource banned: admin_exploit",
        "resource kicked: admin_hack",
        "admin abuse detected",
        "permission exploit detected",
        "acl exploit detected",
        "ace exploit detected",
        "admin privilege escalation detected",
        "unauthorized privilege detected",
        "admin role spoof detected",
        "permission spoof detected",
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
        "ace_bypass",
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
        "altv_admin_tool",
        "alt_admin_tool",
        "altv_admin_menu",
    ];

    private static readonly string[] DownloadArchiveNames =
    [
        "altv_admin.zip",
        "altv_admin_tool.zip",
        "altv_admin_bypass.zip",
        "altv_perm_bypass.zip",
        "altv_admin_hack.zip",
        "altv_admin_exploit.zip",
        "altv_superadmin.zip",
        "altv_sudo.zip",
        "altv_admin.rar",
        "altv_admin_tool.rar",
        "altv_admin_bypass.rar",
        "altv_perm_bypass.rar",
        "altv_admin_hack.rar",
        "altv_admin_exploit.rar",
        "altv_superadmin.rar",
        "altv_admin.7z",
        "altv_admin_tool.7z",
        "altv_admin_bypass.7z",
        "admin_bypass_altv.zip",
        "admin_hack_altv.zip",
        "admin_exploit_altv.zip",
        "admin_bypass_altv.rar",
        "admin_hack_altv.rar",
        "alt_admin.zip",
        "alt_admin_tool.zip",
        "alt_admin_bypass.zip",
        "alt_admin_hack.zip",
        "alt_admin.rar",
        "alt_admin_tool.rar",
        "alt_admin_bypass.rar",
        "altv_admin_setup.exe",
        "altv_admin_tool_setup.exe",
        "altv_admin_bypass_setup.exe",
        "altv_perm_bypass_setup.exe",
        "altv_admin_hack_setup.exe",
        "altv_superadmin_setup.exe",
        "admin_tool_altv_setup.exe",
        "alt_admin_setup.exe",
        "alt_admin_tool_setup.exe",
        "altv_admin_v2.exe",
        "altv_admin_tool_v2.exe",
        "altv_admin_bypass_v2.exe",
        "altv_admin_menu_setup.exe",
        "admin_menu_altv_setup.exe",
        "altv_acl_bypass_setup.exe",
        "altv_ace_bypass_setup.exe",
        "altv_permission_exploit_setup.exe",
        "altv_perm_exploit_setup.exe",
        "altv_sudo_exploit_setup.exe",
        "altv_superadmin_exploit_setup.exe",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckAltVAdminToolExecutables(ctx, ct),
            CheckAltVAdminToolDlls(ctx, ct),
            CheckAltVAdminScriptFiles(ctx, ct),
            CheckAltVAdminConfigFiles(ctx, ct),
            CheckAltVAdminClientLogs(ctx, ct),
            CheckAltVAdminServerLogs(ctx, ct),
            CheckAltVAdminResourceFolders(ctx, ct),
            CheckAltVAdminDownloadArtifacts(ctx, ct),
            CheckRegistryForAltVAdminAbuse(ctx, ct)
        );
    }

    private Task CheckAltVAdminToolExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>(AltVBasePaths)
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
                            Title = "alt:V admin abuse tool executable detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known alt:V admin abuse or permission exploit executable '{fn}' found on disk. " +
                                     "These tools are used to impersonate server admins, bypass ACL/ACE permission checks, escalate privileges, " +
                                     "or exploit admin command systems on alt:V GTA:V multiplayer servers.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckAltVAdminToolDlls(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>(AltVBasePaths)
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
                            Title = "alt:V admin abuse DLL detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known alt:V admin abuse or permission exploit DLL '{fn}' found on disk. " +
                                     "Admin abuse DLLs targeting alt:V are typically injected into the client or server process " +
                                     "to intercept ACL/ACE permission checks, forge admin credentials, or enable unauthorized admin commands.",
                            Detail = $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
        await Task.CompletedTask;
    }, ct);

    private Task CheckAltVAdminScriptFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var baseDir in AltVBasePaths)
        {
            foreach (var subDir in new[] { "resources", "client_packages" })
            {
                var searchRoot = Path.Combine(baseDir, subDir);
                if (!Directory.Exists(searchRoot)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(searchRoot, maxDepth: 7, ct))
                    {
                        var ext = Path.GetExtension(file);
                        bool isScript = ext.Equals(".js", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".mjs", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".cjs", StringComparison.OrdinalIgnoreCase)
                            || ext.Equals(".ts", StringComparison.OrdinalIgnoreCase);
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
                                Title = $"alt:V admin abuse script: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(file) ?? searchRoot,
                                FileName = Path.GetFileName(file),
                                Reason = $"alt:V script file contains {hits} admin abuse or permission exploit patterns " +
                                         $"(first match: '{firstMatch}'). Scripts with 4+ of these patterns strongly indicate admin bypass, " +
                                         "privilege escalation via alt:V ACL/ACE, or unauthorized admin command abuse targeting alt:V servers.",
                                Detail = $"File: {file} | Pattern hits: {hits} | First match: {firstMatch}"
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckAltVAdminConfigFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>(AltVBasePaths)
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
                            Title = $"alt:V admin abuse config file: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Admin abuse configuration file '{fn}' found. These files are generated by alt:V admin exploit tools " +
                                     "to store target server addresses, bypassed ACL/ACE permission lists, spoofed admin roles, " +
                                     "or exploit parameters for alt:V GTA:V multiplayer servers.",
                            Detail = preview is not null ? $"Preview: {preview}" : $"Full path: {file}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }, ct);

    private Task CheckAltVAdminClientLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
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
                                Title = "alt:V client log: admin abuse artifact",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(logFile) ?? baseDir,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"alt:V client log contains admin abuse pattern: '{pattern}'. " +
                                         "Client logs record cheat tool activity including admin bypass attempts, " +
                                         "ACL/ACE permission exploit confirmations, and unauthorized admin command usage on alt:V servers.",
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

    private Task CheckAltVAdminServerLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
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
            @"C:\altv-server\logs",
            @"C:\altv_server\logs",
            @"C:\alt-server\logs",
            @"C:\altv\server\logs",
            @"C:\altv-server\log",
            @"C:\altv_server\log",
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
                                Title = "alt:V server log: admin abuse detection record",
                                Risk = RiskLevel.High,
                                Location = logDir,
                                FileName = Path.GetFileName(logFile),
                                Reason = $"alt:V server log contains admin abuse detection record: '{pattern}'. " +
                                         "Server logs record ban/kick events, detected permission exploits, ACL/ACE bypass attempts, " +
                                         "and forbidden resource loads that indicate use of admin abuse tools on alt:V multiplayer servers.",
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

    private Task CheckAltVAdminResourceFolders(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var baseDir in AltVBasePaths)
        {
            foreach (var subDir in new[] { "resources", "client_packages" })
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
                                Title = $"alt:V admin abuse resource folder: {folderName}",
                                Risk = RiskLevel.High,
                                Location = searchRoot,
                                FileName = folderName,
                                Reason = $"alt:V {subDir} folder '{folderName}' matches known admin abuse or permission exploit naming patterns. " +
                                         "Admin exploit packages installed as alt:V resources can bypass ACL/ACE server permission checks, " +
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

    private Task CheckAltVAdminDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
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
                            Title = $"alt:V admin abuse tool download artifact: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"alt:V admin abuse tool archive or installer '{fn}' found in {dir}. " +
                                     "Downloaded admin exploit archives and setup executables indicate prior acquisition of " +
                                     "admin bypass software targeting alt:V multiplayer servers.",
                            Detail = $"Full path: {file}"
                        });
                    }
                    else
                    {
                        var fnLower = fn.ToLowerInvariant();
                        bool isSuspicious =
                            (fnLower.Contains("altv") || fnLower.Contains("alt_v") || fnLower.Contains("alt-v"))
                            && (fnLower.Contains("admin") || fnLower.Contains("superadmin") || fnLower.Contains("perm_bypass")
                                || fnLower.Contains("permission_bypass") || fnLower.Contains("acl_bypass")
                                || fnLower.Contains("ace_bypass") || fnLower.Contains("role_bypass")
                                || fnLower.Contains("sudo") || fnLower.Contains("oper"));
                        if (isSuspicious)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V admin abuse download artifact (heuristic): {fn}",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(file) ?? dir,
                                FileName = fn,
                                Reason = $"File '{fn}' in {dir} contains both alt:V-related and admin abuse-related terms in its name. " +
                                         "Heuristic match indicates a likely admin exploit tool or permission bypass archive targeting alt:V.",
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

    private Task CheckRegistryForAltVAdminAbuse(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
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
                            || (lower.Contains("altv") && lower.Contains("admin"))
                            || (lower.Contains("altv") && lower.Contains("perm_bypass"))
                            || (lower.Contains("altv") && lower.Contains("permission_bypass"))
                            || (lower.Contains("altv") && lower.Contains("acl_bypass"))
                            || (lower.Contains("altv") && lower.Contains("ace_bypass"))
                            || (lower.Contains("altv") && lower.Contains("superadmin"))
                            || (lower.Contains("altv") && lower.Contains("sudo"))
                            || (lower.Contains("alt_v") && lower.Contains("admin_bypass"))
                            || (lower.Contains("alt-v") && lower.Contains("admin_hack"))
                            || (lower.Contains("alt.v") && lower.Contains("admin_exploit"));
                        if (isAdminAbuse)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V admin abuse tool execution (UserAssist)",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{uaPath}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"Windows UserAssist registry records execution of an alt:V admin abuse tool: '{decoded}'. " +
                                         "UserAssist tracks every GUI program launched by the user and is a reliable forensic indicator " +
                                         "of prior execution of admin exploit or ACL/ACE permission bypass software for alt:V.",
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
                        || (lower.Contains("altv") && lower.Contains("admin"))
                        || (lower.Contains("altv") && lower.Contains("perm_bypass"))
                        || (lower.Contains("altv") && lower.Contains("permission_bypass"))
                        || (lower.Contains("altv") && lower.Contains("acl_bypass"))
                        || (lower.Contains("altv") && lower.Contains("ace_bypass"))
                        || (lower.Contains("altv") && lower.Contains("superadmin"))
                        || (lower.Contains("altv") && lower.Contains("sudo"))
                        || (lower.Contains("alt_v") && lower.Contains("admin_bypass"))
                        || (lower.Contains("alt-v") && lower.Contains("admin_hack"));
                    if (isAdminAbuse)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V admin abuse tool execution (MUICache)",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\" + muiPath,
                            FileName = Path.GetFileName(valName),
                            Reason = $"Windows MUICache records an alt:V admin abuse executable was run: '{valName}'. " +
                                     "MUICache stores the friendly name of every EXE ever executed and persists " +
                                     "even after the file is deleted, providing durable forensic evidence of admin exploit tool usage.",
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
                        || (lower.Contains("altv") && lower.Contains("admin"))
                        || (lower.Contains("altv") && lower.Contains("perm_bypass"))
                        || (lower.Contains("altv") && lower.Contains("permission_bypass"))
                        || (lower.Contains("altv") && lower.Contains("acl_bypass"))
                        || (lower.Contains("altv") && lower.Contains("ace_bypass"))
                        || (lower.Contains("altv") && lower.Contains("superadmin"))
                        || (lower.Contains("altv") && lower.Contains("sudo"))
                        || (lower.Contains("alt_v") && lower.Contains("admin_bypass"))
                        || (lower.Contains("alt-v") && lower.Contains("admin_exploit"));
                    if (isAdminAbuse)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V admin abuse tool autostart (Run key)",
                            Risk = RiskLevel.High,
                            Location = $@"{hiveName}\{keyPath}",
                            FileName = val,
                            Reason = $"alt:V admin abuse tool configured to auto-start via Windows Run registry key. " +
                                     $"Value '{val}' points to: '{data}'. " +
                                     "Auto-start entries indicate persistent installation of admin exploit or ACL/ACE permission bypass software for alt:V.",
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
                            (lower.Contains("altv") || lower.Contains("alt:v") || lower.Contains("alt-v"))
                            && (lower.Contains("admin") || lower.Contains("perm bypass")
                                || lower.Contains("permission bypass") || lower.Contains("acl bypass")
                                || lower.Contains("ace bypass") || lower.Contains("superadmin")
                                || lower.Contains("sudo") || lower.Contains("oper"))
                            || (locLower.Contains("altv") && locLower.Contains("admin"))
                            || (locLower.Contains("altv") && locLower.Contains("perm_bypass"))
                            || (locLower.Contains("altv") && locLower.Contains("admin_bypass"));
                        if (isAdminAbuse)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V admin abuse tool installer record",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                FileName = displayName,
                                Reason = $"Uninstall registry record found for alt:V admin abuse software: '{displayName}'. " +
                                         "This indicates an admin exploit or ACL/ACE permission bypass tool was formally installed on this system.",
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
                        (lower.Contains("altv") || lower.Contains("alt:v") || lower.Contains("alt-v"))
                        && (lower.Contains("admin") || lower.Contains("perm bypass")
                            || lower.Contains("permission bypass") || lower.Contains("acl bypass")
                            || lower.Contains("ace bypass") || lower.Contains("superadmin")
                            || lower.Contains("sudo"));
                    if (isAdminAbuse)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V admin abuse tool installer record (HKCU)",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{subKeyName}",
                            FileName = displayName,
                            Reason = $"User-level uninstall registry record found for alt:V admin abuse software: '{displayName}'. " +
                                     "This indicates an admin exploit tool was installed or run with user-level privileges on this system.",
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
