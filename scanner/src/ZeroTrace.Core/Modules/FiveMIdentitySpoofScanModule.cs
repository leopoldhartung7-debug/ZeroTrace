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

public sealed class FiveMIdentitySpoofScanModule : IScanModule
{
    public string Name => "FiveM Identity & License Spoof Forensic Scan";
    public double Weight => 4.2;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    // -------------------------------------------------------------------------
    // Executable names (65+)
    // -------------------------------------------------------------------------
    private static readonly string[] SpoofExecutables =
    {
        "fivem_spoof.exe", "fivem_hwid_spoof.exe", "fivem_license_spoof.exe",
        "fivem_id_spoof.exe", "fivem_ban_evade.exe", "fivem_ban_bypass.exe",
        "fivem_unban.exe", "fivem_identity_spoof.exe", "fivem_ip_spoof.exe",
        "fivem_mac_spoof.exe", "hwid_spoof_fivem.exe", "license_spoof_fivem.exe",
        "id_spoof_fivem.exe", "ban_evade_fivem.exe", "ban_bypass_fivem.exe",
        "unban_fivem.exe", "identity_spoof_fivem.exe", "ip_spoof_fivem.exe",
        "mac_spoof_fivem.exe", "spoof_fivem.exe", "hwid_spoof.exe",
        "license_spoof.exe", "id_spoof.exe", "ban_evade.exe", "ban_bypass.exe",
        "unban.exe", "identity_spoof.exe", "ip_spoof.exe", "mac_spoof.exe",
        "fivem_uuid_spoof.exe", "fivem_guid_spoof.exe", "fivem_steam_spoof.exe",
        "fivem_discord_spoof.exe", "fivem_xbl_spoof.exe", "fivem_fivem_spoof.exe",
        "fivem_ros_spoof.exe", "fivem_rockstar_spoof.exe", "uuid_spoof_fivem.exe",
        "guid_spoof_fivem.exe", "steam_spoof_fivem.exe", "discord_spoof_fivem.exe",
        "xbl_spoof_fivem.exe", "ros_spoof_fivem.exe", "rockstar_spoof_fivem.exe",
        "fivem_cloneid.exe", "fivem_clone_hwid.exe", "fivem_hwid_changer.exe",
        "fivem_license_changer.exe", "fivem_id_changer.exe",
        "fivem_identity_changer.exe", "hwid_changer_fivem.exe",
        "license_changer_fivem.exe", "identity_changer_fivem.exe",
        "fivem_ban_remove.exe", "fivem_ban_clear.exe", "fivem_unban_tool.exe",
        "ban_remove_fivem.exe", "ban_clear_fivem.exe", "unban_tool_fivem.exe",
        "fivem_spoof_v2.exe", "hwid_spoof_v2.exe", "ban_bypass_v2.exe",
        "license_spoof_v2.exe", "id_spoof_v2.exe", "ban_evade_v2.exe",
    };

    // -------------------------------------------------------------------------
    // DLL names (45+)
    // -------------------------------------------------------------------------
    private static readonly string[] SpoofDlls =
    {
        "fivem_spoof.dll", "hwid_spoof.dll", "license_spoof.dll", "id_spoof.dll",
        "ban_evade.dll", "ban_bypass.dll", "identity_spoof.dll", "ip_spoof.dll",
        "mac_spoof.dll", "uuid_spoof.dll", "guid_spoof.dll", "steam_spoof.dll",
        "discord_spoof.dll", "xbl_spoof.dll", "ros_spoof.dll", "rockstar_spoof.dll",
        "hwid_changer.dll", "license_changer.dll", "identity_changer.dll",
        "ban_remove.dll", "ban_clear.dll", "fivem_spoof_v2.dll",
        "hwid_spoof_v2.dll", "ban_bypass_v2.dll", "license_spoof_v2.dll",
        "spoof_hook.dll", "spoof_inject.dll", "spoof_bypass.dll",
        "hwid_hook.dll", "license_hook.dll", "id_hook.dll", "ban_hook.dll",
        "identity_hook.dll", "spoof_loader.dll", "hwid_loader.dll",
        "license_loader.dll", "ban_loader.dll", "identity_loader.dll",
        "spoof_dll.dll", "hwid_dll.dll", "license_dll.dll", "ban_dll.dll",
        "identity_dll.dll", "spoof_lib.dll", "hwid_lib.dll",
    };

    // -------------------------------------------------------------------------
    // Resource folder names (50+)
    // -------------------------------------------------------------------------
    private static readonly string[] SpoofResourceFolders =
    {
        "spoof", "hwid_spoof", "license_spoof", "id_spoof", "ban_evade",
        "ban_bypass", "identity_spoof", "ip_spoof", "mac_spoof", "uuid_spoof",
        "guid_spoof", "steam_spoof", "discord_spoof", "xbl_spoof", "ros_spoof",
        "rockstar_spoof", "hwid_changer", "license_changer", "identity_changer",
        "ban_remove", "ban_clear", "unban", "fivem_spoof", "spoof_v2",
        "hwid_spoof_v2", "ban_bypass_v2", "license_spoof_v2", "ban_evade_v2",
        "spoof_tool", "hwid_tool", "license_tool", "ban_tool", "identity_tool",
        "spoof_menu", "hwid_menu", "license_menu", "ban_menu", "identity_menu",
        "license_bypass", "hwid_bypass", "id_bypass", "ban_evade_tool",
        "unban_tool", "clone_hwid", "clone_id", "clone_license", "spoof_all",
        "hwid_all", "license_all", "id_all",
    };

    // -------------------------------------------------------------------------
    // Lua content keywords — flag file if 4+ are found
    // -------------------------------------------------------------------------
    private static readonly string[] LuaSpoofKeywords =
    {
        "GetPlayerIdentifiers", "GetPlayerIdentifier", "spoof", "hwid",
        "license", "ban_bypass", "ban_evade", "identity_spoof", "ip_spoof",
        "mac_spoof", "uuid_spoof", "guid_spoof", "steam_spoof", "discord_spoof",
        "xbl_spoof", "ros_spoof", "hwid_changer", "license_changer",
        "identity_changer", "ban_remove", "ban_clear", "fake_identity",
        "fake_license", "fake_hwid", "bypass_ban", "evade_ban", "change_hwid",
        "change_license", "change_identity",
    };

    // -------------------------------------------------------------------------
    // Client log patterns (45+)
    // -------------------------------------------------------------------------
    private static readonly string[] ClientLogPatterns =
    {
        "hwid spoof detected", "license spoof detected", "identity spoof detected",
        "ban bypass detected", "ban evasion detected", "ip spoof", "mac spoof",
        "uuid spoof", "guid spoof", "steam spoof", "discord spoof", "xbl spoof",
        "ros spoof", "rockstar spoof", "hwid changer", "license changer",
        "identity changer", "ban removed", "ban cleared", "spoof hook detected",
        "spoof inject detected", "fake identity", "fake license", "fake hwid",
        "anti-cheat: spoof", "ac: hwid", "ac: license", "ac: identity",
        "ac: ban_bypass", "ban for spoofing", "kick for spoofing",
        "suspicious hwid", "suspicious license", "suspicious identity",
        "suspicious ban history", "duplicate hwid", "duplicate license",
        "duplicate identity", "hwid mismatch", "license mismatch",
        "identity mismatch", "spoof bypass", "spoofer detected",
        "ban evasion tool", "unban tool detected", "clone hwid",
    };

    // -------------------------------------------------------------------------
    // Server log patterns (45+)
    // -------------------------------------------------------------------------
    private static readonly string[] ServerLogPatterns =
    {
        "spoof detected", "hwid spoof", "license spoof", "identity spoof",
        "ban bypass", "ban evasion", "duplicate hwid", "duplicate license",
        "duplicate identity", "banned player detected", "previously banned",
        "ban evaded", "identity mismatch", "license mismatch", "hwid mismatch",
        "suspicious identity", "suspicious license", "suspicious hwid",
        "anti-cheat: spoof", "ac: hwid", "ac: license", "ac: identity",
        "ban for spoofing", "kick for spoofing", "server ban list match",
        "global ban list match", "spoof tool", "hwid changer detected",
        "license changer detected", "identity changer detected",
        "fake hwid", "fake license", "fake identity", "ban clear attempt",
        "ban remove attempt", "unban attempt", "spoof inject",
        "spoof hook", "clone identity", "clone hwid detected",
        "duplicate player", "ban evasion attempt", "hwid clone",
        "license clone", "identity clone", "spoofer",
    };

    // -------------------------------------------------------------------------
    // Download artifact names (50+)
    // -------------------------------------------------------------------------
    private static readonly string[] SpoofArchivePatterns =
    {
        "fivem_spoof", "hwid_spoof_fivem", "license_spoof_fivem",
        "fivem_ban_bypass", "fivem_ban_evade", "fivem_unban",
        "fivem_identity_spoof", "fivem_hwid_changer", "fivem_license_changer",
        "fivem_id_changer", "ban_bypass_fivem", "ban_evade_fivem",
        "unban_fivem", "spoof_fivem", "hwid_changer_fivem",
        "identity_changer_fivem", "fivem_spoof_v2", "hwid_spoof_v2_fivem",
        "ban_bypass_v2_fivem", "fivem_clone_hwid", "fivem_clone_id",
        "fivem_clone_license", "fivem_ban_remove", "fivem_ban_clear",
        "fivem_unban_tool", "fivem_uuid_spoof", "fivem_guid_spoof",
        "fivem_steam_spoof", "fivem_discord_spoof", "fivem_xbl_spoof",
        "fivem_ros_spoof", "fivem_rockstar_spoof", "spoof_all_fivem",
        "hwid_all_fivem", "license_all_fivem", "id_all_fivem",
        "fivem_spoof_tool", "hwid_spoof_tool_fivem", "license_spoof_tool",
        "ban_evade_tool_fivem", "unban_tool_fivem", "identity_spoof_tool",
        "fivem_ip_spoof", "fivem_mac_spoof", "ip_spoof_fivem",
        "mac_spoof_fivem", "fivem_hwid_bypass", "hwid_bypass_fivem",
        "license_bypass_fivem", "id_bypass_fivem",
    };

    // -------------------------------------------------------------------------
    // UserAssist ROT13 targets (35+) — decoded values
    // -------------------------------------------------------------------------
    private static readonly string[] UserAssistDecodedTargets =
    {
        "fivem_spoof", "hwid_spoof_fivem", "license_spoof_fivem",
        "fivem_ban_bypass", "fivem_ban_evade", "fivem_unban",
        "fivem_identity_spoof", "fivem_hwid_changer", "fivem_license_changer",
        "ban_bypass_fivem", "ban_evade_fivem", "unban_fivem",
        "spoof_fivem", "hwid_changer_fivem", "fivem_spoof_v2",
        "ban_bypass_v2", "id_spoof_fivem", "fivem_id_changer",
        "fivem_mac_spoof", "fivem_ip_spoof", "fivem_uuid_spoof",
        "fivem_guid_spoof", "fivem_steam_spoof", "fivem_discord_spoof",
        "fivem_xbl_spoof", "fivem_ros_spoof", "fivem_rockstar_spoof",
        "fivem_clone_hwid", "fivem_ban_remove", "fivem_ban_clear",
        "fivem_unban_tool", "hwid_spoof_v2", "license_spoof_v2",
        "id_spoof_v2", "ban_evade_v2",
    };

    // -------------------------------------------------------------------------
    // MUICache targets (30+)
    // -------------------------------------------------------------------------
    private static readonly string[] MuiCacheTargets =
    {
        "fivem_spoof", "hwid_spoof_fivem", "license_spoof_fivem",
        "fivem_ban_bypass", "fivem_unban", "fivem_identity_spoof",
        "fivem_hwid_changer", "ban_bypass_fivem", "ban_evade_fivem",
        "spoof_fivem", "hwid_changer_fivem", "fivem_spoof_v2",
        "ban_bypass_v2", "id_spoof_fivem", "fivem_id_changer",
        "fivem_mac_spoof", "fivem_ip_spoof", "fivem_steam_spoof",
        "fivem_discord_spoof", "fivem_clone_hwid", "fivem_ban_remove",
        "hwid_spoof_v2", "license_spoof_v2", "id_spoof_v2",
        "ban_evade_v2", "fivem_ros_spoof", "fivem_rockstar_spoof",
        "fivem_unban_tool", "fivem_ban_clear", "fivem_guid_spoof",
    };

    // -------------------------------------------------------------------------
    // Software registry subkey names for HKCU/HKLM spoof tool installs
    // -------------------------------------------------------------------------
    private static readonly string[] SpoofSoftwareKeys =
    {
        "FiveMSpoof", "HwidSpoofFiveM", "LicenseSpoofFiveM",
        "FiveMBanBypass", "FiveMBanEvade", "FiveMUnban",
        "FiveMIdentitySpoof", "FiveMHwidChanger", "FiveMBanRemove",
        "BanBypassFiveM", "SpoofFiveM", "HwidChangerFiveM",
        "FiveMSpoofV2", "BanBypassV2", "IdSpoofFiveM",
        "FiveMIdentityChanger", "FiveMCloneHwid", "FiveMUnbanTool",
    };

    // -------------------------------------------------------------------------
    // Archive extensions for download artifact scan
    // -------------------------------------------------------------------------
    private static readonly string[] ArchiveExtensions =
        { ".zip", ".rar", ".7z", ".gz", ".cab", ".tar", ".iso" };

    // =========================================================================
    // RunAsync — parallel dispatch
    // =========================================================================

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.WhenAll(
            CheckIdentitySpoofExecutables(ctx, ct),
            CheckIdentitySpoofDlls(ctx, ct),
            CheckIdentitySpoofResourceFolders(ctx, ct),
            CheckIdentitySpoofLuaFiles(ctx, ct),
            CheckIdentitySpoofClientLogs(ctx, ct),
            CheckIdentitySpoofServerLogs(ctx, ct),
            CheckIdentitySpoofDownloadArtifacts(ctx, ct),
            CheckRegistryForIdentitySpoof(ctx, ct),
            CheckIdentitySpoofConfigFiles(ctx, ct),
            CheckIdentitySpoofPrefetch(ctx, ct),
            CheckIdentitySpoofTempArtifacts(ctx, ct),
            CheckHostsFileForSpoofTampering(ctx, ct),
            CheckIdentitySpoofAppDataFolders(ctx, ct)
        );
    }

    // =========================================================================
    // 1. Executable scan
    // =========================================================================

    private Task CheckIdentitySpoofExecutables(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = BuildSearchDirectories();

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string fileName = Path.GetFileName(file);
                    bool matched = SpoofExecutables.Any(e =>
                        fileName.Equals(e, StringComparison.OrdinalIgnoreCase));

                    if (!matched) continue;

                    string content = string.Empty;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Identity/License Spoof Executable: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"Executable '{fileName}' matches a known FiveM identity/license spoofing " +
                                 "or ban evasion tool name. These tools manipulate HWID, license tokens, " +
                                 "IP addresses, MAC addresses or other identifiers reported to FiveM servers " +
                                 "in order to evade bans and create false identities.",
                        Detail = $"Directory: {dir}"
                    });
                }
            }
        }, ct);

    // =========================================================================
    // 2. DLL scan
    // =========================================================================

    private Task CheckIdentitySpoofDlls(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = BuildSearchDirectories();

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string fileName = Path.GetFileName(file);
                    bool matched = SpoofDlls.Any(d =>
                        fileName.Equals(d, StringComparison.OrdinalIgnoreCase));

                    if (!matched) continue;

                    string content = string.Empty;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Spoof/Bypass DLL: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"DLL '{fileName}' matches a known FiveM identity spoofing or ban bypass " +
                                 "library name. These DLLs are typically injected into the FiveM client " +
                                 "process to intercept and alter identity-related API calls, forging " +
                                 "HWID values, license tokens, and network addresses reported to servers.",
                        Detail = $"Directory: {dir}"
                    });
                }
            }
        }, ct);

    // =========================================================================
    // 3. Resource folder scan
    // =========================================================================

    private Task CheckIdentitySpoofResourceFolders(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var fivemDir = FindFiveMDirectory();
            var resourceRoots = new List<string>();

            if (fivemDir != null)
            {
                resourceRoots.Add(Path.Combine(fivemDir, "FiveM.app", "resources"));
                resourceRoots.Add(Path.Combine(fivemDir, "resources"));
                resourceRoots.Add(Path.Combine(fivemDir, "citizen", "resources"));
                resourceRoots.Add(fivemDir);
            }

            // Also scan common user directories for leftover resource folders
            resourceRoots.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            resourceRoots.Add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));

            foreach (var root in resourceRoots)
            {
                if (!Directory.Exists(root)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> subdirs;
                try
                {
                    subdirs = Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var subdir in subdirs)
                {
                    ct.ThrowIfCancellationRequested();

                    string folderName = Path.GetFileName(subdir);
                    bool matched = SpoofResourceFolders.Any(f =>
                        folderName.Equals(f, StringComparison.OrdinalIgnoreCase));

                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Spoof Resource Folder: {folderName}",
                        Risk = RiskLevel.High,
                        Location = subdir,
                        FileName = folderName,
                        Reason = $"Directory '{folderName}' matches a known FiveM identity/license spoof " +
                                 "resource folder name. FiveM cheat resources that spoof player identities, " +
                                 "HWID values, license tokens, or ban history are typically distributed " +
                                 "as resource folders placed into the FiveM resources directory.",
                        Detail = $"Parent: {root}"
                    });
                }
            }
        }, ct);

    // =========================================================================
    // 4. Lua file content scan
    // =========================================================================

    private Task CheckIdentitySpoofLuaFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = BuildSearchDirectories();
            var fivemDir = FindFiveMDirectory();
            if (fivemDir != null && !searchDirs.Contains(fivemDir, StringComparer.OrdinalIgnoreCase))
                searchDirs.Add(fivemDir);

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(dir, "*.lua", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in files)
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
                    catch (IOException)
                    {
                        continue;
                    }

                    var matched = LuaSpoofKeywords
                        .Where(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matched.Count < 4) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Lua Identity Spoof Script: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Lua file contains {matched.Count} identity/license spoofing keywords. " +
                                 "The combination of these API calls and keywords indicates a script " +
                                 "designed to forge player identifiers, bypass ban systems, or manipulate " +
                                 "HWID/license data within a FiveM server resource context.",
                        Detail = $"Matched keywords ({matched.Count}): {string.Join(", ", matched.Take(10))}"
                    });
                }
            }
        }, ct);

    // =========================================================================
    // 5. Client log scan
    // =========================================================================

    private Task CheckIdentitySpoofClientLogs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var logDirs = new List<string>();
            var fivemDir = FindFiveMDirectory();

            if (fivemDir != null)
            {
                logDirs.Add(Path.Combine(fivemDir, "FiveM.app", "logs"));
                logDirs.Add(Path.Combine(fivemDir, "FiveM.app"));
                logDirs.Add(Path.Combine(fivemDir, "logs"));
                logDirs.Add(fivemDir);
            }

            logDirs.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FiveM", "FiveM.app", "logs"));
            logDirs.Add(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FiveM"));

            foreach (var logDir in logDirs)
            {
                if (!Directory.Exists(logDir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> logFiles;
                try
                {
                    logFiles = Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories)
                        .Concat(Directory.EnumerateFiles(logDir, "*.txt", SearchOption.AllDirectories));
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

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
                    catch (IOException)
                    {
                        continue;
                    }

                    foreach (var pattern in ClientLogPatterns)
                    {
                        if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM Client Log: Identity Spoof Indicator",
                            Risk = RiskLevel.High,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"FiveM client log contains the pattern '{pattern}', which indicates " +
                                     "that identity spoofing or ban bypass activity was detected or logged " +
                                     "during a previous FiveM session. This is a forensic artifact left " +
                                     "behind by spoofing tools or by anti-cheat systems flagging the activity.",
                            Detail = $"Pattern matched: {pattern}"
                        });
                        break;
                    }
                }
            }
        }, ct);

    // =========================================================================
    // 6. Server log scan
    // =========================================================================

    private Task CheckIdentitySpoofServerLogs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            // FiveM server logs may be present if the user runs a local server
            var serverLogDirs = new List<string>();
            var fivemDir = FindFiveMDirectory();

            if (fivemDir != null)
            {
                serverLogDirs.Add(Path.Combine(fivemDir, "server-data", "logs"));
                serverLogDirs.Add(Path.Combine(fivemDir, "server", "logs"));
                serverLogDirs.Add(Path.Combine(fivemDir, "server-data"));
                serverLogDirs.Add(Path.Combine(fivemDir, "server"));
            }

            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            serverLogDirs.Add(Path.Combine(userProfile, "FXServer", "logs"));
            serverLogDirs.Add(Path.Combine(userProfile, "FXServer"));
            serverLogDirs.Add(Path.Combine(userProfile, "server-data", "logs"));
            serverLogDirs.Add(Path.Combine(userProfile, "fivem-server", "logs"));

            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            serverLogDirs.Add(Path.Combine(programData, "FXServer", "logs"));
            serverLogDirs.Add(Path.Combine(programData, "cfx-server-data", "logs"));

            foreach (var logDir in serverLogDirs)
            {
                if (!Directory.Exists(logDir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> logFiles;
                try
                {
                    logFiles = Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories)
                        .Concat(Directory.EnumerateFiles(logDir, "*.txt", SearchOption.AllDirectories));
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

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
                    catch (IOException)
                    {
                        continue;
                    }

                    foreach (var pattern in ServerLogPatterns)
                    {
                        if (!content.Contains(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Server Log: Identity Spoof / Ban Evasion Indicator",
                            Risk = RiskLevel.High,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"FiveM server log contains the pattern '{pattern}', indicating that " +
                                     "identity spoofing, ban evasion, or duplicate identity events were " +
                                     "logged by a local FiveM server. This is a forensic artifact suggesting " +
                                     "active use of spoofing tools against players or the local server's " +
                                     "anti-cheat mechanisms.",
                            Detail = $"Pattern matched: {pattern}"
                        });
                        break;
                    }
                }
            }
        }, ct);

    // =========================================================================
    // 7. Download artifact scan
    // =========================================================================

    private Task CheckIdentitySpoofDownloadArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var scanDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads",
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            };

            foreach (var dir in scanDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string ext = Path.GetExtension(file);
                    if (!ArchiveExtensions.Any(e => e.Equals(ext, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    string fileName = Path.GetFileNameWithoutExtension(file);
                    bool matched = SpoofArchivePatterns.Any(p =>
                        fileName.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Spoof Tool Archive: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Archive '{Path.GetFileName(file)}' matches a known FiveM identity/license " +
                                 "spoofing or ban bypass tool distribution package name. Such archives " +
                                 "are commonly used to distribute HWID spoofers, license changers, " +
                                 "and ban evasion tools targeting the FiveM platform.",
                        Detail = $"Directory: {dir}"
                    });
                }
            }
        }, ct);

    // =========================================================================
    // 8. Registry scan
    // =========================================================================

    private Task CheckRegistryForIdentitySpoof(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            CheckUserAssistForIdentitySpoof(ctx, ct);
            CheckMuiCacheForIdentitySpoof(ctx, ct);
            CheckRunKeysForIdentitySpoof(ctx, ct);
            CheckSoftwareKeysForIdentitySpoof(ctx, ct);
            CheckUninstallKeysForIdentitySpoof(ctx, ct);
        }, ct);

    private void CheckUserAssistForIdentitySpoof(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var ua = baseKey.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (ua is null) return;

            foreach (var guid in ua.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var count = ua.OpenSubKey($@"{guid}\Count");
                if (count is null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var valueName in count.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    string decoded = Rot13Decode(valueName);
                    if (string.IsNullOrWhiteSpace(decoded)) continue;

                    bool matched = UserAssistDecodedTargets.Any(t =>
                        decoded.Contains(t, StringComparison.OrdinalIgnoreCase));
                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "UserAssist: FiveM Identity Spoof Tool Execution",
                        Risk = RiskLevel.High,
                        Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                        FileName = Path.GetFileName(decoded.TrimEnd('\\')),
                        Reason = $"UserAssist registry (ROT13-decoded) records execution of '{decoded}', " +
                                 "which matches a known FiveM identity spoofing or ban bypass tool. " +
                                 "UserAssist retains execution history even after the file is deleted, " +
                                 "making this a strong forensic indicator of past spoof tool usage.",
                        Detail = $"Decoded value: {decoded}"
                    });
                }
            }
        }
        catch { }
    }

    private void CheckMuiCacheForIdentitySpoof(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var muiCache = baseKey.OpenSubKey(
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache");
            if (muiCache is null) return;
            ctx.IncrementRegistryKeys();

            foreach (var valueName in muiCache.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(valueName)) continue;

                bool matched = MuiCacheTargets.Any(t =>
                    valueName.Contains(t, StringComparison.OrdinalIgnoreCase));
                if (!matched) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "MUICache: FiveM Identity Spoof Tool Reference",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\Classes\Local Settings\...\MuiCache",
                    FileName = Path.GetFileName(valueName.TrimEnd('\\')),
                    Reason = $"MUICache entry '{valueName}' references a known FiveM identity spoofing " +
                             "or ban bypass tool. MUICache records the friendly names of recently " +
                             "executed applications, persisting even after the executable is removed, " +
                             "providing a forensic execution trail.",
                    Detail = $"MUICache value: {valueName}"
                });
            }
        }
        catch { }
    }

    private void CheckRunKeysForIdentitySpoof(ScanContext ctx, CancellationToken ct)
    {
        var runKeys = new[]
        {
            (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (RegistryHive.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        };

        foreach (var (hive, keyPath) in runKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var key = baseKey.OpenSubKey(keyPath);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    string? value = key.GetValue(valueName)?.ToString();
                    if (string.IsNullOrWhiteSpace(value)) continue;

                    bool matchedName = UserAssistDecodedTargets.Any(t =>
                        valueName.Contains(t, StringComparison.OrdinalIgnoreCase));
                    bool matchedValue = UserAssistDecodedTargets.Any(t =>
                        value!.Contains(t, StringComparison.OrdinalIgnoreCase));

                    if (!matchedName && !matchedValue) continue;

                    string hiveName = hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM";
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Run Key: FiveM Identity Spoof Tool Autostart",
                        Risk = RiskLevel.High,
                        Location = $@"{hiveName}\{keyPath}\{valueName}",
                        FileName = Path.GetFileName(value!.TrimEnd('"', ' ')),
                        Reason = $"Run/RunOnce registry key '{hiveName}\\{keyPath}' contains value " +
                                 $"'{valueName}' pointing to '{value}', which matches a known FiveM " +
                                 "identity spoofing or ban bypass tool. Autostart registration indicates " +
                                 "the tool was configured to launch automatically at user login.",
                        Detail = $"Value: {value}"
                    });
                }
            }
            catch { }
        }
    }

    private void CheckSoftwareKeysForIdentitySpoof(ScanContext ctx, CancellationToken ct)
    {
        var softwareKeyPaths = new[]
        {
            (RegistryHive.CurrentUser,  @"Software"),
            (RegistryHive.LocalMachine, @"Software"),
            (RegistryHive.LocalMachine, @"Software\WOW6432Node"),
        };

        foreach (var (hive, keyPath) in softwareKeyPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var softwareKey = baseKey.OpenSubKey(keyPath);
                if (softwareKey is null) continue;

                foreach (var subKeyName in softwareKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    bool matched = SpoofSoftwareKeys.Any(sk =>
                        subKeyName.Equals(sk, StringComparison.OrdinalIgnoreCase));

                    if (!matched)
                    {
                        matched = UserAssistDecodedTargets.Any(t =>
                            subKeyName.Contains(t, StringComparison.OrdinalIgnoreCase));
                    }

                    if (!matched) continue;

                    string hiveName = hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM";
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Software Registry Key: FiveM Spoof Tool Install ({subKeyName})",
                        Risk = RiskLevel.High,
                        Location = $@"{hiveName}\{keyPath}\{subKeyName}",
                        FileName = subKeyName,
                        Reason = $"Software registry key '{subKeyName}' under '{hiveName}\\{keyPath}' " +
                                 "matches a known FiveM identity spoofing or ban bypass tool installation " +
                                 "key. This indicates the tool was installed or registered on this system.",
                        Detail = $"Registry path: {hiveName}\\{keyPath}\\{subKeyName}"
                    });
                }
            }
            catch { }
        }
    }

    private void CheckUninstallKeysForIdentitySpoof(ScanContext ctx, CancellationToken ct)
    {
        var uninstallPaths = new[]
        {
            (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.CurrentUser,  @"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        };

        foreach (var (hive, keyPath) in uninstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var uninstallKey = baseKey.OpenSubKey(keyPath);
                if (uninstallKey is null) continue;

                foreach (var subKeyName in uninstallKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();

                    using var sub = uninstallKey.OpenSubKey(subKeyName);
                    if (sub is null) continue;
                    ctx.IncrementRegistryKeys();

                    string? displayName = sub.GetValue("DisplayName")?.ToString();
                    string? installLocation = sub.GetValue("InstallLocation")?.ToString();
                    string? uninstallString = sub.GetValue("UninstallString")?.ToString();

                    var checkStrings = new[] { displayName, installLocation, uninstallString }
                        .Where(s => !string.IsNullOrWhiteSpace(s))
                        .ToList();

                    bool matched = checkStrings.Any(s =>
                        UserAssistDecodedTargets.Any(t =>
                            s!.Contains(t, StringComparison.OrdinalIgnoreCase)) ||
                        SpoofSoftwareKeys.Any(sk =>
                            s!.Contains(sk, StringComparison.OrdinalIgnoreCase)));

                    if (!matched) continue;

                    string hiveName = hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM";
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Uninstall Key: FiveM Spoof Tool Installation Record",
                        Risk = RiskLevel.High,
                        Location = $@"{hiveName}\{keyPath}\{subKeyName}",
                        FileName = displayName ?? subKeyName,
                        Reason = $"Uninstall registry entry '{displayName ?? subKeyName}' under " +
                                 $"'{hiveName}\\{keyPath}' matches a known FiveM identity spoofing or " +
                                 "ban bypass tool. This uninstall record indicates the tool was formally " +
                                 "installed on this system, even if it has since been removed.",
                        Detail = $"DisplayName: {displayName} | InstallLocation: {installLocation}"
                    });
                }
            }
            catch { }
        }
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static List<string> BuildSearchDirectories()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var temp = Path.GetTempPath();
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);

        var dirs = new List<string>
        {
            Path.Combine(userProfile, "Downloads"),
            desktop,
            temp,
            Path.Combine(localAppData, "Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            localAppData,
            roamingAppData,
            Path.Combine(userProfile, "Documents"),
            Path.Combine(userProfile, "Desktop"),
        };

        var fivemDir = FindFiveMDirectory();
        if (fivemDir != null)
        {
            dirs.Add(fivemDir);
            dirs.Add(Path.Combine(fivemDir, "FiveM.app"));
            dirs.Add(Path.Combine(fivemDir, "FiveM.app", "plugins"));
            dirs.Add(Path.Combine(fivemDir, "plugins"));
        }

        return dirs;
    }

    private static string? FindFiveMDirectory()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var candidates = new[]
        {
            Path.Combine(localAppData, "FiveM"),
            Path.Combine(localAppData, "FiveM", "FiveM.app"),
        };
        return candidates.FirstOrDefault(Directory.Exists);
    }

    private static string Rot13Decode(string s)
    {
        var chars = s.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (c >= 'A' && c <= 'Z')
                chars[i] = (char)('A' + (c - 'A' + 13) % 26);
            else if (c >= 'a' && c <= 'z')
                chars[i] = (char)('a' + (c - 'a' + 13) % 26);
        }
        return new string(chars);
    }

    // =========================================================================
    // Additional forensic checks surfaced by RunAsync via Task.WhenAll
    // (These are wired into RunAsync below — see the extended RunAsync override.)
    // =========================================================================

    // Known spoof tool configuration file names left behind after uninstall
    private static readonly string[] SpoofConfigFileNames =
    {
        "spoof_config.json", "hwid_config.json", "license_config.json",
        "id_config.json", "ban_bypass_config.json", "identity_config.json",
        "spoof_settings.ini", "hwid_settings.ini", "license_settings.ini",
        "ban_bypass_settings.ini", "spoof_config.xml", "hwid_config.xml",
        "license_config.xml", "id_config.xml", "ban_bypass_config.xml",
        "fivem_spoof_config.json", "fivem_hwid_config.json",
        "fivem_license_config.json", "fivem_ban_bypass_config.json",
        "spoof.cfg", "hwid.cfg", "license.cfg", "ban_bypass.cfg",
        "identity.cfg", "spoof_tool.cfg", "hwid_tool.cfg",
        "license_tool.cfg", "ban_tool.cfg", "identity_tool.cfg",
        "spoof.dat", "hwid.dat", "license.dat", "ban_bypass.dat",
        "identity.dat", "spoof_data.bin", "hwid_data.bin",
        "license_data.bin", "ban_data.bin", "identity_data.bin",
        "spoof_log.txt", "hwid_log.txt", "license_log.txt",
        "ban_bypass_log.txt", "identity_log.txt",
    };

    // Known spoof tool batch/script launcher names
    private static readonly string[] SpoofScriptNames =
    {
        "spoof.bat", "hwid_spoof.bat", "license_spoof.bat",
        "ban_bypass.bat", "ban_evade.bat", "identity_spoof.bat",
        "fivem_spoof.bat", "fivem_hwid.bat", "fivem_license.bat",
        "fivem_ban_bypass.bat", "spoof.ps1", "hwid_spoof.ps1",
        "license_spoof.ps1", "ban_bypass.ps1", "identity_spoof.ps1",
        "fivem_spoof.ps1", "fivem_hwid.ps1", "fivem_license.ps1",
        "fivem_ban_bypass.ps1", "spoof.cmd", "hwid_spoof.cmd",
        "license_spoof.cmd", "ban_bypass.cmd", "identity_spoof.cmd",
        "fivem_spoof.cmd", "fivem_hwid.cmd", "run_spoof.bat",
        "run_hwid.bat", "run_license.bat", "run_ban_bypass.bat",
        "install_spoof.bat", "install_hwid.bat", "install_license.bat",
        "start_spoof.bat", "start_hwid.bat",
    };

    // Suspicious prefetch names for spoof tools (without .exe extension for prefix matching)
    private static readonly string[] SpoofPrefetchPrefixes =
    {
        "FIVEM_SPOOF", "HWID_SPOOF_FIVEM", "LICENSE_SPOOF_FIVEM",
        "FIVEM_BAN_BYPASS", "FIVEM_BAN_EVADE", "FIVEM_UNBAN",
        "FIVEM_IDENTITY_SPOOF", "FIVEM_HWID_CHANGER", "BAN_BYPASS_FIVEM",
        "SPOOF_FIVEM", "HWID_CHANGER_FIVEM", "FIVEM_SPOOF_V2",
        "BAN_BYPASS_V2", "ID_SPOOF_FIVEM", "FIVEM_ID_CHANGER",
        "FIVEM_MAC_SPOOF", "FIVEM_IP_SPOOF", "FIVEM_STEAM_SPOOF",
        "FIVEM_DISCORD_SPOOF", "FIVEM_CLONE_HWID", "FIVEM_BAN_REMOVE",
        "HWID_SPOOF_V2", "LICENSE_SPOOF_V2", "ID_SPOOF_V2", "BAN_EVADE_V2",
    };

    // Cache/temp file patterns left by FiveM spoof tools
    private static readonly string[] SpoofCachePatterns =
    {
        "spoof_cache", "hwid_cache", "license_cache", "id_cache",
        "ban_bypass_cache", "identity_cache", "spoof_temp",
        "hwid_temp", "license_temp", "ban_bypass_temp",
        "fivem_spoof_cache", "fivem_hwid_cache", "fivem_license_cache",
        "fivem_ban_cache", "spoof_backup", "hwid_backup",
        "license_backup", "ban_bypass_backup",
    };

    // -------------------------------------------------------------------------
    // Check for spoof tool config/data remnant files
    // -------------------------------------------------------------------------

    public Task CheckIdentitySpoofConfigFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchDirs = BuildSearchDirectories();
            var fivemDir = FindFiveMDirectory();
            if (fivemDir != null && !searchDirs.Contains(fivemDir, StringComparer.OrdinalIgnoreCase))
                searchDirs.Add(fivemDir);

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string fileName = Path.GetFileName(file);

                    bool isConfig = SpoofConfigFileNames.Any(c =>
                        fileName.Equals(c, StringComparison.OrdinalIgnoreCase));
                    bool isScript = SpoofScriptNames.Any(s =>
                        fileName.Equals(s, StringComparison.OrdinalIgnoreCase));

                    if (!isConfig && !isScript) continue;

                    string content = string.Empty;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { }

                    string artifactType = isConfig ? "configuration/data file" : "launcher script";
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Spoof Tool {(isConfig ? "Config" : "Script")} Remnant: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = $"File '{fileName}' is a known FiveM identity/license spoof tool " +
                                 $"{artifactType}. Configuration and script remnants are forensic " +
                                 "artifacts left behind by spoof tools even after the main executable " +
                                 "has been deleted. Their presence indicates prior use of spoofing " +
                                 "or ban evasion tools targeting the FiveM platform.",
                        Detail = $"Type: {artifactType} | Directory: {dir}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Prefetch scan for executed spoof tools
    // -------------------------------------------------------------------------

    public Task CheckIdentitySpoofPrefetch(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var prefetchDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

            if (!Directory.Exists(prefetchDir)) return;

            IEnumerable<string> pfFiles;
            try
            {
                pfFiles = Directory.EnumerateFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                return;
            }

            foreach (var pfFile in pfFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string baseName = Path.GetFileNameWithoutExtension(pfFile).ToUpperInvariant();
                // Prefetch format: "EXENAME.EXE-XXXXXXXX.pf"
                int dash = baseName.LastIndexOf('-');
                string exeBase = dash > 0 ? baseName[..dash] : baseName;

                bool matched = SpoofPrefetchPrefixes.Any(p =>
                    exeBase.Equals(p, StringComparison.OrdinalIgnoreCase) ||
                    exeBase.StartsWith(p, StringComparison.OrdinalIgnoreCase));

                if (!matched) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Prefetch: FiveM Spoof Tool Execution ({exeBase})",
                    Risk = RiskLevel.High,
                    Location = pfFile,
                    FileName = Path.GetFileName(pfFile),
                    Reason = $"Windows Prefetch file '{Path.GetFileName(pfFile)}' records that a program " +
                             $"matching the FiveM identity/license spoof tool pattern '{exeBase}' was " +
                             "executed on this system. Prefetch data persists after the executable is " +
                             "deleted, providing a durable forensic trace of spoof tool execution.",
                    Detail = $"Prefetch entry: {exeBase}"
                });
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Temp directory scan for spoof tool cache/work files
    // -------------------------------------------------------------------------

    public Task CheckIdentitySpoofTempArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var tempDirs = new[]
            {
                Path.GetTempPath(),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
            };

            foreach (var tempDir in tempDirs)
            {
                if (!Directory.Exists(tempDir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> entries;
                try
                {
                    entries = Directory.EnumerateFileSystemEntries(tempDir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var entry in entries)
                {
                    ct.ThrowIfCancellationRequested();

                    string entryName = Path.GetFileName(entry);
                    bool matched = SpoofCachePatterns.Any(p =>
                        entryName.Contains(p, StringComparison.OrdinalIgnoreCase));

                    if (!matched) continue;

                    bool isDir = Directory.Exists(entry);
                    string content = string.Empty;

                    if (!isDir)
                    {
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(entry, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { }
                    }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Spoof Tool Temp/Cache Artifact: {entryName}",
                        Risk = RiskLevel.High,
                        Location = entry,
                        FileName = entryName,
                        Reason = $"{(isDir ? "Directory" : "File")} '{entryName}' in a system temp folder " +
                                 "matches the naming pattern of cache or working files left behind by " +
                                 "FiveM identity/license spoof tools. These temporary artifacts are " +
                                 "created during spoof tool operation and may contain spoofed identity " +
                                 "data, HWID replacement values, or bypass operation logs.",
                        Detail = $"Temp directory: {tempDir} | Type: {(isDir ? "directory" : "file")}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // Hosts file tampering check for FiveM / license server blocks
    // -------------------------------------------------------------------------

    private static readonly string[] FiveMHostsBlockTargets =
    {
        "cfx.re", "fivem.net", "citizenfx.com", "fivemlicense",
        "fivem-license", "fivem.license", "citizenfx.license",
        "rockstargames.com", "socialclub.rockstargames.com",
        "licensing.fivem.net", "identity.fivem.net",
        "ban.fivem.net", "banlist.fivem.net", "bancheck.fivem.net",
        "anticheat.fivem.net", "ac.fivem.net", "report.fivem.net",
    };

    public Task CheckHostsFileForSpoofTampering(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var hostsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "drivers", "etc", "hosts");

            if (!File.Exists(hostsPath)) return;

            string[] lines;
            try
            {
                lines = File.ReadAllLines(hostsPath);
            }
            catch (IOException)
            {
                return;
            }

            ctx.IncrementFiles();

            foreach (var raw in lines)
            {
                ct.ThrowIfCancellationRequested();

                string line = raw.Trim();
                if (line.Length == 0 || line.StartsWith('#')) continue;

                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;

                string ip = parts[0];
                for (int i = 1; i < parts.Length; i++)
                {
                    string host = parts[i];
                    if (host.StartsWith('#')) break;

                    bool matched = FiveMHostsBlockTargets.Any(t =>
                        host.Contains(t, StringComparison.OrdinalIgnoreCase));

                    if (!matched) continue;

                    bool isNullRoute = ip.Equals("0.0.0.0", StringComparison.Ordinal) ||
                                      ip.Equals("127.0.0.1", StringComparison.Ordinal) ||
                                      ip.Equals("::1", StringComparison.Ordinal);

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = isNullRoute
                            ? $"Hosts File: FiveM License/Identity Server Blocked ({host})"
                            : $"Hosts File: FiveM License/Identity Server Redirected ({host})",
                        Risk = isNullRoute ? RiskLevel.High : RiskLevel.High,
                        Location = hostsPath,
                        FileName = "hosts",
                        Reason = $"The Windows hosts file contains an entry redirecting '{host}' to " +
                                 $"'{ip}'. This FiveM licensing, identity, or ban-check server is " +
                                 (isNullRoute
                                     ? "blocked via a null-route address. Identity spoof tools commonly " +
                                       "block FiveM license and ban-check servers to prevent detection."
                                     : "redirected to a foreign IP, which may indicate license server " +
                                       "spoofing or man-in-the-middle interception of identity checks."),
                        Detail = $"Hosts entry: {line}"
                    });
                }
            }
        }, ct);

    // -------------------------------------------------------------------------
    // AppData roaming scan for FiveM spoof tool profile/data directories
    // -------------------------------------------------------------------------

    private static readonly string[] SpoofAppDataFolders =
    {
        "FiveMSpoof", "HwidSpoofFiveM", "LicenseSpoofFiveM",
        "FiveMBanBypass", "FiveMBanEvade", "FiveMUnban",
        "FiveMIdentitySpoof", "FiveMHwidChanger", "FiveMLicenseChanger",
        "BanBypassFiveM", "SpoofFiveM", "HwidChangerFiveM",
        "FiveMSpoofV2", "BanBypassV2", "IdSpoofFiveM",
        "FiveMCloneHwid", "FiveMBanRemove", "FiveMBanClear",
        "FiveMUnbanTool", "HwidSpoofV2", "LicenseSpoofV2",
        "IdSpoofV2", "BanEvadeV2", "FiveMRosSpoof",
        "FiveMRockstarSpoof", "FiveMGuidSpoof", "FiveMUuidSpoof",
        "FiveMSteamSpoof", "FiveMDiscordSpoof", "FiveMXblSpoof",
    };

    public Task CheckIdentitySpoofAppDataFolders(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var appDataRoots = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            };

            foreach (var root in appDataRoots)
            {
                if (!Directory.Exists(root)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> subdirs;
                try
                {
                    subdirs = Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var subdir in subdirs)
                {
                    ct.ThrowIfCancellationRequested();

                    string folderName = Path.GetFileName(subdir);
                    bool matched = SpoofAppDataFolders.Any(f =>
                        folderName.Equals(f, StringComparison.OrdinalIgnoreCase));

                    if (!matched) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Spoof Tool AppData Folder: {folderName}",
                        Risk = RiskLevel.High,
                        Location = subdir,
                        FileName = folderName,
                        Reason = $"AppData directory '{folderName}' matches the installation data folder " +
                                 "name of a known FiveM identity/license spoof or ban evasion tool. " +
                                 "Spoof tools create application data folders to persist spoofed identity " +
                                 "profiles, cached HWID replacements, and bypass state between sessions.",
                        Detail = $"AppData root: {root}"
                    });
                }
            }
        }, ct);
}
