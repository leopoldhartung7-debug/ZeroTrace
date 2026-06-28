using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class AltVBanEvasionDeepForensicScanModule : IScanModule
{
    public string Name => "AltV Ban Evasion Deep";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    // -------------------------------------------------------------------------
    // Keyword arrays
    // -------------------------------------------------------------------------

    private static readonly string[] AltVDataDirNames =
    [
        "altv", "alt-v", "alt_v", "altvmp", "altv-mp"
    ];

    private static readonly string[] CleanerFileKeywords =
    [
        "cleaner", "clean", "wipe", "altv_clean", "altvclean", "altv-clean",
        "ban_cleaner", "bancleaner", "cache_wipe", "cachewipe", "reset_altv",
        "resetaltv", "altv_reset", "altvreset", "identity_reset", "identityreset"
    ];

    private static readonly string[] AccountSwitcherKeywords =
    [
        "account_switcher", "accountswitcher", "acc_switch", "accswitch",
        "altv_switcher", "altvswitcher", "altv_account", "altvaccount",
        "profile_switcher", "profileswitcher", "multi_account", "multiaccount"
    ];

    private static readonly string[] SteamSwitcherKeywords =
    [
        "steam_switcher", "steamswitcher", "steam_account", "steamaccount",
        "asm_", "account_manager", "sac_", "steamaccountchanger"
    ];

    private static readonly string[] VpnConfigKeywords =
    [
        "altv", "alt-v", "altvmp", "master.altv.mp", "cdn.alt-mp.com",
        "altv.mp", "alt-mp.com"
    ];

    private static readonly string[] SpooferLogKeywords =
    [
        "spoof", "hwid", "serial", "bypass", "fake", "clone", "reset_id",
        "resetid", "generateid", "generate_id", "changehwid", "change_hwid"
    ];

    private static readonly string[] AltVLogWipeKeywords =
    [
        "altv", "alt-v"
    ];

    private static readonly string[] BanListFileNames =
    [
        "bans.json", "banlist.txt", "banlist.json", "banned_ids.txt",
        "banned_ids.json", "ban_list.txt", "ban_list.json", "bans.txt",
        "banned.txt", "banned.json", "kicked.txt", "kicked.json"
    ];

    private static readonly string[] AntiBanJsPatterns =
    [
        "tokenRotat", "token_rotat", "resetHWID", "reset_hwid", "bypassBan",
        "bypass_ban", "identityReset", "identity_reset", "hwid_bypass",
        "hwidBypass", "evade_ban", "evadeBan", "ban_evade", "banEvade",
        "rotateSteam", "rotate_steam", "rotateToken", "rotate_token",
        "clearIdentity", "clear_identity", "spoofHWID", "spoof_hwid"
    ];

    private static readonly string[] BackupDirKeywords =
    [
        "backup", "profile_backup", "profilebackup", "alt_account",
        "altaccount", "account_backup", "accountbackup", "old_profile",
        "oldprofile", "saved_profile", "savedprofile", "altvbackup",
        "altv_backup", "identity_backup", "identitybackup"
    ];

    private static readonly string[] BanEvasionRegistryKeywords =
    [
        "altv", "alt-v", "altvmp", "ban_evad", "banevad", "hwid_spoof",
        "hwidspoof", "identity_reset", "identityreset", "account_switch",
        "accountswitch", "cache_clean", "cacheclean", "altv_clean", "altvclean"
    ];

    private static readonly string[] PrefetchBanEvasionNames =
    [
        "altv_cleaner", "altvcleaner", "altv-cleaner", "hwid_reset", "hwidreset",
        "hwid-reset", "account_switch", "accountswitch", "account-switch",
        "altv_reset", "altvreset", "ban_evader", "banevader", "identity_reset",
        "identityreset", "steamaccountchanger", "steam_switcher", "altvwipe",
        "altv_wipe", "cachewiper", "cache_wiper"
    ];

    private static readonly string[] BanKickLogKeywords =
    [
        "you have been banned", "you are banned", "banned from this server",
        "ban reason", "kicked: ban", "kick reason: ban", "permanently banned",
        "temporarily banned", "banned by admin", "global ban", "you were kicked",
        "ban evasion detected", "evading ban"
    ];

    private static readonly string[] AutoJoinScriptKeywords =
    [
        "altv.exe", "alt-v.exe", "connect", "reconnect", "auto_join",
        "autojoin", "auto-join", "rejoin", "re_join", "restart_altv",
        "restartaltv", "loop", "while", "timeout", "sleep"
    ];

    private static readonly string[] RockstarRotationKeywords =
    [
        "socialclub", "social_club", "rgsc", "rockstar", "sc_login",
        "sclogin", "rockstar_account", "rockstaraccount"
    ];

    private static readonly string[] WireGuardOpenVpnKeywords =
    [
        "altv", "alt-v", "altvmp", "master.altv.mp", "altv.mp",
        "cdn.alt-mp.com", "alt-mp.com", "185.56.64", "149.56.8"
    ];

    private static readonly string[] BanBrowserHistoryKeywords =
    [
        "altv ban", "altv unban", "altv hwid", "altv hwid reset",
        "altv ban bypass", "altv ban evade", "altv banned", "altvmp ban",
        "alt-v ban", "alt v ban", "bypass altv ban", "evade altv ban",
        "altv ban appeal", "altv ban check", "altv unban tool",
        "altv identity reset", "altv spoof", "altv hwid spoof"
    ];

    private static readonly string[] TokenFileExtensions =
    [
        ".token", ".auth", ".session", ".tok", ".credential", ".cred"
    ];

    private static readonly string[] VpnConfigExtensions =
    [
        ".ovpn", ".conf", ".config"
    ];

    private static readonly string[] AutoJoinExtensions =
    [
        ".bat", ".cmd", ".ahk", ".ps1", ".vbs"
    ];

    private static readonly string[] BrowserProfilePaths =
    [
        @"Google\Chrome\User Data",
        @"Mozilla\Firefox\Profiles",
        @"Microsoft\Edge\User Data",
        @"BraveSoftware\Brave-Browser\User Data",
        @"Opera Software\Opera Stable",
        @"Vivaldi\User Data"
    ];

    // -------------------------------------------------------------------------
    // RunAsync — fan-out all 18 checks concurrently
    // -------------------------------------------------------------------------

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckMultipleAltVDataDirectories(ctx, ct),
            CheckCacheCleanerTools(ctx, ct),
            CheckAccountSwitcherTools(ctx, ct),
            CheckSteamAlternateAccounts(ctx, ct),
            CheckIpRotationArtifacts(ctx, ct),
            CheckHwidSpooferLogs(ctx, ct),
            CheckLogManipulation(ctx, ct),
            CheckLocalBanListFiles(ctx, ct),
            CheckAntiBanScriptsInResources(ctx, ct),
            CheckProfileBackupDirectories(ctx, ct),
            CheckBanEvasionRegistryTraces(ctx, ct),
            CheckPrefetchBanEvasionEntries(ctx, ct),
            CheckServerConnectionHistory(ctx, ct),
            CheckAutoJoinScripts(ctx, ct),
            CheckRockstarAccountRotation(ctx, ct),
            CheckWireGuardOpenVpnConfigs(ctx, ct),
            CheckBanDatabaseBrowserHistory(ctx, ct),
            CheckMultipleAuthTokenFiles(ctx, ct)
        );

        ctx.Report(1.0, Name, "AltV ban evasion deep forensic scan complete");
    }

    // -------------------------------------------------------------------------
    // Check 1: Multiple alt:V data directories / profile folders
    // -------------------------------------------------------------------------

    private Task CheckMultipleAltVDataDirectories(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var searchRoots = new[]
        {
            appData,
            localAppData,
            Path.Combine(appData, ".."),
        };

        var foundAltVDirs = new List<string>();

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            try
            {
                var dirs = Directory.GetDirectories(root);
                foreach (var dir in dirs)
                {
                    if (ct.IsCancellationRequested) return;
                    var dirName = Path.GetFileName(dir);
                    if (dirName is null) continue;
                    foreach (var keyword in AltVDataDirNames)
                    {
                        if (dirName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            foundAltVDirs.Add(dir);
                            break;
                        }
                    }
                }
            }
            catch { }
        }

        var primaryAltVPath = Path.Combine(appData, "altv");
        if (Directory.Exists(primaryAltVPath))
        {
            try
            {
                var subDirs = Directory.GetDirectories(primaryAltVPath);
                var identityDirs = new List<string>();

                foreach (var sub in subDirs)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var subName = Path.GetFileName(sub);
                    if (subName is null) continue;

                    if (subName.Length >= 16 && subName.All(c => "0123456789abcdefABCDEF-_".Contains(c, StringComparison.Ordinal)))
                    {
                        identityDirs.Add(sub);
                    }

                    if (subName.StartsWith("account_", StringComparison.OrdinalIgnoreCase)
                        || subName.StartsWith("profile_", StringComparison.OrdinalIgnoreCase)
                        || subName.StartsWith("identity_", StringComparison.OrdinalIgnoreCase))
                    {
                        identityDirs.Add(sub);
                    }
                }

                if (identityDirs.Count > 1)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Multiple alt:V Identity/Account Directories Found",
                        Risk = RiskLevel.High,
                        Location = primaryAltVPath,
                        FileName = Path.GetFileName(primaryAltVPath),
                        Reason = $"Found {identityDirs.Count} identity or account subdirectories inside the alt:V AppData folder, " +
                                 "indicating multiple accounts or identity rotation for ban evasion.",
                        Detail = string.Join("; ", identityDirs.Select(Path.GetFileName))
                    });
                }
            }
            catch { }
        }

        if (foundAltVDirs.Count > 1)
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Multiple alt:V Data Directory Locations",
                Risk = RiskLevel.Medium,
                Location = string.Join("; ", foundAltVDirs),
                FileName = null,
                Reason = $"Found {foundAltVDirs.Count} separate directories across AppData locations that appear to belong to alt:V, " +
                         "which may indicate identity rotation or profile backup for ban evasion.",
                Detail = string.Join(Environment.NewLine, foundAltVDirs)
            });
        }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 2: alt:V cache cleaner tools and scripts
    // -------------------------------------------------------------------------

    private Task CheckCacheCleanerTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) is string home ? Path.Combine(home, "Downloads") : null,
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (dir is null || !Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileNameWithoutExtension(file);
                if (fileName is null) continue;

                bool hasCleanerKeyword = false;
                bool hasAltVKeyword = false;

                foreach (var kw in CleanerFileKeywords)
                {
                    if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        hasCleanerKeyword = true;
                        break;
                    }
                }

                foreach (var kw in AltVDataDirNames)
                {
                    if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        hasAltVKeyword = true;
                        break;
                    }
                }

                var ext = Path.GetExtension(file);
                bool isExecutableOrScript = ext.Equals(".exe", StringComparison.OrdinalIgnoreCase)
                    || ext.Equals(".bat", StringComparison.OrdinalIgnoreCase)
                    || ext.Equals(".cmd", StringComparison.OrdinalIgnoreCase)
                    || ext.Equals(".ps1", StringComparison.OrdinalIgnoreCase)
                    || ext.Equals(".vbs", StringComparison.OrdinalIgnoreCase)
                    || ext.Equals(".ahk", StringComparison.OrdinalIgnoreCase);

                if ((hasCleanerKeyword && hasAltVKeyword) || (hasCleanerKeyword && isExecutableOrScript))
                {
                    var riskLevel = (hasAltVKeyword && isExecutableOrScript) ? RiskLevel.Critical : RiskLevel.High;
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V Cache Cleaner Tool Detected",
                        Risk = riskLevel,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"File '{Path.GetFileName(file)}' in '{dir}' matches patterns associated with alt:V " +
                                 "cache cleaner or ban evasion cleanup tools. These tools are used to remove " +
                                 "ban-related artifacts to allow re-entry to servers after being banned.",
                        Detail = $"Matched cleaner keyword in file name. Extension: {ext}"
                    });
                }
            }
        }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 3: Account switcher tools targeting alt:V
    // -------------------------------------------------------------------------

    private Task CheckAccountSwitcherTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) is string h ? Path.Combine(h, "Downloads") : null,
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };

        var altvAppData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv");

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (dir is null || !Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fileName = Path.GetFileNameWithoutExtension(file);
                if (fileName is null) continue;

                foreach (var kw in AccountSwitcherKeywords)
                {
                    if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Account Switcher Tool Targeting alt:V",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Executable '{Path.GetFileName(file)}' matches patterns of account switcher tools " +
                                     "used to cycle between accounts after a ban. This is a primary ban evasion technique.",
                            Detail = $"Matched keyword: '{kw}'"
                        });
                        break;
                    }
                }
            }
        }

        if (Directory.Exists(altvAppData))
        {
            IEnumerable<string> configFiles;
            try { configFiles = Directory.EnumerateFiles(altvAppData, "*.json", SearchOption.AllDirectories); }
            catch { return; }

            foreach (var configFile in configFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    int accountEntries = 0;
                    foreach (var line in content.Split('\n'))
                    {
                        if (line.Contains("\"account\"", StringComparison.OrdinalIgnoreCase)
                            || line.Contains("\"identity\"", StringComparison.OrdinalIgnoreCase)
                            || line.Contains("\"token\"", StringComparison.OrdinalIgnoreCase))
                        {
                            accountEntries++;
                        }
                    }

                    if (accountEntries > 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Config File with Multiple Account Entries",
                            Risk = RiskLevel.High,
                            Location = configFile,
                            FileName = Path.GetFileName(configFile),
                            Reason = $"Config file contains {accountEntries} account/identity/token entries, " +
                                     "suggesting it is used by an account switcher for ban evasion.",
                            Detail = $"File: {configFile}"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 4: Steam alternate accounts
    // -------------------------------------------------------------------------

    private Task CheckSteamAlternateAccounts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var programFiles = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetEnvironmentVariable("ProgramW6432") ?? string.Empty
        };

        string? steamPath = null;
        foreach (var pf in programFiles)
        {
            if (string.IsNullOrEmpty(pf)) continue;
            var candidate = Path.Combine(pf, "Steam");
            if (Directory.Exists(candidate)) { steamPath = candidate; break; }
        }

        if (steamPath is null)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Valve\Steam");
                if (key?.GetValue("SteamPath") is string regPath && Directory.Exists(regPath))
                    steamPath = regPath;
            }
            catch { }
        }

        if (steamPath is not null)
        {
            var loginUsersFile = Path.Combine(steamPath, "config", "loginusers.vdf");
            if (File.Exists(loginUsersFile))
            {
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(loginUsersFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    int accountCount = 0;
                    foreach (var line in content.Split('\n'))
                    {
                        if (line.Contains("\"AccountName\"", StringComparison.OrdinalIgnoreCase))
                            accountCount++;
                    }

                    if (accountCount > 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Multiple Steam Accounts in loginusers.vdf",
                            Risk = RiskLevel.High,
                            Location = loginUsersFile,
                            FileName = "loginusers.vdf",
                            Reason = $"Steam loginusers.vdf contains {accountCount} account entries. " +
                                     "Multiple Steam accounts are commonly used to evade game server bans " +
                                     "by switching to a different Steam identity after being banned.",
                            Detail = $"Account count: {accountCount}"
                        });
                    }
                }
                catch { }
            }
        }

        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) is string h ? Path.Combine(h, "Downloads") : null,
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        foreach (var dir in searchDirs)
        {
            if (dir is null || !Directory.Exists(dir)) continue;

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(dir, "*.exe", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fileName = Path.GetFileNameWithoutExtension(file) ?? string.Empty;

                foreach (var kw in SteamSwitcherKeywords)
                {
                    if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Steam Profile Switcher Tool Detected",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Executable '{Path.GetFileName(file)}' matches patterns associated with Steam account " +
                                     "switcher tools. These tools facilitate cycling through Steam accounts after a ban.",
                            Detail = $"Matched keyword: '{kw}'"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 5: IP rotation targeting alt:V
    // -------------------------------------------------------------------------

    private Task CheckIpRotationArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var hostsFile = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "drivers", "etc", "hosts");

        if (File.Exists(hostsFile))
        {
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(hostsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                var suspiciousLines = new List<string>();
                foreach (var line in content.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith('#') || string.IsNullOrWhiteSpace(trimmed)) continue;
                    foreach (var kw in VpnConfigKeywords)
                    {
                        if (trimmed.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            suspiciousLines.Add(trimmed);
                            break;
                        }
                    }
                }

                if (suspiciousLines.Count > 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Hosts File Modified for alt:V Domain Redirection",
                        Risk = RiskLevel.Critical,
                        Location = hostsFile,
                        FileName = "hosts",
                        Reason = "The Windows hosts file contains entries targeting alt:V master server domains. " +
                                 "This modification can redirect alt:V authentication or anti-cheat traffic " +
                                 "for ban evasion or authentication bypass.",
                        Detail = string.Join(Environment.NewLine, suspiciousLines)
                    });
                }
            }
            catch { }
        }

        var vpnSearchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) is string h ? Path.Combine(h, "Downloads") : null,
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        foreach (var dir in vpnSearchDirs)
        {
            if (dir is null || !Directory.Exists(dir)) continue;

            foreach (var ext in VpnConfigExtensions)
            {
                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, $"*{ext}", SearchOption.TopDirectoryOnly); }
                catch { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var kw in VpnConfigKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "VPN Config Targeting alt:V Domains",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"VPN/proxy configuration file '{Path.GetFileName(file)}' references alt:V server domains " +
                                             "or IP addresses. This may indicate IP rotation setup to evade alt:V IP-based bans.",
                                    Detail = $"Matched keyword: '{kw}' in {Path.GetExtension(file)} config"
                                });
                                break;
                            }
                        }
                    }
                    catch { }
                }
            }
        }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 6: HWID spoofer logs mentioning alt:V
    // -------------------------------------------------------------------------

    private Task CheckHwidSpooferLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var logSearchDirs = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        };

        var logExtensions = new[] { ".log", ".txt", ".dat" };

        foreach (var dir in logSearchDirs)
        {
            if (!Directory.Exists(dir)) continue;

            foreach (var ext in logExtensions)
            {
                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, $"*{ext}", SearchOption.TopDirectoryOnly); }
                catch { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    try
                    {
                        var fileInfo = new FileInfo(file);
                        if (fileInfo.Length > 10 * 1024 * 1024) continue;

                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        bool hasAltV = false;
                        bool hasSpoofer = false;

                        foreach (var kw in AltVLogWipeKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                hasAltV = true;
                                break;
                            }
                        }

                        foreach (var kw in SpooferLogKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                hasSpoofer = true;
                                break;
                            }
                        }

                        if (hasAltV && hasSpoofer)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "HWID Spoofer Log Referencing alt:V",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Log file '{Path.GetFileName(file)}' contains both alt:V references and HWID spoofer keywords. " +
                                         "This strongly indicates a HWID spoofing tool was used in conjunction with alt:V, " +
                                         "likely for ban evasion by faking hardware identifiers.",
                                Detail = $"Location: {dir}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 7: Log manipulation in alt:V directories
    // -------------------------------------------------------------------------

    private Task CheckLogManipulation(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var altvAppData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv");

        if (!Directory.Exists(altvAppData)) return;

        var altvInstallPaths = new List<string> { altvAppData };

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\altv");
            if (key?.GetValue("InstallPath") is string installPath && Directory.Exists(installPath))
                altvInstallPaths.Add(installPath);
            ctx.IncrementRegistryKeys();
        }
        catch { }

        foreach (var altvPath in altvInstallPaths)
        {
            if (!Directory.Exists(altvPath)) continue;

            IEnumerable<string> logDirs;
            try
            {
                logDirs = Directory.EnumerateDirectories(altvPath, "*", SearchOption.AllDirectories)
                    .Where(d =>
                    {
                        var name = Path.GetFileName(d);
                        return name is not null &&
                               (name.Equals("logs", StringComparison.OrdinalIgnoreCase)
                                || name.Equals("log", StringComparison.OrdinalIgnoreCase));
                    });
            }
            catch { continue; }

            foreach (var logDir in logDirs)
            {
                if (ct.IsCancellationRequested) return;

                try
                {
                    var logFiles = Directory.GetFiles(logDir, "*.log");
                    ctx.IncrementFiles();

                    var dirInfo = new DirectoryInfo(logDir);
                    var parentWriteTime = dirInfo.LastWriteTime;
                    var daysSinceModified = (DateTime.Now - parentWriteTime).TotalDays;

                    if (logFiles.Length == 0 && daysSinceModified < 7)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Log Directory Appears Wiped",
                            Risk = RiskLevel.High,
                            Location = logDir,
                            FileName = Path.GetFileName(logDir),
                            Reason = $"alt:V log directory '{logDir}' contains no log files despite the directory " +
                                     $"being modified {daysSinceModified:F1} days ago. This suggests logs were deliberately " +
                                     "deleted to hide ban-related activity.",
                            Detail = $"Directory last modified: {parentWriteTime:yyyy-MM-dd HH:mm:ss}"
                        });
                    }
                    else
                    {
                        foreach (var logFile in logFiles)
                        {
                            ctx.IncrementFiles();
                            try
                            {
                                var fi = new FileInfo(logFile);
                                if (fi.Length == 0 && (DateTime.Now - fi.LastWriteTime).TotalDays < 3)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "Empty alt:V Log File (Possible Wipe)",
                                        Risk = RiskLevel.Medium,
                                        Location = logFile,
                                        FileName = Path.GetFileName(logFile),
                                        Reason = "alt:V log file is empty but was recently modified. " +
                                                 "This may indicate the log was intentionally wiped to remove " +
                                                 "evidence of ban-related events or suspicious activity.",
                                        Detail = $"File size: 0 bytes, Last write: {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss}"
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    // -------------------------------------------------------------------------
    // Check 8: Local ban list files
    // -------------------------------------------------------------------------

    private Task CheckLocalBanListFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var altvRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv");

        var searchRoots = new List<string>();
        if (Directory.Exists(altvRoot)) searchRoots.Add(altvRoot);

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\altv");
            if (key?.GetValue("InstallPath") is string installPath && Directory.Exists(installPath))
                searchRoots.Add(installPath);
            ctx.IncrementRegistryKeys();
        }
        catch { }

        var extraDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) is string h ? Path.Combine(h, "Downloads") : null,
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };
        foreach (var d in extraDirs) { if (d is not null && Directory.Exists(d)) searchRoots.Add(d); }

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                if (fileName is null) continue;

                foreach (var banFileName in BanListFileNames)
                {
                    if (fileName.Equals(banFileName, StringComparison.OrdinalIgnoreCase))
                    {
                        var fi = new FileInfo(file);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Local Ban List File Found in alt:V Directory",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"File '{fileName}' matching known ban list naming patterns was found in an alt:V-related directory. " +
                                     "Possession of local ban lists may indicate server operator ban evasion research or " +
                                     "attempts to maintain banned player identity databases.",
                            Detail = $"File size: {fi.Length} bytes, Last modified: {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss}"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 9: Anti-ban scripts in alt:V resource directories
    // -------------------------------------------------------------------------

    private Task CheckAntiBanScriptsInResources(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var altvAppData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv");

        var resourceRoots = new List<string>();

        var possibleResourceDirs = new[]
        {
            Path.Combine(altvAppData, "resources"),
            Path.Combine(altvAppData, "resource"),
            Path.Combine(altvAppData, "server", "resources"),
        };

        foreach (var d in possibleResourceDirs)
        {
            if (Directory.Exists(d)) resourceRoots.Add(d);
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\altv");
            if (key?.GetValue("InstallPath") is string installPath && Directory.Exists(installPath))
            {
                var resourcesInInstall = Path.Combine(installPath, "resources");
                if (Directory.Exists(resourcesInInstall)) resourceRoots.Add(resourcesInInstall);
            }
            ctx.IncrementRegistryKeys();
        }
        catch { }

        foreach (var resourceRoot in resourceRoots)
        {
            IEnumerable<string> jsFiles;
            try { jsFiles = Directory.EnumerateFiles(resourceRoot, "*.js", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var jsFile in jsFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    var fi = new FileInfo(jsFile);
                    if (fi.Length > 5 * 1024 * 1024) continue;

                    using var fs = new FileStream(jsFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    var matchedPatterns = new List<string>();
                    foreach (var pattern in AntiBanJsPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            matchedPatterns.Add(pattern);
                    }

                    if (matchedPatterns.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Anti-Ban Script Detected in alt:V Resources",
                            Risk = RiskLevel.Critical,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Reason = $"JavaScript resource file '{Path.GetFileName(jsFile)}' contains {matchedPatterns.Count} " +
                                     "anti-ban pattern matches including token rotation, HWID bypass, or identity reset logic. " +
                                     "This script appears designed to circumvent alt:V ban enforcement.",
                            Detail = $"Matched patterns: {string.Join(", ", matchedPatterns)}"
                        });
                    }
                    else if (matchedPatterns.Count == 1)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Suspicious Anti-Ban Pattern in alt:V Resource Script",
                            Risk = RiskLevel.High,
                            Location = jsFile,
                            FileName = Path.GetFileName(jsFile),
                            Reason = $"JavaScript resource file '{Path.GetFileName(jsFile)}' contains a pattern " +
                                     "associated with ban evasion scripts. Single-pattern match warrants investigation.",
                            Detail = $"Matched pattern: {matchedPatterns[0]}"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 10: Profile backup directories
    // -------------------------------------------------------------------------

    private Task CheckProfileBackupDirectories(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) is string h ? Path.Combine(h, "Downloads") : null,
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        foreach (var root in searchRoots)
        {
            if (root is null || !Directory.Exists(root)) continue;

            IEnumerable<string> subDirs;
            try { subDirs = Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (var subDir in subDirs)
            {
                if (ct.IsCancellationRequested) return;
                var dirName = Path.GetFileName(subDir) ?? string.Empty;

                bool hasBackupKeyword = false;
                foreach (var kw in BackupDirKeywords)
                {
                    if (dirName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        hasBackupKeyword = true;
                        break;
                    }
                }

                bool hasAltVKeyword = false;
                foreach (var kw in AltVDataDirNames)
                {
                    if (dirName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        hasAltVKeyword = true;
                        break;
                    }
                }

                if (hasBackupKeyword && hasAltVKeyword)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V Profile Backup Directory Found",
                        Risk = RiskLevel.High,
                        Location = subDir,
                        FileName = dirName,
                        Reason = $"Directory '{dirName}' contains both alt:V and backup/profile keywords, " +
                                 "indicating a deliberate backup of alt:V identity data. " +
                                 "Profile backups are used to restore identities after they are banned.",
                        Detail = $"Parent: {root}"
                    });
                }
                else if (hasBackupKeyword)
                {
                    IEnumerable<string> innerDirs;
                    try { innerDirs = Directory.EnumerateDirectories(subDir, "*", SearchOption.TopDirectoryOnly); }
                    catch { continue; }

                    foreach (var inner in innerDirs)
                    {
                        var innerName = Path.GetFileName(inner) ?? string.Empty;
                        bool innerHasAltV = false;
                        foreach (var kw in AltVDataDirNames)
                        {
                            if (innerName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                innerHasAltV = true;
                                break;
                            }
                        }

                        if (innerHasAltV)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "alt:V Data Found Inside Backup Directory",
                                Risk = RiskLevel.High,
                                Location = inner,
                                FileName = innerName,
                                Reason = $"Found alt:V related directory '{innerName}' inside a backup folder '{dirName}'. " +
                                         "This suggests alt:V profile data is being backed up for identity restoration after a ban.",
                                Detail = $"Backup root: {subDir}"
                            });
                        }
                    }
                }
            }
        }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 11: Ban evasion registry traces
    // -------------------------------------------------------------------------

    private Task CheckBanEvasionRegistryTraces(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var runKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        };

        foreach (var runKey in runKeys)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(runKey);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    ctx.IncrementRegistryKeys();
                    if (ct.IsCancellationRequested) return;

                    var value = key.GetValue(valueName)?.ToString() ?? string.Empty;

                    foreach (var kw in BanEvasionRegistryKeywords)
                    {
                        if (valueName.Contains(kw, StringComparison.OrdinalIgnoreCase)
                            || value.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Ban Evasion Tool in Registry Autostart",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKCU\{runKey}\{valueName}",
                                FileName = null,
                                Reason = $"Registry autostart entry '{valueName}' references ban evasion keywords. " +
                                         "A tool associated with alt:V ban evasion appears to be configured to run automatically at startup.",
                                Detail = $"Value: {value}"
                            });
                            break;
                        }
                    }
                }
            }
            catch { }
        }

        var mruPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU",
        };

        foreach (var mruPath in mruPaths)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(mruPath);
                if (key is null) continue;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    ctx.IncrementRegistryKeys();
                    if (ct.IsCancellationRequested) return;

                    using var subKey = key.OpenSubKey(subKeyName);
                    if (subKey is null) continue;

                    foreach (var valueName in subKey.GetValueNames())
                    {
                        var value = subKey.GetValue(valueName)?.ToString() ?? string.Empty;
                        foreach (var kw in BanEvasionRegistryKeywords)
                        {
                            if (value.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Ban Evasion Tool in Registry MRU",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKCU\{mruPath}\{subKeyName}\{valueName}",
                                    FileName = null,
                                    Reason = $"Registry MRU (Most Recently Used) entry references ban evasion keywords: '{kw}'. " +
                                             "This indicates the user recently interacted with a ban evasion tool via a file dialog.",
                                    Detail = $"Value data: {value[..Math.Min(value.Length, 200)]}"
                                });
                                break;
                            }
                        }
                    }
                }
            }
            catch { }
        }

        var userAssistPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        try
        {
            using var userAssistKey = Registry.CurrentUser.OpenSubKey(userAssistPath);
            if (userAssistKey is not null)
            {
                foreach (var guidKeyName in userAssistKey.GetSubKeyNames())
                {
                    ctx.IncrementRegistryKeys();
                    if (ct.IsCancellationRequested) return;

                    using var guidKey = userAssistKey.OpenSubKey(Path.Combine(guidKeyName, "Count"));
                    if (guidKey is null) continue;

                    foreach (var valueName in guidKey.GetValueNames())
                    {
                        foreach (var kw in BanEvasionRegistryKeywords)
                        {
                            if (valueName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Ban Evasion Tool Execution in UserAssist",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKCU\{userAssistPath}\{guidKeyName}\Count\{valueName}",
                                    FileName = null,
                                    Reason = $"UserAssist registry entry '{valueName}' shows a ban evasion tool was executed on this system. " +
                                             "UserAssist records GUI application launch history and provides strong evidence of tool execution.",
                                    Detail = $"Matched keyword: '{kw}'"
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    // -------------------------------------------------------------------------
    // Check 12: Prefetch entries for ban evasion executables
    // -------------------------------------------------------------------------

    private Task CheckPrefetchBanEvasionEntries(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir)) return;

        string[] pfFiles;
        try { pfFiles = Directory.GetFiles(prefetchDir, "*.pf"); }
        catch { return; }

        foreach (var pfFile in pfFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();

            var pfName = Path.GetFileNameWithoutExtension(pfFile) ?? string.Empty;
            var dashIdx = pfName.LastIndexOf('-');
            var exeNameRaw = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            var exeName = exeNameRaw.ToLowerInvariant();

            foreach (var banKeyword in PrefetchBanEvasionNames)
            {
                if (exeName.Contains(banKeyword, StringComparison.OrdinalIgnoreCase))
                {
                    DateTime lastRun = default;
                    try { lastRun = File.GetLastWriteTime(pfFile); } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Ban Evasion Tool in Prefetch: {exeNameRaw}.exe",
                        Risk = RiskLevel.Critical,
                        Location = pfFile,
                        FileName = exeNameRaw + ".exe",
                        Reason = $"Windows Prefetch contains an entry for '{exeNameRaw}.exe' which matches known " +
                                 "ban evasion tool naming patterns. Prefetch entries confirm the executable was launched on this system.",
                        Detail = lastRun != default
                            ? $"Prefetch last updated (approx. last run): {lastRun:yyyy-MM-dd HH:mm:ss}"
                            : null
                    });
                    break;
                }
            }
        }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 13: Server connection history with ban/kick records
    // -------------------------------------------------------------------------

    private Task CheckServerConnectionHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var altvAppData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv");

        var logSearchRoots = new List<string>();
        if (Directory.Exists(altvAppData)) logSearchRoots.Add(altvAppData);

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\altv");
            if (key?.GetValue("InstallPath") is string installPath && Directory.Exists(installPath))
                logSearchRoots.Add(installPath);
            ctx.IncrementRegistryKeys();
        }
        catch { }

        foreach (var logRoot in logSearchRoots)
        {
            IEnumerable<string> logFiles;
            try { logFiles = Directory.EnumerateFiles(logRoot, "*.log", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var logFile in logFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    var fi = new FileInfo(logFile);
                    if (fi.Length > 20 * 1024 * 1024) continue;

                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    var banLines = new List<string>();
                    foreach (var line in content.Split('\n'))
                    {
                        foreach (var kw in BanKickLogKeywords)
                        {
                            if (line.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                banLines.Add(line.Trim());
                                break;
                            }
                        }
                        if (banLines.Count >= 10) break;
                    }

                    if (banLines.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V Log Contains Ban/Kick Records",
                            Risk = RiskLevel.High,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"alt:V log file '{Path.GetFileName(logFile)}' contains {banLines.Count} line(s) with ban or kick messages. " +
                                     "Documented bans provide context for subsequent ban evasion activity.",
                            Detail = string.Join(Environment.NewLine, banLines.Take(5))
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 14: Auto-join scripts
    // -------------------------------------------------------------------------

    private Task CheckAutoJoinScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var searchDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) is string h ? Path.Combine(h, "Downloads") : null,
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
        };

        foreach (var dir in searchDirs)
        {
            if (dir is null || !Directory.Exists(dir)) continue;

            foreach (var ext in AutoJoinExtensions)
            {
                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, $"*{ext}", SearchOption.TopDirectoryOnly); }
                catch { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    try
                    {
                        var fi = new FileInfo(file);
                        if (fi.Length > 1 * 1024 * 1024) continue;

                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        bool hasAltV = false;
                        bool hasAutoJoin = false;
                        int matchCount = 0;

                        foreach (var kw in AutoJoinScriptKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                matchCount++;
                                if (kw.Contains("altv", StringComparison.OrdinalIgnoreCase)
                                    || kw.Contains("alt-v", StringComparison.OrdinalIgnoreCase))
                                    hasAltV = true;
                                else
                                    hasAutoJoin = true;
                            }
                        }

                        if (hasAltV && hasAutoJoin && matchCount >= 3)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Auto-Join Script Targeting alt:V Detected",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Script file '{Path.GetFileName(file)}' ({ext}) contains patterns indicating " +
                                         "it automatically restarts alt:V and reconnects to a server after being kicked or banned. " +
                                         $"Matched {matchCount} auto-join indicators.",
                                Detail = $"Script type: {ext}"
                            });
                        }
                        else if (hasAltV && matchCount >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Possible Auto-Reconnect Script for alt:V",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Script '{Path.GetFileName(file)}' references alt:V and loop/reconnect patterns. " +
                                         "May be configured to auto-reconnect after ban-induced kicks.",
                                Detail = $"Matched {matchCount} keywords in {ext} script"
                            });
                        }
                    }
                    catch { }
                }
            }
        }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 15: Social Club / Rockstar account data emptied or rotated
    // -------------------------------------------------------------------------

    private Task CheckRockstarAccountRotation(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var rgscPaths = new[]
        {
            Path.Combine(localAppData, "Rockstar Games", "Social Club"),
            Path.Combine(appData, "Rockstar Games", "Social Club"),
            Path.Combine(localAppData, "Rockstar Games", "Launcher"),
            Path.Combine(appData, "Rockstar Games", "GTA V"),
        };

        foreach (var rgscPath in rgscPaths)
        {
            if (!Directory.Exists(rgscPath)) continue;

            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(rgscPath, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            var profileFiles = new List<string>();
            var emptyProfileFiles = new List<string>();

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file) ?? string.Empty;
                bool isProfileRelated = false;
                foreach (var kw in RockstarRotationKeywords)
                {
                    if (fileName.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    {
                        isProfileRelated = true;
                        break;
                    }
                }

                var ext = Path.GetExtension(file);
                if (ext.Equals(".xml", StringComparison.OrdinalIgnoreCase)
                    || ext.Equals(".json", StringComparison.OrdinalIgnoreCase)
                    || ext.Equals(".dat", StringComparison.OrdinalIgnoreCase)
                    || isProfileRelated)
                {
                    profileFiles.Add(file);
                    var fi = new FileInfo(file);
                    if (fi.Length == 0) emptyProfileFiles.Add(file);
                }
            }

            if (emptyProfileFiles.Count > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Rockstar Social Club Profile Data Emptied",
                    Risk = RiskLevel.High,
                    Location = rgscPath,
                    FileName = null,
                    Reason = $"Found {emptyProfileFiles.Count} empty profile/data file(s) in Rockstar Social Club directory. " +
                             "Emptied RGSC profile data may indicate deliberate clearing of account identity for ban evasion " +
                             "on alt:V which relies on Rockstar account authentication.",
                    Detail = string.Join("; ", emptyProfileFiles.Select(Path.GetFileName))
                });
            }

            var loginFiles = profileFiles.Where(f =>
            {
                var name = Path.GetFileName(f) ?? string.Empty;
                return name.Contains("login", StringComparison.OrdinalIgnoreCase)
                       || name.Contains("account", StringComparison.OrdinalIgnoreCase)
                       || name.Contains("user", StringComparison.OrdinalIgnoreCase);
            }).ToList();

            if (loginFiles.Count > 2)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Multiple Rockstar Login/Account Files",
                    Risk = RiskLevel.Medium,
                    Location = rgscPath,
                    FileName = null,
                    Reason = $"Found {loginFiles.Count} login or account-related files in the Rockstar Social Club directory. " +
                             "Multiple Rockstar accounts suggest identity rotation for ban evasion on alt:V servers " +
                             "that track Rockstar credentials.",
                    Detail = string.Join("; ", loginFiles.Select(Path.GetFileName))
                });
            }
        }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\WOW6432Node\Rockstar Games\Rockstar Games Social Club");
            if (key is not null)
            {
                ctx.IncrementRegistryKeys();
                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString() ?? string.Empty;
                    if (valueName.Contains("account", StringComparison.OrdinalIgnoreCase)
                        && string.IsNullOrWhiteSpace(value))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cleared Rockstar Registry Account Entry",
                            Risk = RiskLevel.Medium,
                            Location = @"HKLM\SOFTWARE\WOW6432Node\Rockstar Games\Rockstar Games Social Club",
                            FileName = null,
                            Reason = $"Registry value '{valueName}' under Rockstar Social Club key is empty. " +
                                     "Cleared account registry values may indicate account rotation or identity wiping.",
                            Detail = $"Value name: {valueName}"
                        });
                    }
                }
            }
        }
        catch { }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 16: WireGuard/OpenVPN configs targeting alt:V master server
    // -------------------------------------------------------------------------

    private Task CheckWireGuardOpenVpnConfigs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var vpnSearchPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WireGuard"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WireGuard", "Data", "Configurations"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "OpenVPN", "config"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "OpenVPN", "config"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "OpenVPN", "config"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".wireguard"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "WireGuard"),
        };

        foreach (var vpnPath in vpnSearchPaths)
        {
            if (!Directory.Exists(vpnPath)) continue;

            foreach (var configExt in VpnConfigExtensions)
            {
                IEnumerable<string> configFiles;
                try { configFiles = Directory.EnumerateFiles(vpnPath, $"*{configExt}", SearchOption.AllDirectories); }
                catch { continue; }

                foreach (var configFile in configFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    try
                    {
                        using var fs = new FileStream(configFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        var matchedKeywords = new List<string>();
                        foreach (var kw in WireGuardOpenVpnKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                matchedKeywords.Add(kw);
                        }

                        if (matchedKeywords.Count > 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "WireGuard/OpenVPN Config Targeting alt:V Infrastructure",
                                Risk = RiskLevel.High,
                                Location = configFile,
                                FileName = Path.GetFileName(configFile),
                                Reason = $"VPN configuration file '{Path.GetFileName(configFile)}' references alt:V master server " +
                                         "domains or known alt:V IP ranges. This config may be used to tunnel traffic through " +
                                         "a different IP to evade alt:V IP-based bans.",
                                Detail = $"Matched: {string.Join(", ", matchedKeywords)}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }

        try
        {
            using var wgKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WireGuard");
            if (wgKey is not null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "WireGuard Service Installed",
                    Risk = RiskLevel.Low,
                    Location = @"HKLM\SYSTEM\CurrentControlSet\Services\WireGuard",
                    FileName = null,
                    Reason = "WireGuard VPN service is installed on this system. While legitimate uses exist, " +
                             "WireGuard is frequently used for IP rotation to evade alt:V server bans. " +
                             "Correlate with VPN config findings for full picture.",
                    Detail = "WireGuard service registry entry present"
                });
            }
        }
        catch { }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 17: Ban database browser history
    // -------------------------------------------------------------------------

    private Task CheckBanDatabaseBrowserHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        foreach (var browserRelPath in BrowserProfilePaths)
        {
            string browserBase;
            if (browserRelPath.StartsWith("Mozilla", StringComparison.OrdinalIgnoreCase))
                browserBase = Path.Combine(appData, browserRelPath);
            else
                browserBase = Path.Combine(localAppData, browserRelPath);

            if (!Directory.Exists(browserBase)) continue;

            IEnumerable<string> historyFiles;
            try
            {
                historyFiles = Directory.EnumerateFiles(browserBase, "History", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(browserBase, "places.sqlite", SearchOption.AllDirectories));
            }
            catch { continue; }

            foreach (var historyFile in historyFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                try
                {
                    var fi = new FileInfo(historyFile);
                    if (fi.Length > 200 * 1024 * 1024) continue;

                    using var fs = new FileStream(historyFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true,
                        bufferSize: 65536, leaveOpen: false);
                    string content = await sr.ReadToEndAsync(ct);

                    var matchedKeywords = new List<string>();
                    foreach (var kw in BanBrowserHistoryKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            matchedKeywords.Add(kw);
                    }

                    if (matchedKeywords.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Browser History Contains alt:V Ban Research",
                            Risk = RiskLevel.High,
                            Location = historyFile,
                            FileName = Path.GetFileName(historyFile),
                            Reason = $"Browser history database '{Path.GetFileName(historyFile)}' contains {matchedKeywords.Count} " +
                                     "search term(s) related to alt:V ban evasion, unban tools, or HWID reset services. " +
                                     "This indicates active research into ban circumvention methods.",
                            Detail = $"Matched queries: {string.Join(", ", matchedKeywords)}"
                        });
                    }
                }
                catch { }
            }
        }
    }, ct);

    // -------------------------------------------------------------------------
    // Check 18: Multiple authentication token files
    // -------------------------------------------------------------------------

    private Task CheckMultipleAuthTokenFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var altvAppData = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv");

        var tokenSearchRoots = new List<string>();
        if (Directory.Exists(altvAppData)) tokenSearchRoots.Add(altvAppData);

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\altv");
            if (key?.GetValue("InstallPath") is string installPath && Directory.Exists(installPath))
                tokenSearchRoots.Add(installPath);
            ctx.IncrementRegistryKeys();
        }
        catch { }

        foreach (var tokenRoot in tokenSearchRoots)
        {
            var tokenFilesByExt = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

            foreach (var tokenExt in TokenFileExtensions)
            {
                IEnumerable<string> tokenFiles;
                try { tokenFiles = Directory.EnumerateFiles(tokenRoot, $"*{tokenExt}", SearchOption.AllDirectories); }
                catch { continue; }

                var foundTokens = new List<string>();
                foreach (var tokenFile in tokenFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    foundTokens.Add(tokenFile);
                }

                if (foundTokens.Count > 0)
                    tokenFilesByExt[tokenExt] = foundTokens;
            }

            var totalTokenFiles = tokenFilesByExt.Values.Sum(l => l.Count);
            if (totalTokenFiles > 3)
            {
                var allTokenFiles = tokenFilesByExt.Values.SelectMany(x => x).ToList();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Multiple alt:V Authentication Token Files Found",
                    Risk = RiskLevel.Critical,
                    Location = tokenRoot,
                    FileName = null,
                    Reason = $"Found {totalTokenFiles} authentication token files ({string.Join(", ", tokenFilesByExt.Keys)}) " +
                             "in alt:V directories. Multiple token files strongly indicate token rotation — a technique used " +
                             "to switch between different authenticated identities to evade bans tied to a specific token.",
                    Detail = string.Join(Environment.NewLine, allTokenFiles.Take(10).Select(f =>
                    {
                        try
                        {
                            var fi = new FileInfo(f);
                            return $"{Path.GetFileName(f)} ({fi.Length} bytes, modified {fi.LastWriteTime:yyyy-MM-dd HH:mm})";
                        }
                        catch { return Path.GetFileName(f); }
                    }))
                });
            }
            else if (totalTokenFiles == 2 || totalTokenFiles == 3)
            {
                var allTokenFiles = tokenFilesByExt.Values.SelectMany(x => x).ToList();

                var ages = new List<TimeSpan>();
                foreach (var tf in allTokenFiles)
                {
                    try
                    {
                        var fi = new FileInfo(tf);
                        ages.Add(DateTime.Now - fi.LastWriteTime);
                    }
                    catch { }
                }

                bool hasRecentAndOld = ages.Any(a => a.TotalDays < 1) && ages.Any(a => a.TotalDays > 7);

                if (hasRecentAndOld)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "alt:V Token Files Suggest Rotation (Recent + Old)",
                        Risk = RiskLevel.High,
                        Location = tokenRoot,
                        FileName = null,
                        Reason = $"Found {totalTokenFiles} token files with mixed ages: some recent (< 1 day) and some older (> 7 days). " +
                                 "This pattern indicates token rotation where old tokens are retained while new ones are generated, " +
                                 "a hallmark of ban evasion by identity cycling.",
                        Detail = string.Join("; ", allTokenFiles.Select(f =>
                        {
                            try { return $"{Path.GetFileName(f)}: {new FileInfo(f).LastWriteTime:yyyy-MM-dd HH:mm}"; }
                            catch { return Path.GetFileName(f); }
                        }))
                    });
                }
                else
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Multiple alt:V Token Files Present",
                        Risk = RiskLevel.Medium,
                        Location = tokenRoot,
                        FileName = null,
                        Reason = $"Found {totalTokenFiles} authentication token files in alt:V directories. " +
                                 "While not conclusive alone, multiple token files may indicate account switching for ban evasion.",
                        Detail = string.Join("; ", allTokenFiles.Select(Path.GetFileName))
                    });
                }
            }

            foreach (var (ext, tokenFiles) in tokenFilesByExt)
            {
                foreach (var tokenFile in tokenFiles)
                {
                    if (ct.IsCancellationRequested) return;

                    try
                    {
                        var fi = new FileInfo(tokenFile);
                        if (fi.Length == 0)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Empty alt:V Token File (Possible Rotation Artifact)",
                                Risk = RiskLevel.Low,
                                Location = tokenFile,
                                FileName = Path.GetFileName(tokenFile),
                                Reason = $"Token file '{Path.GetFileName(tokenFile)}' exists but is empty. " +
                                         "Empty token files are commonly left behind after token rotation or after a " +
                                         "ban evasion tool wiped the active token.",
                                Detail = $"Last modified: {fi.LastWriteTime:yyyy-MM-dd HH:mm:ss}"
                            });
                        }
                        else if (fi.Length > 0)
                        {
                            using var fs = new FileStream(tokenFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            int suspiciousCount = 0;
                            if (content.Contains("token", StringComparison.OrdinalIgnoreCase)) suspiciousCount++;
                            if (content.Contains("hwid", StringComparison.OrdinalIgnoreCase)) suspiciousCount++;
                            if (content.Contains("identity", StringComparison.OrdinalIgnoreCase)) suspiciousCount++;
                            if (content.Contains("bypass", StringComparison.OrdinalIgnoreCase)) suspiciousCount++;
                            if (content.Contains("evade", StringComparison.OrdinalIgnoreCase)) suspiciousCount++;

                            if (suspiciousCount >= 3)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "alt:V Token File Contains Ban Evasion Indicators",
                                    Risk = RiskLevel.Critical,
                                    Location = tokenFile,
                                    FileName = Path.GetFileName(tokenFile),
                                    Reason = $"Token/auth file '{Path.GetFileName(tokenFile)}' contains {suspiciousCount} keywords " +
                                             "associated with ban evasion (hwid, bypass, evade, identity). " +
                                             "This file may be a configuration artifact for an authentication bypass tool.",
                                    Detail = $"File size: {fi.Length} bytes"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
        }
    }, ct);
}
