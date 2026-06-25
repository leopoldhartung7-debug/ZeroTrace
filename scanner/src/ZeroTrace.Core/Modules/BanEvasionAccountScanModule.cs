using Microsoft.Win32;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

// Detects artifacts from ban evasion and account bypass techniques. Covers:
// multiple game account credentials stored in Windows Credential Manager,
// alt-account switcher tools, platform-specific ban bypass tools (Steam, EAC,
// BattlEye, Activision, EA, Riot), HWID spoofer activation via scheduled tasks,
// VPN auto-start on game launch, cheat re-purchase artifacts, license key
// collections, and game re-installation ban evasion evidence.
public sealed class BanEvasionAccountScanModule : IScanModule
{
    public string Name => "Ban Evasion & Account Bypass Detection";
    public double Weight => 4.1;
    public int ParallelGroup => 4;

    // Alt account switcher / manager executables
    private static readonly string[] AccountSwitcherExecutables =
    {
        "account_manager.exe", "accountmanager.exe", "account-manager.exe",
        "steam_account_switcher.exe", "steamaccountswitcher.exe",
        "account_rotator.exe", "accountrotator.exe", "account-rotator.exe",
        "multi_account.exe", "multiaccount.exe", "multi-account.exe",
        "alt_account.exe", "altaccount.exe", "alt-account.exe",
        "account_switcher.exe", "accountswitcher.exe", "acc_switcher.exe",
        "account_swap.exe", "accountswap.exe",
        "steam_account_manager.exe", "steamaccountmanager.exe",
        "multi_client.exe", "multiclient.exe",
        "account_bot.exe", "accountbot.exe",
    };

    // Steam-specific ban bypass executables
    private static readonly string[] SteamBanBypassExecutables =
    {
        "steam_ban_bypass.exe", "steambanbypass.exe", "steam-ban-bypass.exe",
        "steamid_changer.exe", "steamidchanger.exe", "steamid-changer.exe",
        "profile_changer.exe", "profilechanger.exe", "profile-changer.exe",
        "ban_bypass_steam.exe", "banbypasssteam.exe",
        "steam_unban.exe", "steamunban.exe",
        "vac_unban.exe", "vacunban.exe", "vac-unban.exe",
        "vac_bypass.exe", "vacbypass.exe",
    };

    // BattlEye ban bypass executables
    private static readonly string[] BattlEyeBypassExecutables =
    {
        "be_ban_bypass.exe", "bebanbypass.exe", "be-ban-bypass.exe",
        "be_unban.exe", "beunban.exe", "be-unban.exe",
        "be_spoofer.exe", "bespoofer.exe", "be-spoofer.exe",
        "battleye_bypass.exe", "battleyebypass.exe",
        "battleye_unban.exe", "battleyeunban.exe",
        "be_bypass.exe", "bebypass.exe",
    };

    // EAC (Easy Anti-Cheat) ban bypass executables
    private static readonly string[] EacBypassExecutables =
    {
        "eac_bypass.exe", "eacbypass.exe", "eac-bypass.exe",
        "eac_unban.exe", "eacunban.exe", "eac-unban.exe",
        "easy_anticheat_bypass.exe", "easyanticheatbypass.exe",
        "eac_ban_bypass.exe", "eacbanbypass.exe",
        "eac_spoofer.exe", "eacspoofer.exe",
    };

    // Activision/Battle.net/Warzone bypass executables
    private static readonly string[] ActivisionBypassExecutables =
    {
        "blizzard_bypass.exe", "blizzardbypass.exe", "blizzard-bypass.exe",
        "battlenet_bypass.exe", "battlenetbypass.exe", "battle-net-bypass.exe",
        "cod_unban.exe", "codunban.exe", "cod-unban.exe",
        "warzone_unban.exe", "warzoneunban.exe", "warzone-unban.exe",
        "activision_bypass.exe", "activisionbypass.exe", "activision-bypass.exe",
        "warzone_bypass.exe", "warzonebypass.exe",
        "cod_bypass.exe", "codbypass.exe",
        "shadow_ban_bypass.exe", "shadowbanbypass.exe",
    };

    // EA/Origin ban bypass executables
    private static readonly string[] EaBypassExecutables =
    {
        "ea_unban.exe", "eaunban.exe", "ea-unban.exe",
        "origin_unban.exe", "originunban.exe", "origin-unban.exe",
        "ea_bypass.exe", "eabypass.exe", "ea-bypass.exe",
        "origin_bypass.exe", "originbypass.exe", "origin-bypass.exe",
        "ea_ban_bypass.exe", "eabanbypass.exe",
        "eadesktop_bypass.exe", "eadesktopbypass.exe",
    };

    // Riot Games / Valorant / Vanguard bypass executables
    private static readonly string[] RiotBypassExecutables =
    {
        "riot_unban.exe", "riotunban.exe", "riot-unban.exe",
        "valorant_unban.exe", "valorantunban.exe", "valorant-unban.exe",
        "vanguard_bypass.exe", "vanguardbypass.exe", "vanguard-bypass.exe",
        "riot_bypass.exe", "riotbypass.exe", "riot-bypass.exe",
        "valorant_bypass.exe", "valorantbypass.exe",
        "vanguard_unban.exe", "vanguardunban.exe",
        "lol_unban.exe", "lolunban.exe",
    };

    // Cheat re-purchase artifact file names
    private static readonly string[] PurchaseArtifactFileNames =
    {
        "receipt.txt", "receipt.pdf", "order.txt", "order.pdf",
        "invoice.txt", "invoice.pdf", "purchase.txt", "purchase.pdf",
        "confirmation.txt", "order_confirmation.txt",
    };

    // License/key file names and patterns
    private static readonly string[] LicenseFileExtensions =
    {
        ".key", ".lic", ".license", ".serial",
    };

    private static readonly string[] LicenseFileNames =
    {
        "key.txt", "license.txt", "serial.txt", "license.key",
        "cheat.key", "cheat.lic", "loader.key", "activation.key",
        "activation.txt", "product_key.txt", "hwid_key.txt",
    };

    // Known banned-account backup directory names
    private static readonly string[] BannedAccountBackupDirNames =
    {
        "old_account", "old_acc", "oldaccount", "oldacc",
        "banned_acc", "banned_account", "bannedacc", "bannedaccount",
        "backup_steam", "steam_backup", "steambackup", "backupsteam",
        "banned", "banned_steam", "bannedssteam",
        "backup_account", "account_backup", "accountbackup",
        "old_steam", "steam_old",
    };

    // VPN executable names used for auto-start on game launch
    private static readonly string[] VpnExecutableNames =
    {
        "wireguard.exe", "openvpn.exe", "nordvpn.exe", "expressvpn.exe",
        "surfshark.exe", "protonvpn.exe", "mullvad.exe", "windscribe.exe",
        "privateinternetaccess.exe", "pia.exe", "cyberghost.exe",
        "ipvanish.exe", "vpn.exe", "vpnclient.exe",
    };

    // Game executable partial names for VPN+game scheduled task combo detection
    private static readonly string[] GameExecutableKeywords =
    {
        "valorant", "warzone", "fortnite", "apex", "csgo", "cs2", "rust",
        "tarkov", "battlefront", "battlefield", "rainbow", "siege",
        "pubg", "overwatch", "rocketleague", "destiny", "dayz",
    };

    // Regex to match spoofer JSON config listing games and spoof flags
    private static readonly Regex SpooferGameConfigRegex = new(
        @"""game""\s*:\s*""([^""]+)"".*?""spoof_(disk|nic|mac|hwid|gpu|cpu)""\s*:\s*true",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    // Regex to detect repeated cheat purchase receipts in a single file
    private static readonly Regex RepeatedPurchaseRegex = new(
        @"(order\s*(id|number|#)\s*:?\s*[A-Z0-9\-]{4,})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.00, Name, "Checking Windows Credential Manager for multiple game credentials...");
        await Task.Run(() => CheckCredentialManagerArtifacts(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.09, Name, "Scanning for account switcher tools...");
        await Task.Run(() => ScanForAccountSwitcherTools(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.18, Name, "Checking Steam ban bypass tools...");
        await Task.Run(() => ScanForPlatformBanBypassTools(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.28, Name, "Checking HWID spoofer autostart entries for ban evasion...");
        await Task.Run(() => CheckSpooferAutostartEntries(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.37, Name, "Checking scheduled tasks for VPN + game launch combos...");
        await Task.Run(() => CheckScheduledTasksForVpnGameCombo(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.46, Name, "Scanning for spoofer configs listing game ban targets...");
        await Task.Run(() => ScanSpooferGameConfigs(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.55, Name, "Checking for cheat re-purchase artifacts...");
        await Task.Run(() => ScanForCheatRepurchaseArtifacts(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.64, Name, "Scanning for cheat license key collections...");
        await Task.Run(() => ScanForLicenseKeyCollections(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.73, Name, "Checking for banned account backup directories...");
        await Task.Run(() => ScanForBannedAccountBackups(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.82, Name, "Checking for proxy rotation configs in cheat directories...");
        await Task.Run(() => ScanForProxyRotationConfigs(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(0.91, Name, "Checking registry for additional ban evasion indicators...");
        await Task.Run(() => CheckRegistryBanEvasionIndicators(ctx, ct), ct).ConfigureAwait(false);

        ctx.Report(1.00, Name, "Ban evasion and account bypass scan complete.");
    }

    // Enumerates files in %APPDATA%\Microsoft\Credentials\ and flags if there are
    // many credential blobs, which cheaters accumulate by storing multiple banned accounts.
    private void CheckCredentialManagerArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var roamingData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var credentialPaths = new[]
        {
            System.IO.Path.Combine(roamingData, "Microsoft", "Credentials"),
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "Credentials"),
        };

        int totalCredFiles = 0;
        var foundPaths = new List<string>();

        foreach (var credPath in credentialPaths)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(credPath)) continue;
            try
            {
                var files = Directory.GetFiles(credPath);
                totalCredFiles += files.Length;
                if (files.Length > 0) foundPaths.Add(credPath);
                ctx.IncrementFiles(files.Length);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }

        // More than 5 credential blobs is unusual for a single user account and
        // suggests accumulation of multiple game account credentials.
        if (totalCredFiles >= 5)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"High number of Windows Credential Manager entries ({totalCredFiles})",
                Risk     = totalCredFiles >= 10 ? RiskLevel.High : RiskLevel.Medium,
                Location = string.Join("; ", foundPaths),
                Reason   = $"The Windows Credential Manager store contains {totalCredFiles} credential " +
                           "blob files. While some legitimate applications store credentials here, " +
                           "cheaters accumulate many entries by saving banned game account passwords, " +
                           "multiple Steam accounts, and alt-account login credentials for rapid account " +
                           "switching after bans. A high count is suspicious when combined with other " +
                           "ban evasion indicators.",
                Detail   = $"Total credential files: {totalCredFiles} | Paths: {string.Join("; ", foundPaths)}"
            });
        }
    }

    // Scans common directories for alt-account switcher and manager executables.
    private void ScanForAccountSwitcherTools(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = GetStandardSearchRoots();

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;
            try
            {
                ScanDirectoryForFileNames(ctx, root, AccountSwitcherExecutables, ct,
                    maxDepth: 3,
                    titlePrefix: "Account switcher/manager tool",
                    reason: "is a known alt-account switcher or manager tool. These are used " +
                            "by ban-evading players to maintain and rapidly switch between multiple " +
                            "game accounts after bans are applied to their primary accounts. " +
                            "Account switchers often integrate with Steam family sharing, credential " +
                            "managers, and HWID spoofers to complete the ban evasion workflow.",
                    risk: RiskLevel.High);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Scans for platform-specific ban bypass tools across all supported platforms.
    private void ScanForPlatformBanBypassTools(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = GetStandardSearchRoots();

        var platformTools = new (string[] Executables, string Platform, RiskLevel Risk)[]
        {
            (SteamBanBypassExecutables, "Steam/VAC", RiskLevel.Critical),
            (BattlEyeBypassExecutables, "BattlEye", RiskLevel.Critical),
            (EacBypassExecutables, "Easy Anti-Cheat (EAC)", RiskLevel.Critical),
            (ActivisionBypassExecutables, "Activision/Battle.net", RiskLevel.Critical),
            (EaBypassExecutables, "EA/Origin", RiskLevel.Critical),
            (RiotBypassExecutables, "Riot/Vanguard", RiskLevel.Critical),
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            foreach (var (executables, platform, riskLevel) in platformTools)
            {
                if (ct.IsCancellationRequested) return;
                try
                {
                    ScanDirectoryForFileNames(ctx, root, executables, ct,
                        maxDepth: 3,
                        titlePrefix: $"{platform} ban bypass tool",
                        reason: $"is a known {platform} ban bypass tool. This category of tool " +
                                $"directly targets the {platform} anti-cheat or platform ban " +
                                "enforcement system to allow permanently banned players to " +
                                "continue using the platform. These tools often combine HWID " +
                                "spoofing with account credential manipulation to fully " +
                                "circumvent permanent hardware bans.",
                        risk: riskLevel);
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
    }

    // Generic directory scanner that looks for a list of file names and adds findings.
    private void ScanDirectoryForFileNames(ScanContext ctx, string directory,
        string[] targetFileNames, CancellationToken ct, int maxDepth,
        string titlePrefix, string reason, RiskLevel risk)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fileName = System.IO.Path.GetFileName(file);

            if (targetFileNames.Any(t => t.Equals(fileName, StringComparison.OrdinalIgnoreCase)))
            {
                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"{titlePrefix}: {fileName}",
                    Risk     = risk,
                    Location = file,
                    FileName = fileName,
                    Reason   = $"The file '{fileName}' {reason}",
                    Detail   = $"Path: {file}"
                });
            }
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            try { ScanDirectoryForFileNames(ctx, sub, targetFileNames, ct, maxDepth - 1, titlePrefix, reason, risk); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Checks autostart registry locations for HWID spoofer executables — ban evaders
    // configure spoofers to auto-run before game launch to ensure the spoof is active.
    private void CheckSpooferAutostartEntries(ScanContext ctx, CancellationToken ct)
    {
        var runKeys = new[]
        {
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.LocalMachine, "HKLM"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.CurrentUser, "HKCU"),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.CurrentUser, "HKCU"),
        };

        var spooferKeywords = new[]
        {
            "spoof", "hwid", "serialchange", "macchange", "nicspoof",
            "diskspoof", "cpuspoof", "gpuspoof", "bios_spoof", "bioschange",
            "rezeex", "klar", "striker", "phantom", "nemesis", "eclipse",
            "icebergspoof", "frigidspoof", "polarspoof", "zynspoof",
        };

        foreach (var (keyPath, hive, hiveName) in runKeys)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = hive.OpenSubKey(keyPath, writable: false);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                foreach (var valueName in key.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    var value = key.GetValue(valueName) as string ?? "";
                    var valueLower = value.ToLowerInvariant();
                    var nameLower = valueName.ToLowerInvariant();

                    foreach (var keyword in spooferKeywords)
                    {
                        if (valueLower.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                            nameLower.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module   = Name,
                                Title    = $"HWID spoofer autostart entry: {valueName}",
                                Risk     = RiskLevel.Critical,
                                Location = $@"{hiveName}\{keyPath}\{valueName}",
                                FileName = System.IO.Path.GetFileName(value.Split(' ')[0].Trim('"')),
                                Reason   = $"An autostart registry entry named '{valueName}' with value " +
                                           $"'{value}' contains the keyword '{keyword}', indicating a " +
                                           "HWID spoofer is configured to run automatically at system " +
                                           "startup or user login. Permanently banned players configure " +
                                           "spoofers to activate before the game launches so that the " +
                                           "hardware fingerprint is already replaced by the time the " +
                                           "anti-cheat system reads it.",
                                Detail   = $"ValueName: {valueName} | Value: {value} | Keyword: {keyword}"
                            });
                            break;
                        }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Reads Windows Task Scheduler XML task definitions to detect VPN + game
    // launch combinations that indicate structured ban evasion workflows.
    private void CheckScheduledTasksForVpnGameCombo(ScanContext ctx, CancellationToken ct)
    {
        var taskRoots = new[]
        {
            @"C:\Windows\System32\Tasks",
            @"C:\Windows\SysWOW64\Tasks",
        };

        foreach (var taskRoot in taskRoots)
        {
            if (!Directory.Exists(taskRoot)) continue;
            try
            {
                ScanTaskDirectoryForVpnGameCombo(ctx, taskRoot, ct, maxDepth: 3);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanTaskDirectoryForVpnGameCombo(ScanContext ctx, string directory,
        CancellationToken ct, int maxDepth)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            try
            {
                InspectTaskFileForVpnGameCombo(ctx, file);
            }
            catch (IOException) { }
            catch { }
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            try { ScanTaskDirectoryForVpnGameCombo(ctx, sub, ct, maxDepth - 1); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void InspectTaskFileForVpnGameCombo(ScanContext ctx, string taskFile)
    {
        string content;
        using var fs = new FileStream(taskFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var sr = new StreamReader(fs);
        content = sr.ReadToEnd();

        var contentLower = content.ToLowerInvariant();

        // Look for tasks that reference both a VPN executable and a game executable
        bool hasVpn  = VpnExecutableNames.Any(vpn =>
            contentLower.Contains(vpn, StringComparison.OrdinalIgnoreCase));
        bool hasGame = GameExecutableKeywords.Any(game =>
            contentLower.Contains(game, StringComparison.OrdinalIgnoreCase));

        if (!hasVpn || !hasGame) return;

        var matchedVpn  = VpnExecutableNames.First(vpn =>
            contentLower.Contains(vpn, StringComparison.OrdinalIgnoreCase));
        var matchedGame = GameExecutableKeywords.First(game =>
            contentLower.Contains(game, StringComparison.OrdinalIgnoreCase));

        // Also check for spoofer keywords to elevate risk for VPN+game+spoofer combo
        var spooferInTask = contentLower.Contains("spoof") || contentLower.Contains("hwid");
        var risk = spooferInTask ? RiskLevel.Critical : RiskLevel.High;

        ctx.AddFinding(new Finding
        {
            Module   = Name,
            Title    = $"Scheduled task combines VPN ({matchedVpn}) with game ({matchedGame})" +
                       (spooferInTask ? " and spoofer" : ""),
            Risk     = risk,
            Location = taskFile,
            FileName = System.IO.Path.GetFileName(taskFile),
            Reason   = $"A Windows scheduled task references both the VPN client '{matchedVpn}' " +
                       $"and the game or anti-cheat component '{matchedGame}'" +
                       (spooferInTask ? " along with a spoofer tool" : "") +
                       ". Automated task scheduling that launches a VPN before or alongside a " +
                       "game is a hallmark of structured ban evasion — the VPN provides IP address " +
                       "rotation to defeat IP bans, and when combined with HWID spoofing and " +
                       "account switching, enables a complete ban evasion workflow.",
            Detail   = $"Task: {System.IO.Path.GetFileName(taskFile)} | VPN: {matchedVpn} | Game: {matchedGame}"
                       + (spooferInTask ? " | Spoofer keyword present" : "")
        });
    }

    // Scans for spoofer JSON configuration files that list specific games and
    // spoof flags, indicating targeted ban evasion for those games.
    private void ScanSpooferGameConfigs(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = GetStandardSearchRoots();
        var configExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { ".json", ".cfg", ".ini", ".conf", ".config" };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;
            try
            {
                ScanForSpooferGameConfigsRecursive(ctx, root, configExtensions, ct, maxDepth: 3);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanForSpooferGameConfigsRecursive(ScanContext ctx, string directory,
        HashSet<string> configExtensions, CancellationToken ct, int maxDepth)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            var ext = System.IO.Path.GetExtension(file);
            if (!configExtensions.Contains(ext)) continue;

            ctx.IncrementFiles();
            try
            {
                InspectFileForSpooferGameConfig(ctx, file);
            }
            catch (IOException) { }
            catch { }
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            try { ScanForSpooferGameConfigsRecursive(ctx, sub, configExtensions, ct, maxDepth - 1); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void InspectFileForSpooferGameConfig(ScanContext ctx, string file)
    {
        string content;
        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var sr = new StreamReader(fs);
        content = sr.ReadToEnd();

        var match = SpooferGameConfigRegex.Match(content);
        if (!match.Success) return;

        var gameName = match.Groups[1].Value;
        var spoofType = match.Groups[2].Value;

        ctx.AddFinding(new Finding
        {
            Module   = Name,
            Title    = $"Spoofer config targeting game '{gameName}' for ban evasion",
            Risk     = RiskLevel.Critical,
            Location = file,
            FileName = System.IO.Path.GetFileName(file),
            Reason   = $"The configuration file '{System.IO.Path.GetFileName(file)}' contains a spoofer " +
                       $"configuration entry targeting the game '{gameName}' with '{spoofType}' spoofing " +
                       "enabled. This pattern — a JSON/config file specifying a game name alongside " +
                       "hardware spoofing flags — is the signature of targeted ban evasion: the user " +
                       "has configured their HWID spoofer specifically for that game's anti-cheat system.",
            Detail   = $"Game: {gameName} | SpoofType: {spoofType} | Config: {file}"
        });
    }

    // Scans cheat-related directories for receipt, order, and invoice files that
    // may contain evidence of repeated cheat software purchases after bans.
    private void ScanForCheatRepurchaseArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var cheatRoots = GetCheatToolDirectories();

        foreach (var root in cheatRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;
            try
            {
                ScanDirectoryForRepurchaseArtifacts(ctx, root, ct, maxDepth: 3);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanDirectoryForRepurchaseArtifacts(ScanContext ctx, string directory,
        CancellationToken ct, int maxDepth)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();

            foreach (var purchaseFile in PurchaseArtifactFileNames)
            {
                if (!fileName.Equals(purchaseFile, StringComparison.OrdinalIgnoreCase)) continue;

                // Read the file to check for repeated purchase order IDs
                try
                {
                    string content;
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = sr.ReadToEnd();

                    var orderMatches = RepeatedPurchaseRegex.Matches(content);
                    if (orderMatches.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Multiple cheat purchase orders in file: {System.IO.Path.GetFileName(file)}",
                            Risk     = RiskLevel.High,
                            Location = file,
                            FileName = System.IO.Path.GetFileName(file),
                            Reason   = $"The file '{System.IO.Path.GetFileName(file)}' in a cheat-related " +
                                       $"directory contains {orderMatches.Count} purchase order references. " +
                                       "Multiple purchase records for the same cheat software in a single " +
                                       "directory indicate that the cheat was re-purchased after one or more " +
                                       "ban waves revoked access. This pattern is a strong indicator of " +
                                       "persistent cheating behaviour across multiple account/HWID ban cycles.",
                            Detail   = $"Order count: {orderMatches.Count} | Path: {file} | " +
                                       $"First order: {orderMatches[0].Value}"
                        });
                    }
                    else
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"Cheat purchase receipt/invoice file: {System.IO.Path.GetFileName(file)}",
                            Risk     = RiskLevel.Medium,
                            Location = file,
                            FileName = System.IO.Path.GetFileName(file),
                            Reason   = $"A purchase receipt or invoice file '{System.IO.Path.GetFileName(file)}' " +
                                       "was found in a cheat-related directory. The presence of purchase " +
                                       "documentation alongside cheat tools confirms the intentional " +
                                       "acquisition of cheat software, which is relevant evidence in a " +
                                       "ban evasion investigation.",
                            Detail   = $"Path: {file}"
                        });
                    }
                }
                catch (IOException) { }
                catch { }
                break;
            }
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            try { ScanDirectoryForRepurchaseArtifacts(ctx, sub, ct, maxDepth - 1); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Scans cheat-related directories for collections of 5 or more license/key files,
    // indicating accumulation of cheat licenses across multiple ban cycles.
    private void ScanForLicenseKeyCollections(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = GetStandardSearchRoots();

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;
            try
            {
                ScanForLicenseKeyCollectionsRecursive(ctx, root, ct, maxDepth: 3);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanForLicenseKeyCollectionsRecursive(ScanContext ctx, string directory,
        CancellationToken ct, int maxDepth)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        var licenseFiles = new List<string>();
        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();
            var ext = System.IO.Path.GetExtension(file).ToLowerInvariant();

            bool isLicenseFile = LicenseFileExtensions.Contains(ext) ||
                                 LicenseFileNames.Any(lf => fileName.Equals(lf, StringComparison.OrdinalIgnoreCase));
            if (isLicenseFile) licenseFiles.Add(file);
        }

        if (licenseFiles.Count >= 5)
        {
            ctx.AddFinding(new Finding
            {
                Module   = Name,
                Title    = $"Large cheat license key collection ({licenseFiles.Count} files) in: {System.IO.Path.GetFileName(directory)}",
                Risk     = RiskLevel.High,
                Location = directory,
                Reason   = $"The directory '{directory}' contains {licenseFiles.Count} license or " +
                           "key files. A collection of five or more cheat license files in a single " +
                           "directory is strongly indicative of accumulated licenses from re-purchasing " +
                           "the same cheat software after repeated ban waves revoked previous license " +
                           "keys. Legitimate software installations rarely accumulate this many " +
                           "individual license files in one folder.",
                Detail   = $"License file count: {licenseFiles.Count} | Directory: {directory} | " +
                           $"Files: {string.Join(", ", licenseFiles.Take(5).Select(System.IO.Path.GetFileName))}"
                           + (licenseFiles.Count > 5 ? $" (+{licenseFiles.Count - 5} more)" : "")
            });
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            try { ScanForLicenseKeyCollectionsRecursive(ctx, sub, ct, maxDepth - 1); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Scans user directories for banned-account backup folders — these are kept
    // as reference for usernames, game progress, or items on the banned account.
    private void ScanForBannedAccountBackups(ScanContext ctx, CancellationToken ct)
    {
        var searchRoots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            @"C:\", @"D:\", @"E:\",
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;
            try
            {
                ScanForBannedAccountBackupsRecursive(ctx, root, ct, maxDepth: 2);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanForBannedAccountBackupsRecursive(ScanContext ctx, string directory,
        CancellationToken ct, int maxDepth)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            var dirName = System.IO.Path.GetFileName(sub).ToLowerInvariant();

            foreach (var bannedDirName in BannedAccountBackupDirNames)
            {
                if (dirName.Equals(bannedDirName, StringComparison.OrdinalIgnoreCase) ||
                    dirName.Contains(bannedDirName, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Banned account backup directory: {System.IO.Path.GetFileName(sub)}",
                        Risk     = RiskLevel.High,
                        Location = sub,
                        Reason   = $"The directory '{System.IO.Path.GetFileName(sub)}' matches a naming pattern " +
                                   "used for banned account backup folders. Players who receive hardware " +
                                   "bans often keep a backup of their banned account data (screenshots, " +
                                   "Steam config, friend lists, inventory snapshots) before switching " +
                                   "to a new account. The presence of such a directory is a supporting " +
                                   "indicator in a ban evasion investigation.",
                        Detail   = $"Path: {sub} | Pattern match: {bannedDirName}"
                    });
                    break;
                }
            }

            try { ScanForBannedAccountBackupsRecursive(ctx, sub, ct, maxDepth - 1); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Scans cheat directories for proxy rotation configuration files (proxy_list.txt,
    // socks_list.txt, etc.) used for multi-account IP rotation.
    private void ScanForProxyRotationConfigs(ScanContext ctx, CancellationToken ct)
    {
        var proxyFileNames = new[]
        {
            "proxy_list.txt", "proxylist.txt", "proxies.txt",
            "socks_list.txt", "sockslist.txt", "socks5.txt", "socks4.txt",
            "proxy_rotation.txt", "rotation.txt", "ip_list.txt",
        };

        var cheatRoots = GetCheatToolDirectories();

        foreach (var root in cheatRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;
            try
            {
                ScanDirectoryForProxyConfigs(ctx, root, proxyFileNames, ct, maxDepth: 3);
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void ScanDirectoryForProxyConfigs(ScanContext ctx, string directory,
        string[] proxyFileNames, CancellationToken ct, int maxDepth)
    {
        if (maxDepth <= 0 || ct.IsCancellationRequested) return;

        string[] files;
        try { files = Directory.GetFiles(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var file in files)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fileName = System.IO.Path.GetFileName(file).ToLowerInvariant();

            foreach (var proxyFile in proxyFileNames)
            {
                if (!fileName.Equals(proxyFile, StringComparison.OrdinalIgnoreCase)) continue;

                // Count lines to estimate proxy count
                int lineCount = 0;
                try
                {
                    string content;
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = sr.ReadToEnd();
                    lineCount = content.Split('\n', StringSplitOptions.RemoveEmptyEntries).Length;
                }
                catch (IOException) { }

                ctx.AddFinding(new Finding
                {
                    Module   = Name,
                    Title    = $"Proxy rotation list in cheat directory: {System.IO.Path.GetFileName(file)}",
                    Risk     = lineCount >= 10 ? RiskLevel.High : RiskLevel.Medium,
                    Location = file,
                    FileName = System.IO.Path.GetFileName(file),
                    Reason   = $"A proxy or SOCKS rotation list '{System.IO.Path.GetFileName(file)}' " +
                               $"({lineCount} entries) was found in a cheat-related directory. " +
                               "Proxy rotation lists stored alongside cheat tools are used to cycle " +
                               "IP addresses between game sessions to evade IP ban systems and " +
                               "regional restrictions. Multi-account cheaters use these to switch " +
                               "both the game account and the IP address simultaneously after a ban.",
                    Detail   = $"Proxy file: {proxyFile} | Line count: {lineCount} | Path: {file}"
                });
                break;
            }
        }

        string[] subDirs;
        try { subDirs = Directory.GetDirectories(directory); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var sub in subDirs)
        {
            if (ct.IsCancellationRequested) return;
            try { ScanDirectoryForProxyConfigs(ctx, sub, proxyFileNames, ct, maxDepth - 1); }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Checks registry for additional ban evasion indicators: Steam multiple
    // accounts, Riot/Vanguard bypass flags, and spoofer scheduler entries.
    private void CheckRegistryBanEvasionIndicators(ScanContext ctx, CancellationToken ct)
    {
        if (ct.IsCancellationRequested) return;

        // Check for Riot Vanguard uninstall artifacts — Vanguard is uninstalled
        // before attempting bypass, then reinstalled with spoofed hardware.
        CheckVanguardUninstallArtifacts(ctx, ct);

        // Check for BattlEye bypass service entries
        CheckBattlEyeBypassServiceEntries(ctx, ct);

        // Check for EAC bypass registry artifacts
        CheckEacBypassRegistryArtifacts(ctx, ct);

        // Check for Activision shadow ban detection bypass
        CheckActivisionBypassRegistryArtifacts(ctx, ct);
    }

    private void CheckVanguardUninstallArtifacts(ScanContext ctx, CancellationToken ct)
    {
        // Vanguard is kernel-level and must be uninstalled before hardware spoofers
        // can work. Evidence of Vanguard being removed then reinstalled is relevant.
        var vanguardServicePaths = new[]
        {
            @"SYSTEM\CurrentControlSet\Services\vgc",
            @"SYSTEM\CurrentControlSet\Services\vgk",
        };

        foreach (var svcPath in vanguardServicePaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(svcPath, writable: false);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                var startValue = key.GetValue("Start") as int?;
                var imagePath  = key.GetValue("ImagePath") as string ?? "";
                var errorCtrl  = key.GetValue("ErrorControl") as int?;

                // Vanguard service with Start=4 (disabled) alongside HWID spoofer artifacts
                // indicates the Vanguard bypass workflow: spoof HW → re-enable Vanguard.
                if (startValue == 4)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module   = Name,
                        Title    = $"Vanguard service disabled ({System.IO.Path.GetFileName(svcPath)}) — possible bypass workflow",
                        Risk     = RiskLevel.High,
                        Location = $@"HKLM\{svcPath}\Start",
                        Reason   = $"The Riot Vanguard anti-cheat service '{System.IO.Path.GetFileName(svcPath)}' " +
                                   "has its Start value set to 4 (Disabled). Vanguard-bypass workflows " +
                                   "require disabling the kernel-level anti-cheat driver before running " +
                                   "HWID spoofing tools, then re-enabling it on a 'clean' hardware " +
                                   "fingerprint. A disabled Vanguard service combined with other spoofer " +
                                   "artifacts is a strong ban evasion indicator.",
                        Detail   = $"Service: {System.IO.Path.GetFileName(svcPath)} | Start = 4 | ImagePath: {imagePath}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void CheckBattlEyeBypassServiceEntries(ScanContext ctx, CancellationToken ct)
    {
        // BattlEye bypass tools sometimes install themselves as services or modify
        // BattlEye service entries.
        const string servicesPath = @"SYSTEM\CurrentControlSet\Services";
        var beBypassKeywords = new[] { "be_bypass", "bebypass", "be_unban", "beunban", "battleye_bypass" };

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(servicesPath, writable: false);
            if (servicesKey is null) return;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                var svcLower = svcName.ToLowerInvariant();

                foreach (var keyword in beBypassKeywords)
                {
                    if (svcLower.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"BattlEye bypass service entry: {svcName}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{servicesPath}\{svcName}",
                            Reason   = $"A Windows service named '{svcName}' matches a BattlEye ban " +
                                       "bypass keyword pattern. BattlEye bypass tools that install as " +
                                       "kernel services are used to intercept BattlEye's hardware " +
                                       "scanning routines, allowing permanently banned players to " +
                                       "pass hardware checks on the same physical machine.",
                            Detail   = $"Service: {svcName} | Keyword: {keyword}"
                        });
                        break;
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch { }
    }

    private void CheckEacBypassRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        // EAC stores its hardware ID in registry; bypass tools modify these entries.
        var eacPaths = new[]
        {
            @"SOFTWARE\Epic Games\EasyAntiCheat",
            @"SOFTWARE\EasyAntiCheat",
            @"SOFTWARE\WOW6432Node\EasyAntiCheat",
        };

        foreach (var eacPath in eacPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(eacPath, writable: false);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                // Look for zeroed or placeholder HWID values that EAC bypass tools write
                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName) as string ?? "";
                    if (string.IsNullOrWhiteSpace(value)) continue;

                    var valueLower = value.ToLowerInvariant().Trim();
                    if ((valueLower.Replace("0", "").Replace("-", "").Length == 0 && value.Length >= 8) ||
                        valueLower is "bypass" or "modified" or "spoofed" or "none" or "null")
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module   = Name,
                            Title    = $"EAC registry value appears zeroed or spoofed: {valueName}",
                            Risk     = RiskLevel.Critical,
                            Location = $@"HKLM\{eacPath}\{valueName}",
                            Reason   = $"The Easy Anti-Cheat registry value '{valueName}' under " +
                                       $"'{eacPath}' contains a suspicious value: '{value}'. " +
                                       "EAC ban bypass tools modify or zero out the hardware " +
                                       "identifier values that EAC stores in the registry as part " +
                                       "of its hardware ban enforcement, allowing permanently banned " +
                                       "players to bypass the hardware ban check.",
                            Detail   = $"EAC path: {eacPath} | ValueName: {valueName} | Value: {value}"
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    private void CheckActivisionBypassRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        // Activision uses a machine ID stored in registry for shadow ban detection.
        // Bypass tools modify or delete these to escape shadow bans.
        var activisionPaths = new[]
        {
            @"SOFTWARE\Activision",
            @"SOFTWARE\WOW6432Node\Activision",
            @"SOFTWARE\Blizzard Entertainment",
            @"SOFTWARE\WOW6432Node\Blizzard Entertainment",
        };

        foreach (var actPath in activisionPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(actPath, writable: false);
                if (key is null) continue;
                ctx.IncrementRegistryKeys();

                // Scan for subkeys with machine ID or hardware ID values that are zeroed
                foreach (var subName in key.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    try
                    {
                        using var subKey = key.OpenSubKey(subName, writable: false);
                        if (subKey is null) continue;
                        ctx.IncrementRegistryKeys();

                        foreach (var valueName in subKey.GetValueNames())
                        {
                            var lowerValueName = valueName.ToLowerInvariant();
                            if (!lowerValueName.Contains("machine") &&
                                !lowerValueName.Contains("hwid") &&
                                !lowerValueName.Contains("device") &&
                                !lowerValueName.Contains("hardware")) continue;

                            var value = subKey.GetValue(valueName) as string ?? "";
                            if (string.IsNullOrWhiteSpace(value)) continue;

                            var cleanValue = value.Replace("0", "").Replace("-", "").Replace("{", "").Replace("}", "").Trim();
                            if (cleanValue.Length == 0 && value.Length >= 8)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module   = Name,
                                    Title    = $"Activision/Blizzard machine ID value appears zeroed: {valueName}",
                                    Risk     = RiskLevel.High,
                                    Location = $@"HKLM\{actPath}\{subName}\{valueName}",
                                    Reason   = $"The Activision/Blizzard registry value '{valueName}' under " +
                                               $"'{actPath}\\{subName}' contains an all-zero value. " +
                                               "Activision shadow ban and hardware ban bypass tools modify " +
                                               "machine identifier values in the Battle.net/Activision " +
                                               "registry entries to reset the hardware fingerprint used " +
                                               "for shadow ban tracking in Call of Duty and Warzone.",
                                    Detail   = $"Path: {actPath}\\{subName} | ValueName: {valueName} | Value: {value}"
                                });
                            }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }
    }

    // Returns the standard set of directories to search for ban evasion tools.
    private static string[] GetStandardSearchRoots()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            System.IO.Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            System.IO.Path.Combine(userProfile, "Documents"),
            @"C:\Tools", @"C:\Hack", @"C:\Hacks", @"C:\Cheats",
            @"C:\Loaders", @"C:\Injectors", @"C:\Spoofers",
            @"D:\Tools", @"D:\Hack", @"D:\Cheats",
        };
    }

    // Returns directories that are strongly associated with cheat toolsets.
    private static string[] GetCheatToolDirectories()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var downloads   = System.IO.Path.Combine(userProfile, "Downloads");
        var desktop     = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);

        var roots = new List<string>
        {
            @"C:\Cheats", @"C:\Hack", @"C:\Hacks", @"C:\Tools",
            @"C:\Loaders", @"C:\Injectors", @"C:\Spoofers",
            @"D:\Cheats", @"D:\Hack", @"D:\Tools",
        };

        // Add cheat-keyword-named subdirectories of Downloads and Desktop
        var cheatKeywords = new[]
        {
            "cheat", "hack", "loader", "injector", "spoofer", "bypass", "evasion"
        };

        foreach (var baseDir in new[] { downloads, desktop })
        {
            if (!Directory.Exists(baseDir)) continue;
            try
            {
                foreach (var sub in Directory.GetDirectories(baseDir))
                {
                    var name = System.IO.Path.GetFileName(sub).ToLowerInvariant();
                    if (cheatKeywords.Any(kw => name.Contains(kw, StringComparison.OrdinalIgnoreCase)))
                        roots.Add(sub);
                }
            }
            catch { }
        }

        return roots.ToArray();
    }
}
