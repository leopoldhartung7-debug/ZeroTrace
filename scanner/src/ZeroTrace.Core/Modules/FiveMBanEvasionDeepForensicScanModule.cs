using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class FiveMBanEvasionDeepForensicScanModule : IScanModule
{
    public string Name => "FiveM Ban Evasion Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] FiveMDataPaths = { @"citizenfx\FiveM\FiveM.app", @"FiveM\FiveM.app" };
    private static readonly string[] BanEvasionExePatterns = { "FiveMCleaner.exe", "cfx_cleaner.exe", "fivem_reset.exe", "ban_cleaner.exe", "AccountSwitcher.exe", "RSC_Switch.exe", "rockstar_switcher.exe", "license_spoofer.exe" };
    private static readonly string[] CleanerScriptKeywords = { "FiveM.app", "citizenfx", "cfx", "cache", "plugins", "del /f", "Remove-Item", "FiveM" };
    private static readonly string[] BanListFileNames = { "ban_list.txt", "banned_servers.json", "server_bans.json", "my_bans.txt", "ban_history.json", "banned.txt" };
    private static readonly string[] CFXBanDomains = { "bans.cfx.re", "forum.cfx.re", "support.cfx.re", "ban.cfx.re" };
    private static readonly string[] BanEvasionRegistryKeys = { @"Software\FiveMCleaner", @"Software\CfxCleaner", @"Software\FiveMSpoofer" };
    private static readonly string[] AntiBanScriptNames = { "anti_ban.lua", "no_ban.lua", "ban_bypass.lua", "ac_bypass.lua", "antiban.lua", "bypass_ac.lua" };
    private static readonly string[] ProfileBackupNames = { "FiveM_backup", "fivem_clean", "profile_backup", "clean_fivem", "fivem_backup.zip", "clean_profile.zip" };

    private static readonly string[] TokenFileNames = { "tokens.json", "auth_token.json", "cfx_token.txt" };
    private static readonly string[] TokenScriptKeywords = { "FiveM", "token", "auth", "cfx" };
    private static readonly string[] RockstarAccountSwitcherExeNames = { "AccountSwitcher.exe", "RSC_Switch.exe", "rockstar_switcher.exe", "account_switch.exe" };
    private static readonly string[] IPRotationKeywords = { "api.fivem.net", "servers.fivem.net", "cfx.re", "fivem", "cfx" };
    private static readonly string[] HostsModificationDomains = { "api.fivem.net", "servers.fivem.net", "cfx.re", "citizenfx.com", "fivem.net" };
    private static readonly string[] LogDeletionKeywords = { "del /f /q", "del /f", "Remove-Item", "FiveM.app\\logs", "citizenfx" };
    private static readonly string[] HWIDSpooferFiveMKeywords = { "FiveM", "fivem", "FiveM.exe", "cfx", "citizenfx" };
    private static readonly string[] HWIDSpooferDirectoryNames = { "HWIDSpoofer", "Spoofer", "hwid_spoofer", "spoofer" };
    private static readonly string[] BanAppealKeywords = { "ban appeal", "unban request", "i was wrongly banned", "appeal ban", "ban reason", "ban dispute" };
    private static readonly string[] BanAppealDocExtensions = { ".docx", ".txt", ".pdf" };
    private static readonly string[] DiscordSwitcherExeNames = { "DiscordSwitch.exe", "discord_account_switch.exe", "discord_multi.exe" };
    private static readonly string[] AutoJoinAhkKeywords = { "fivem://connect/", "fivem://", "cfx.re/join/" };
    private static readonly string[] AutoJoinBatchKeywords = { "tokens.json", "auth_token.json", "FiveM.exe", "fivem_reset", "cfx_token" };
    private static readonly string[] LicenseSpoofExeNames = { "license_spoofer.exe", "cfx_license_gen.exe", "rockstar_spoof.exe" };
    private static readonly string[] ScheduledTaskCleanerKeywords = { "FiveM.app", "citizenfx", "cfx", "FiveM", "ban_cleaner", "fivem_reset" };

    private static string AppData => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static string Downloads => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
    private static string Desktop => Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static string Temp => Path.GetTempPath();
    private static string UserProfile => Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
    private static string ProgramFilesX86 => Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    private static string Documents => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static string System32 => Environment.GetFolderPath(Environment.SpecialFolder.System);

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckMultipleFiveMProfilesArtifacts(ctx, ct),
            CheckCFXTokenRotationArtifacts(ctx, ct),
            CheckRockstarAccountSwitcherArtifacts(ctx, ct),
            CheckFiveMCacheCleanerArtifacts(ctx, ct),
            CheckFiveMIdentitySpoofingArtifacts(ctx, ct),
            CheckSteamAlternateAccountArtifacts(ctx, ct),
            CheckFiveMIPRotationArtifacts(ctx, ct),
            CheckFiveMLogManipulationArtifacts(ctx, ct),
            CheckFiveMServerConnectionHistory(ctx, ct),
            CheckHWIDSpooferForFiveMArtifacts(ctx, ct),
            CheckFiveMBanListArtifacts(ctx, ct),
            CheckGlobalBanDatabaseQueryArtifacts(ctx, ct),
            CheckFiveMProfileBackupArtifacts(ctx, ct),
            CheckDiscordAccountSwitcherArtifacts(ctx, ct),
            CheckFiveMBanEvasionRegistryArtifacts(ctx, ct),
            CheckFiveMNativeAntibanToolArtifacts(ctx, ct),
            CheckFiveMAutoJoinScriptArtifacts(ctx, ct),
            CheckCfxReBanAppealArtifacts(ctx, ct)
        );
    }

    private Task CheckMultipleFiveMProfilesArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var profileRoots = new[]
        {
            Path.Combine(LocalAppData, "FiveM", "FiveM.app", "data", "profiles"),
            Path.Combine(AppData, "citizenfx", "FiveM", "FiveM.app", "data", "profiles"),
        };

        foreach (var root in profileRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            string[] profileDirs;
            try { profileDirs = Directory.GetDirectories(root); }
            catch { continue; }

            ctx.IncrementFiles();

            if (profileDirs.Length > 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Multiple FiveM Profile Directories Detected",
                    Risk = RiskLevel.Critical,
                    Location = root,
                    FileName = null,
                    Reason = $"Found {profileDirs.Length} FiveM profile directories in '{root}'. Multiple profiles indicate account switching to evade bans — each profile is tied to a different Rockstar Social Club license.",
                    Detail = $"Profiles: {string.Join(", ", profileDirs.Select(Path.GetFileName))}"
                });
            }

            foreach (var dir in profileDirs)
            {
                if (ct.IsCancellationRequested) return;
                string dirName = Path.GetFileName(dir) ?? string.Empty;

                if (dirName.Contains("backup", StringComparison.OrdinalIgnoreCase) ||
                    dirName.Contains("old", StringComparison.OrdinalIgnoreCase) ||
                    dirName.Contains("clean", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM Backup Profile Directory Found",
                        Risk = RiskLevel.Critical,
                        Location = dir,
                        FileName = dirName,
                        Reason = $"FiveM backup profile directory '{dirName}' found. Ban evaders keep backup profile directories to restore a clean identity after ban detection.",
                        Detail = $"Path: {dir}"
                    });
                }

                string[] dotProfileFiles;
                try { dotProfileFiles = Directory.GetFiles(dir, "*.profile", SearchOption.TopDirectoryOnly); }
                catch { continue; }

                foreach (var profileFile in dotProfileFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(profileFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        if (content.Contains("license", StringComparison.OrdinalIgnoreCase) ||
                            content.Contains("rockstar", StringComparison.OrdinalIgnoreCase) ||
                            content.Contains("socialclub", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Profile File With Rockstar Account Data",
                                Risk = RiskLevel.Critical,
                                Location = profileFile,
                                FileName = Path.GetFileName(profileFile),
                                Reason = $"FiveM profile file at '{profileFile}' contains Rockstar license or account data. Multiple such files across different profiles indicate Rockstar account switching for ban evasion.",
                                Detail = $"Profile: {Path.GetFileName(profileFile)} in {Path.GetDirectoryName(profileFile)}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckCFXTokenRotationArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var fiveMRoots = new[]
        {
            Path.Combine(LocalAppData, "FiveM", "FiveM.app"),
            Path.Combine(AppData, "citizenfx", "FiveM", "FiveM.app"),
            Path.Combine(LocalAppData, "FiveM"),
            Path.Combine(AppData, "citizenfx"),
        };

        var searchDirs = new List<string>(fiveMRoots) { Downloads, Desktop, UserProfile };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var tokenName in TokenFileNames)
            {
                string tokenPath = Path.Combine(dir, tokenName);
                if (!File.Exists(tokenPath)) continue;

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"CFX Token File Found: {tokenName}",
                    Risk = RiskLevel.Critical,
                    Location = tokenPath,
                    FileName = tokenName,
                    Reason = $"CFX authentication token file '{tokenName}' found at '{tokenPath}'. Token files outside standard FiveM paths or stored as backups indicate token rotation to evade account-based bans.",
                    Detail = $"Token file: {tokenPath}"
                });
            }
        }

        var scriptSearchDirs = new[] { Downloads, Desktop, Temp, UserProfile, Documents };

        foreach (var dir in scriptSearchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] scriptFiles;
            try
            {
                scriptFiles = Directory.GetFiles(dir, "*.bat", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(dir, "*.ps1", SearchOption.TopDirectoryOnly))
                    .Concat(Directory.GetFiles(dir, "*.cmd", SearchOption.TopDirectoryOnly))
                    .ToArray();
            }
            catch { continue; }

            foreach (var scriptFile in scriptFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool mentionsFiveM = content.Contains("FiveM", StringComparison.OrdinalIgnoreCase);
                    bool mentionsToken = content.Contains("token", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains("auth", StringComparison.OrdinalIgnoreCase);

                    if (mentionsFiveM && mentionsToken)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "CFX Token Rotation Script Detected",
                            Risk = RiskLevel.Critical,
                            Location = scriptFile,
                            FileName = Path.GetFileName(scriptFile),
                            Reason = $"Script '{Path.GetFileName(scriptFile)}' references both FiveM and token/auth keywords. This pattern is consistent with CFX token rotation scripts used to cycle Rockstar account tokens to evade bans.",
                            Detail = $"Script path: {scriptFile}"
                        });
                    }
                }
                catch { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckRockstarAccountSwitcherArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[] { Downloads, Desktop, Temp };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var exeName in RockstarAccountSwitcherExeNames)
            {
                string exePath = Path.Combine(dir, exeName);
                if (!File.Exists(exePath)) continue;

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Rockstar Account Switcher Tool Found: {exeName}",
                    Risk = RiskLevel.Critical,
                    Location = exePath,
                    FileName = exeName,
                    Reason = $"Rockstar/Social Club account switcher executable '{exeName}' found at '{exePath}'. Account switcher tools allow rapid switching between Rockstar accounts to evade license-based FiveM bans.",
                    Detail = $"Executable: {exePath}"
                });
            }
        }

        string launcherProfilesDir = Path.Combine(LocalAppData, "Rockstar Games", "Launcher");
        if (Directory.Exists(launcherProfilesDir))
        {
            ctx.IncrementFiles();

            string[] accountDirs;
            try { accountDirs = Directory.GetDirectories(launcherProfilesDir); }
            catch { accountDirs = Array.Empty<string>(); }

            if (accountDirs.Length > 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Multiple Rockstar Launcher Account Directories Found",
                    Risk = RiskLevel.Critical,
                    Location = launcherProfilesDir,
                    FileName = null,
                    Reason = $"Found {accountDirs.Length} directories in Rockstar Launcher profile path '{launcherProfilesDir}'. Multiple account directories indicate multiple Rockstar Social Club accounts configured, consistent with ban evasion via account switching.",
                    Detail = $"Launcher path: {launcherProfilesDir} | Directories: {accountDirs.Length}"
                });
            }
        }

        string socialClubAppData = Path.Combine(AppData, "Rockstar Games", "Social Club");
        if (Directory.Exists(socialClubAppData))
        {
            ctx.IncrementFiles();

            string[] accountFiles;
            try { accountFiles = Directory.GetFiles(socialClubAppData, "*.profile", SearchOption.AllDirectories)
                .Concat(Directory.GetFiles(socialClubAppData, "accounts*.json", SearchOption.AllDirectories))
                .ToArray(); }
            catch { accountFiles = Array.Empty<string>(); }

            if (accountFiles.Length > 1)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Multiple Rockstar Social Club Account Files Found",
                    Risk = RiskLevel.Critical,
                    Location = socialClubAppData,
                    FileName = null,
                    Reason = $"Found {accountFiles.Length} Rockstar Social Club account profile files in '{socialClubAppData}'. Multiple account profiles are a strong indicator of multiple accounts used for FiveM ban evasion.",
                    Detail = $"Social Club path: {socialClubAppData} | Files found: {accountFiles.Length}"
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMCacheCleanerArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[] { Downloads, Desktop, Temp, UserProfile };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var exeName in BanEvasionExePatterns)
            {
                string exePath = Path.Combine(dir, exeName);
                if (!File.Exists(exePath)) continue;

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"FiveM Cache Cleaner Executable Found: {exeName}",
                    Risk = RiskLevel.Critical,
                    Location = exePath,
                    FileName = exeName,
                    Reason = $"FiveM cache cleaner executable '{exeName}' found at '{exePath}'. Cache cleaners are used to delete ban-related data from FiveM directories, a core step in ban evasion.",
                    Detail = $"Executable: {exePath}"
                });
            }
        }

        var scriptSearchDirs = new[] { Downloads, Desktop, Temp, UserProfile, Documents };

        foreach (var dir in scriptSearchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] scriptFiles;
            try
            {
                scriptFiles = Directory.GetFiles(dir, "*.bat", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(dir, "*.ps1", SearchOption.TopDirectoryOnly))
                    .Concat(Directory.GetFiles(dir, "*.cmd", SearchOption.TopDirectoryOnly))
                    .ToArray();
            }
            catch { continue; }

            foreach (var scriptFile in scriptFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    int keywordHits = CleanerScriptKeywords.Count(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (keywordHits >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Directory Cleaner Script Detected",
                            Risk = RiskLevel.Critical,
                            Location = scriptFile,
                            FileName = Path.GetFileName(scriptFile),
                            Reason = $"Script '{Path.GetFileName(scriptFile)}' contains {keywordHits} FiveM cleaner keywords. Scripts that delete FiveM cache directories are used to wipe ban-related artifacts before reconnecting.",
                            Detail = $"Script: {scriptFile} | Matched keywords: {keywordHits}"
                        });
                    }
                }
                catch { }
            }
        }

        string system32Tasks = Path.Combine(System32, "Tasks");
        if (Directory.Exists(system32Tasks))
        {
            string[] taskFiles;
            try { taskFiles = Directory.GetFiles(system32Tasks, "*", SearchOption.AllDirectories); }
            catch { taskFiles = Array.Empty<string>(); }

            foreach (var taskFile in taskFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(taskFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    int kwHits = ScheduledTaskCleanerKeywords.Count(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (kwHits >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Scheduled Task Targeting FiveM Directories Found",
                            Risk = RiskLevel.Critical,
                            Location = taskFile,
                            FileName = Path.GetFileName(taskFile),
                            Reason = $"Scheduled task file '{Path.GetFileName(taskFile)}' references FiveM cleaner keywords ({kwHits} matches). Scheduled tasks that clear FiveM directories automate ban evasion cleanup.",
                            Detail = $"Task file: {taskFile} | Keyword matches: {kwHits}"
                        });
                    }
                }
                catch { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMIdentitySpoofingArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[] { Downloads, Desktop, Temp };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var exeName in LicenseSpoofExeNames)
            {
                string exePath = Path.Combine(dir, exeName);
                if (!File.Exists(exePath)) continue;

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"FiveM License Spoofer Executable Found: {exeName}",
                    Risk = RiskLevel.Critical,
                    Location = exePath,
                    FileName = exeName,
                    Reason = $"License spoofing tool '{exeName}' found at '{exePath}'. FiveM identity is tied to the Rockstar license hash; spoofing tools generate fake licenses to bypass account-based bans.",
                    Detail = $"Executable: {exePath}"
                });
            }
        }

        string[] rockstarRegPaths =
        {
            @"SOFTWARE\Rockstar Games\Social Club",
            @"SOFTWARE\WOW6432Node\Rockstar Games\Social Club",
        };

        foreach (var regPath in rockstarRegPaths)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                ctx.IncrementRegistryKeys();
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    if (valueName.Contains("license", StringComparison.OrdinalIgnoreCase) ||
                        valueName.Contains("serial", StringComparison.OrdinalIgnoreCase) ||
                        valueName.Contains("key", StringComparison.OrdinalIgnoreCase))
                    {
                        object? val = key.GetValue(valueName);
                        string valStr = val?.ToString() ?? string.Empty;

                        if (valStr.Length > 0 && valStr.All(c => c == '0' || c == 'x' || c == 'X'))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Suspicious Rockstar License Registry Value Found",
                                Risk = RiskLevel.Critical,
                                Location = $@"HKLM\{regPath}\{valueName}",
                                FileName = null,
                                Reason = $"Rockstar registry value '{valueName}' at 'HKLM\\{regPath}' contains a suspicious placeholder value consistent with a fake license generated by a license spoofer tool.",
                                Detail = $"Value: '{valueName}' = '{valStr}'"
                            });
                        }
                    }
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckSteamAlternateAccountArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string loginUsersPath = Path.Combine(ProgramFilesX86, "Steam", "config", "loginusers.vdf");

        if (File.Exists(loginUsersPath))
        {
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(loginUsersPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                int accountCount = 0;
                var lines = content.Split('\n');
                foreach (var line in lines)
                {
                    if (line.TrimStart().StartsWith("\"7656", StringComparison.OrdinalIgnoreCase))
                        accountCount++;
                }

                if (accountCount > 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Multiple Steam Accounts in loginusers.vdf",
                        Risk = RiskLevel.High,
                        Location = loginUsersPath,
                        FileName = "loginusers.vdf",
                        Reason = $"Steam loginusers.vdf at '{loginUsersPath}' contains {accountCount} remembered accounts. FiveM ban evaders purchase cheap games on new Steam accounts to obtain a different Steam identity for reconnecting after bans.",
                        Detail = $"Account entries found: {accountCount}"
                    });
                }
            }
            catch { }
        }

        string appDataSteamConfig = Path.Combine(AppData, "Steam", "config");
        if (Directory.Exists(appDataSteamConfig))
        {
            ctx.IncrementFiles();

            string familySharingPath = Path.Combine(appDataSteamConfig, "FamilySharingSessions.vdf");
            if (File.Exists(familySharingPath))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Steam Family Sharing Session File Found",
                    Risk = RiskLevel.High,
                    Location = familySharingPath,
                    FileName = "FamilySharingSessions.vdf",
                    Reason = $"Steam Family Sharing session file found at '{familySharingPath}'. Family sharing allows borrowing another account's game library, enabling ban evaders to use a different Steam identity for FiveM without purchasing a new game.",
                    Detail = $"File: {familySharingPath}"
                });
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMIPRotationArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        string hostsPath = Path.Combine(System32, "drivers", "etc", "hosts");

        if (File.Exists(hostsPath))
        {
            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                foreach (var domain in HostsModificationDomains)
                {
                    if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Hosts File Modified for FiveM/CFX Domain",
                            Risk = RiskLevel.Critical,
                            Location = hostsPath,
                            FileName = "hosts",
                            Reason = $"Windows hosts file at '{hostsPath}' contains an entry for FiveM/CFX domain '{domain}'. Hosts file modifications targeting FiveM/CFX domains can redirect ban check API calls or block ban reporting endpoints.",
                            Detail = $"Domain modified: {domain}"
                        });
                    }
                }
            }
            catch { }
        }

        var vpnConfigDirs = new[]
        {
            Path.Combine(AppData, "OpenVPN"),
            Path.Combine(AppData, "NordVPN"),
            Path.Combine(UserProfile, ".openvpn"),
            Path.Combine(UserProfile, "OpenVPN", "config"),
        };

        foreach (var dir in vpnConfigDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] ovpnFiles;
            try { ovpnFiles = Directory.GetFiles(dir, "*.ovpn", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var ovpnFile in ovpnFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(ovpnFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool mentionsCfx = IPRotationKeywords.Any(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (mentionsCfx)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "VPN Config Targeting FiveM/CFX Endpoints",
                            Risk = RiskLevel.Critical,
                            Location = ovpnFile,
                            FileName = Path.GetFileName(ovpnFile),
                            Reason = $"OpenVPN config file '{Path.GetFileName(ovpnFile)}' at '{ovpnFile}' references FiveM or CFX network endpoints. VPN configs explicitly targeting FiveM infrastructure are used for IP rotation to evade IP-based bans.",
                            Detail = $"VPN config: {ovpnFile}"
                        });
                    }
                }
                catch { }
            }
        }

        var scriptSearchDirs = new[] { Downloads, Desktop, Temp, Documents };

        foreach (var dir in scriptSearchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] scriptFiles;
            try
            {
                scriptFiles = Directory.GetFiles(dir, "*.bat", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(dir, "*.ps1", SearchOption.TopDirectoryOnly))
                    .ToArray();
            }
            catch { continue; }

            foreach (var scriptFile in scriptFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool mentionesCfxEndpoint = IPRotationKeywords.Any(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (mentionesCfxEndpoint)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "IP Rotation Script Targeting FiveM Endpoints",
                            Risk = RiskLevel.Critical,
                            Location = scriptFile,
                            FileName = Path.GetFileName(scriptFile),
                            Reason = $"Script '{Path.GetFileName(scriptFile)}' references FiveM/CFX network endpoints. Scripts that interact with FiveM connection endpoints in conjunction with IP rotation indicate ban evasion via IP cycling.",
                            Detail = $"Script: {scriptFile}"
                        });
                    }
                }
                catch { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMLogManipulationArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logDirs = new[]
        {
            Path.Combine(LocalAppData, "FiveM", "FiveM.app", "logs"),
            Path.Combine(AppData, "citizenfx", "FiveM", "FiveM.app", "logs"),
        };

        foreach (var logDir in logDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(logDir)) continue;

            ctx.IncrementFiles();

            string[] logFiles;
            try { logFiles = Directory.GetFiles(logDir, "*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            if (logFiles.Length == 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "FiveM Log Directory Is Empty",
                    Risk = RiskLevel.High,
                    Location = logDir,
                    FileName = null,
                    Reason = $"FiveM log directory '{logDir}' exists but contains no log files. An empty log directory after FiveM usage indicates deliberate log deletion to remove evidence of ban evasion activity.",
                    Detail = $"Log directory: {logDir}"
                });
            }
            else
            {
                bool allVeryRecent = logFiles.All(f =>
                {
                    try { return (DateTime.UtcNow - File.GetCreationTimeUtc(f)).TotalHours < 1; }
                    catch { return false; }
                });

                if (allVeryRecent && logFiles.Length > 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "All FiveM Log Files Have Recent Creation Timestamps",
                        Risk = RiskLevel.High,
                        Location = logDir,
                        FileName = null,
                        Reason = $"All {logFiles.Length} log files in '{logDir}' were created within the last hour. Uniform recent creation timestamps across all logs indicates the log directory was wiped and logs were recreated, a common anti-forensic technique.",
                        Detail = $"Log files with recent timestamps: {logFiles.Length}"
                    });
                }
            }
        }

        var scriptSearchDirs = new[] { Downloads, Desktop, Temp, UserProfile };

        foreach (var dir in scriptSearchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] scriptFiles;
            try
            {
                scriptFiles = Directory.GetFiles(dir, "*.bat", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(dir, "*.ps1", SearchOption.TopDirectoryOnly))
                    .Concat(Directory.GetFiles(dir, "*.cmd", SearchOption.TopDirectoryOnly))
                    .ToArray();
            }
            catch { continue; }

            foreach (var scriptFile in scriptFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool hasDeletion = LogDeletionKeywords.Any(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (hasDeletion)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Log Deletion Script Detected",
                            Risk = RiskLevel.High,
                            Location = scriptFile,
                            FileName = Path.GetFileName(scriptFile),
                            Reason = $"Script '{Path.GetFileName(scriptFile)}' contains FiveM log deletion commands. Deleting FiveM logs is an anti-forensic technique used to hide ban evasion connection history.",
                            Detail = $"Script: {scriptFile}"
                        });
                    }
                }
                catch { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMServerConnectionHistory(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var serverHistoryPaths = new[]
        {
            Path.Combine(AppData, "citizenfx", "FiveM", "FiveM.app", "data", "servers.json"),
            Path.Combine(LocalAppData, "FiveM", "FiveM.app", "data", "servers.json"),
            Path.Combine(AppData, "citizenfx", "FiveM", "FiveM.app", "data", "server_history.json"),
            Path.Combine(LocalAppData, "FiveM", "FiveM.app", "data", "server_history.json"),
        };

        foreach (var serverFile in serverHistoryPaths)
        {
            if (ct.IsCancellationRequested) return;
            if (!File.Exists(serverFile)) continue;

            ctx.IncrementFiles();
            try
            {
                using var fs = new FileStream(serverFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string content = await sr.ReadToEndAsync(ct);

                if (content.Contains("license", StringComparison.OrdinalIgnoreCase) &&
                    content.Length > 100)
                {
                    int licenseCount = 0;
                    int idx = 0;
                    while ((idx = content.IndexOf("license", idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                    {
                        licenseCount++;
                        idx++;
                    }

                    if (licenseCount > 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Server History Contains Multiple License References",
                            Risk = RiskLevel.High,
                            Location = serverFile,
                            FileName = Path.GetFileName(serverFile),
                            Reason = $"FiveM server connection history at '{serverFile}' contains {licenseCount} license references. Multiple license hashes in connection history indicate account switching between server connections, consistent with ban evasion.",
                            Detail = $"File: {serverFile} | License references: {licenseCount}"
                        });
                    }
                }

                if (content.Contains("banned", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("ban_reason", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("kick_reason", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "FiveM Server History Contains Ban/Kick Records",
                        Risk = RiskLevel.High,
                        Location = serverFile,
                        FileName = Path.GetFileName(serverFile),
                        Reason = $"FiveM server connection history at '{serverFile}' references ban or kick records. Connection history recording bans proves prior ban events; subsequent connections from the same machine indicate ban evasion.",
                        Detail = $"File: {serverFile}"
                    });
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckHWIDSpooferForFiveMArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var spooferDirs = new List<string>();
        foreach (var dirName in HWIDSpooferDirectoryNames)
        {
            spooferDirs.Add(Path.Combine(AppData, dirName));
            spooferDirs.Add(Path.Combine(LocalAppData, dirName));
            spooferDirs.Add(Path.Combine(UserProfile, dirName));
        }

        foreach (var dir in spooferDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            ctx.IncrementFiles();

            string[] spooferFiles;
            try { spooferFiles = Directory.GetFiles(dir, "*", SearchOption.AllDirectories); }
            catch { continue; }

            bool fiveMReferenced = false;
            foreach (var spooferFile in spooferFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                string fileName = Path.GetFileName(spooferFile);
                if (fileName.Equals("spoofer.log", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".log", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".cfg", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".ini", StringComparison.OrdinalIgnoreCase) ||
                    fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        using var fs = new FileStream(spooferFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        if (HWIDSpooferFiveMKeywords.Any(kw =>
                            content.Contains(kw, StringComparison.OrdinalIgnoreCase)))
                        {
                            fiveMReferenced = true;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "HWID Spoofer File References FiveM",
                                Risk = RiskLevel.Critical,
                                Location = spooferFile,
                                FileName = fileName,
                                Reason = $"HWID spoofer file '{fileName}' in '{dir}' contains references to FiveM or CFX. HWID spoofers configured to target FiveM bypass hardware-based ban identification tied to the game client.",
                                Detail = $"File: {spooferFile}"
                            });
                        }
                    }
                    catch { }
                }
            }

            if (!fiveMReferenced && spooferFiles.Length > 0)
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "HWID Spoofer Directory Found",
                    Risk = RiskLevel.Critical,
                    Location = dir,
                    FileName = null,
                    Reason = $"HWID spoofer directory '{dir}' detected. HWID spoofers invalidate hardware-based ban identifiers. When combined with FiveM installation artifacts, this indicates HWID spoofing for FiveM ban evasion.",
                    Detail = $"Spoofer directory: {dir} | Files: {spooferFiles.Length}"
                });
            }
        }

        string[] spooferRegKeys =
        {
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HWIDSpoofer",
            @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spoofer",
        };

        foreach (var regKey in spooferRegKeys)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                string subPath = regKey.Replace(@"HKEY_LOCAL_MACHINE\", string.Empty, StringComparison.OrdinalIgnoreCase);
                using var key = Registry.LocalMachine.OpenSubKey(subPath, writable: false);
                ctx.IncrementRegistryKeys();
                if (key is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "HWID Spoofer Service Registry Key Found",
                        Risk = RiskLevel.Critical,
                        Location = regKey,
                        FileName = null,
                        Reason = $"HWID spoofer service registry key '{regKey}' found. A registered HWID spoofer service indicates kernel-level hardware identifier manipulation, used to evade FiveM hardware-based bans.",
                        Detail = $"Registry key: {regKey}"
                    });
                }
            }
            catch { }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMBanListArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[] { UserProfile, Downloads, Desktop, Documents, Temp };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var banFileName in BanListFileNames)
            {
                string banFilePath = Path.Combine(dir, banFileName);
                if (!File.Exists(banFilePath)) continue;

                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(banFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool hasBanContent = content.Contains("ban", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains("server", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains("ip", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains("reason", StringComparison.OrdinalIgnoreCase);

                    if (hasBanContent)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM Ban Tracking File Found: {banFileName}",
                            Risk = RiskLevel.Critical,
                            Location = banFilePath,
                            FileName = banFileName,
                            Reason = $"Ban tracking file '{banFileName}' found at '{banFilePath}' with ban-related content. Ban evasion tools maintain local ban lists to track which servers banned the user and avoid reconnecting on the same identity.",
                            Detail = $"File: {banFilePath} | Content length: {content.Length} chars"
                        });
                    }
                }
                catch { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckGlobalBanDatabaseQueryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var browserHistoryPaths = new[]
        {
            Path.Combine(LocalAppData, "Google", "Chrome", "User Data", "Default", "History"),
            Path.Combine(AppData, "Mozilla", "Firefox", "Profiles"),
            Path.Combine(LocalAppData, "Microsoft", "Edge", "User Data", "Default", "History"),
        };

        foreach (var histPath in browserHistoryPaths)
        {
            if (ct.IsCancellationRequested) return;

            if (histPath.Contains("Firefox", StringComparison.OrdinalIgnoreCase))
            {
                if (!Directory.Exists(histPath)) continue;
                string[] profileDirs;
                try { profileDirs = Directory.GetDirectories(histPath); }
                catch { continue; }

                foreach (var profileDir in profileDirs)
                {
                    string placesSqlite = Path.Combine(profileDir, "places.sqlite");
                    if (!File.Exists(placesSqlite)) continue;

                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(placesSqlite, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.Latin1);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var domain in CFXBanDomains)
                        {
                            if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Browser History: CFX Ban Domain Visited ({domain})",
                                    Risk = RiskLevel.High,
                                    Location = placesSqlite,
                                    FileName = "places.sqlite",
                                    Reason = $"Firefox history database at '{placesSqlite}' contains references to CFX ban domain '{domain}'. Visiting ban-related CFX/FiveM domains indicates checking ban status, a precursor to ban evasion.",
                                    Detail = $"Domain: {domain} | History: {placesSqlite}"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
            else
            {
                if (!File.Exists(histPath)) continue;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(histPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var domain in CFXBanDomains)
                    {
                        if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Browser History: CFX Ban Domain Visited ({domain})",
                                Risk = RiskLevel.High,
                                Location = histPath,
                                FileName = Path.GetFileName(histPath),
                                Reason = $"Browser history database at '{histPath}' contains references to CFX ban domain '{domain}'. Visiting ban-related CFX/FiveM domains indicates checking ban status or filing ban appeals, consistent with prior ban history.",
                                Detail = $"Domain: {domain} | History: {histPath}"
                            });
                        }
                    }
                }
                catch { }
            }
        }

        var scriptSearchDirs = new[] { Downloads, Desktop, Documents, Temp };

        foreach (var dir in scriptSearchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] scriptFiles;
            try
            {
                scriptFiles = Directory.GetFiles(dir, "*.bat", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(dir, "*.ps1", SearchOption.TopDirectoryOnly))
                    .Concat(Directory.GetFiles(dir, "*.py", SearchOption.TopDirectoryOnly))
                    .ToArray();
            }
            catch { continue; }

            foreach (var scriptFile in scriptFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var domain in CFXBanDomains)
                    {
                        if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Script Querying CFX Ban Database Found",
                                Risk = RiskLevel.High,
                                Location = scriptFile,
                                FileName = Path.GetFileName(scriptFile),
                                Reason = $"Script '{Path.GetFileName(scriptFile)}' makes HTTP requests to CFX ban domain '{domain}'. Scripts that query ban databases check whether the current IP or license is banned before connecting, a classic ban evasion pattern.",
                                Detail = $"Script: {scriptFile} | Domain: {domain}"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMProfileBackupArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[] { UserProfile, Downloads, Desktop, Documents };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var backupName in ProfileBackupNames)
            {
                if (backupName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                {
                    string zipPath = Path.Combine(dir, backupName);
                    if (!File.Exists(zipPath)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Profile Backup Archive Found: {backupName}",
                        Risk = RiskLevel.Critical,
                        Location = zipPath,
                        FileName = backupName,
                        Reason = $"FiveM profile backup archive '{backupName}' found at '{zipPath}'. Ban evaders archive clean FiveM profile directories before using cheats, allowing them to restore a fresh identity after a ban.",
                        Detail = $"Archive: {zipPath}"
                    });
                }
                else
                {
                    string dirPath = Path.Combine(dir, backupName);
                    if (!Directory.Exists(dirPath)) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Profile Backup Directory Found: {backupName}",
                        Risk = RiskLevel.Critical,
                        Location = dirPath,
                        FileName = backupName,
                        Reason = $"FiveM profile backup directory '{backupName}' found at '{dirPath}'. Ban evaders keep backup copies of clean FiveM profiles to restore a fresh identity after server bans.",
                        Detail = $"Backup directory: {dirPath}"
                    });
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDiscordAccountSwitcherArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[] { Downloads, Desktop, Temp };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            foreach (var exeName in DiscordSwitcherExeNames)
            {
                string exePath = Path.Combine(dir, exeName);
                if (!File.Exists(exePath)) continue;

                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Discord Account Switcher Tool Found: {exeName}",
                    Risk = RiskLevel.High,
                    Location = exePath,
                    FileName = exeName,
                    Reason = $"Discord account switcher executable '{exeName}' found at '{exePath}'. Some FiveM servers use Discord authentication; account switcher tools allow using alternate Discord accounts to bypass Discord-linked bans.",
                    Detail = $"Executable: {exePath}"
                });
            }
        }

        string discordAppData = Path.Combine(AppData, "discord");
        if (Directory.Exists(discordAppData))
        {
            ctx.IncrementFiles();

            string[] tokenBackupFiles;
            try
            {
                tokenBackupFiles = Directory.GetFiles(discordAppData, "token*.txt", SearchOption.AllDirectories)
                    .Concat(Directory.GetFiles(discordAppData, "backup_token*", SearchOption.AllDirectories))
                    .ToArray();
            }
            catch { tokenBackupFiles = Array.Empty<string>(); }

            foreach (var tokenFile in tokenBackupFiles)
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Discord Backup Token File Found",
                    Risk = RiskLevel.High,
                    Location = tokenFile,
                    FileName = Path.GetFileName(tokenFile),
                    Reason = $"Discord backup token file '{Path.GetFileName(tokenFile)}' found at '{tokenFile}'. Stored backup tokens allow rapid switching between Discord accounts, used to bypass Discord-based authentication on FiveM servers.",
                    Detail = $"Token backup: {tokenFile}"
                });
            }
        }

        string betterDiscordPath = Path.Combine(AppData, "BetterDiscord");
        if (Directory.Exists(betterDiscordPath))
        {
            ctx.IncrementFiles();

            string pluginsDir = Path.Combine(betterDiscordPath, "plugins");
            if (Directory.Exists(pluginsDir))
            {
                string[] switcherPlugins;
                try
                {
                    switcherPlugins = Directory.GetFiles(pluginsDir, "*switch*", SearchOption.TopDirectoryOnly)
                        .Concat(Directory.GetFiles(pluginsDir, "*account*", SearchOption.TopDirectoryOnly))
                        .ToArray();
                }
                catch { switcherPlugins = Array.Empty<string>(); }

                foreach (var plugin in switcherPlugins)
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "BetterDiscord Account Switcher Plugin Found",
                        Risk = RiskLevel.High,
                        Location = plugin,
                        FileName = Path.GetFileName(plugin),
                        Reason = $"BetterDiscord account switcher plugin '{Path.GetFileName(plugin)}' found. BetterDiscord plugins that switch accounts enable rapid Discord identity changes to evade Discord-linked FiveM server bans.",
                        Detail = $"Plugin: {plugin}"
                    });
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMBanEvasionRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var regKeySuffix in BanEvasionRegistryKeys)
        {
            if (ct.IsCancellationRequested) return;
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(regKeySuffix, writable: false);
                ctx.IncrementRegistryKeys();
                if (key is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Ban Evasion Registry Key Found: {regKeySuffix.Split('\\').Last()}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKCU\{regKeySuffix}",
                        FileName = null,
                        Reason = $"Ban evasion tool registry key 'HKCU\\{regKeySuffix}' found. This key is created by known FiveM cleaner, ban cleaner, or spoofer tools used specifically for FiveM ban evasion.",
                        Detail = $"Registry key: HKCU\\{regKeySuffix}"
                    });
                }
            }
            catch { }
        }

        try
        {
            string profileListPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
            using var profileList = Registry.LocalMachine.OpenSubKey(profileListPath, writable: false);
            ctx.IncrementRegistryKeys();
            if (profileList is not null)
            {
                var subKeys = profileList.GetSubKeyNames();
                int deletedProfiles = 0;

                foreach (var sid in subKeys)
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        using var profileKey = profileList.OpenSubKey(sid, writable: false);
                        ctx.IncrementRegistryKeys();
                        if (profileKey is null) continue;

                        string? profilePath = profileKey.GetValue("ProfileImagePath") as string;
                        if (profilePath is not null && !Directory.Exists(profilePath))
                        {
                            deletedProfiles++;
                        }
                    }
                    catch { }
                }

                if (deletedProfiles > 0)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Deleted User Profile Registry Entries Found",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\{profileListPath}",
                        FileName = null,
                        Reason = $"Found {deletedProfiles} user profile registry entries in '{profileListPath}' pointing to non-existent directories. Deleted user profiles may indicate profile-based identity cycling used in FiveM ban evasion.",
                        Detail = $"Orphaned profile entries: {deletedProfiles}"
                    });
                }
            }
        }
        catch { }

        try
        {
            string runKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
            using var run = Registry.CurrentUser.OpenSubKey(runKey, writable: false);
            ctx.IncrementRegistryKeys();
            if (run is not null)
            {
                foreach (var valueName in run.GetValueNames())
                {
                    if (ct.IsCancellationRequested) break;
                    string val = run.GetValue(valueName)?.ToString() ?? string.Empty;

                    bool isBanEvasionAutostart = BanEvasionExePatterns.Any(exe =>
                        val.Contains(exe, StringComparison.OrdinalIgnoreCase)) ||
                        CleanerScriptKeywords.Any(kw =>
                        valueName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (isBanEvasionAutostart)
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Cleaner/Spoofer Autostart Registry Entry Found",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKCU\{runKey}\{valueName}",
                            FileName = null,
                            Reason = $"Autostart registry entry '{valueName}' in 'HKCU\\{runKey}' references a FiveM cleaner or spoofer tool ('{val}'). Autostart entries for ban evasion tools indicate persistent automated ban evasion.",
                            Detail = $"Value name: {valueName} | Command: {val}"
                        });
                    }
                }
            }
        }
        catch { }

        try
        {
            string mruKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs";
            using var mru = Registry.CurrentUser.OpenSubKey(mruKey, writable: false);
            ctx.IncrementRegistryKeys();
            if (mru is not null)
            {
                foreach (var subKeyName in mru.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        using var subKey = mru.OpenSubKey(subKeyName, writable: false);
                        if (subKey is null) continue;
                        ctx.IncrementRegistryKeys();

                        foreach (var valueName in subKey.GetValueNames())
                        {
                            byte[]? data = subKey.GetValue(valueName) as byte[];
                            if (data is null) continue;

                            string decoded = Encoding.Unicode.GetString(data);
                            bool isBanEvasionExe = BanEvasionExePatterns.Any(exe =>
                                decoded.Contains(exe, StringComparison.OrdinalIgnoreCase));

                            if (isBanEvasionExe)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Recent Documents MRU Contains Ban Evasion Executable Reference",
                                    Risk = RiskLevel.Critical,
                                    Location = $@"HKCU\{mruKey}\{subKeyName}",
                                    FileName = null,
                                    Reason = $"Windows Recent Documents MRU registry at 'HKCU\\{mruKey}\\{subKeyName}' references a known ban evasion executable. MRU entries prove the tool was recently opened by the user.",
                                    Detail = $"Decoded value: {decoded.Trim('\0')[..Math.Min(200, decoded.Trim('\0').Length)]}"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMNativeAntibanToolArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var fiveMResourceRoots = new[]
        {
            Path.Combine(AppData, "citizenfx", "FiveM", "FiveM.app", "citizen", "resources"),
            Path.Combine(LocalAppData, "FiveM", "FiveM.app", "citizen", "resources"),
            Path.Combine(AppData, "citizenfx", "FiveM", "FiveM.app", "resources"),
            Path.Combine(LocalAppData, "FiveM", "FiveM.app", "resources"),
        };

        foreach (var root in fiveMResourceRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            foreach (var antiBanName in AntiBanScriptNames)
            {
                string[] foundFiles;
                try { foundFiles = Directory.GetFiles(root, antiBanName, SearchOption.AllDirectories); }
                catch { continue; }

                foreach (var foundFile in foundFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Anti-Ban Lua Script Found: {antiBanName}",
                        Risk = RiskLevel.Critical,
                        Location = foundFile,
                        FileName = antiBanName,
                        Reason = $"FiveM anti-ban Lua script '{antiBanName}' found at '{foundFile}'. Anti-ban scripts hook into FiveM native functions to intercept or suppress ban signal transmission to the server.",
                        Detail = $"Script: {foundFile}"
                    });
                }
            }

            string[] luaFiles;
            try { luaFiles = Directory.GetFiles(root, "*.lua", SearchOption.AllDirectories); }
            catch { continue; }

            foreach (var luaFile in luaFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(luaFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool hasAntiBanKeyword =
                        content.Contains("anti_ban", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("antiban", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("anti-ban", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("bypass_ac", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("ac_bypass", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("ban_bypass", StringComparison.OrdinalIgnoreCase);

                    bool overridesNatives =
                        content.Contains("AddReplaceNative", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("ReplaceNative", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("NativeOverride", StringComparison.OrdinalIgnoreCase);

                    if (hasAntiBanKeyword || overridesNatives)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Lua Script With Anti-Ban or Native Override Keywords",
                            Risk = RiskLevel.Critical,
                            Location = luaFile,
                            FileName = Path.GetFileName(luaFile),
                            Reason = $"FiveM Lua script '{Path.GetFileName(luaFile)}' at '{luaFile}' contains anti-ban keywords or native function override calls. Scripts that override FiveM native functions are used to intercept and block ban detection calls.",
                            Detail = $"Script: {luaFile} | Anti-ban: {hasAntiBanKeyword} | NativeOverride: {overridesNatives}"
                        });
                    }
                }
                catch { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMAutoJoinScriptArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[] { Downloads, Desktop, Documents, UserProfile, Temp };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] ahkFiles;
            try { ahkFiles = Directory.GetFiles(dir, "*.ahk", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            foreach (var ahkFile in ahkFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(ahkFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool hasFiveMJoin = AutoJoinAhkKeywords.Any(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (hasFiveMJoin)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "AutoHotkey Script With FiveM Auto-Join Pattern",
                            Risk = RiskLevel.High,
                            Location = ahkFile,
                            FileName = Path.GetFileName(ahkFile),
                            Reason = $"AutoHotkey script '{Path.GetFileName(ahkFile)}' at '{ahkFile}' contains FiveM server connection patterns (fivem://connect/ or cfx.re/join/). AHK auto-join scripts re-join servers automatically after ban-driven disconnects, often cycling through new identities.",
                            Detail = $"AHK script: {ahkFile}"
                        });
                    }
                }
                catch { }
            }

            string[] batFiles;
            try { batFiles = Directory.GetFiles(dir, "*.bat", SearchOption.TopDirectoryOnly)
                .Concat(Directory.GetFiles(dir, "*.cmd", SearchOption.TopDirectoryOnly))
                .ToArray(); }
            catch { continue; }

            foreach (var batFile in batFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(batFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool clearsTokens = AutoJoinBatchKeywords.Any(kw =>
                        content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    bool launchesFiveM = content.Contains("FiveM.exe", StringComparison.OrdinalIgnoreCase) ||
                                        content.Contains("FiveM_b", StringComparison.OrdinalIgnoreCase);

                    if (clearsTokens && launchesFiveM)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "FiveM Auto-Relaunch Batch Script With Token Reset",
                            Risk = RiskLevel.High,
                            Location = batFile,
                            FileName = Path.GetFileName(batFile),
                            Reason = $"Batch script '{Path.GetFileName(batFile)}' at '{batFile}' both manipulates CFX token files and launches FiveM.exe. This pattern indicates an auto-join script that clears authentication tokens before relaunching FiveM on a fresh identity.",
                            Detail = $"Script: {batFile}"
                        });
                    }
                }
                catch { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckCfxReBanAppealArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var browserHistoryPaths = new[]
        {
            Path.Combine(LocalAppData, "Google", "Chrome", "User Data", "Default", "History"),
            Path.Combine(AppData, "Mozilla", "Firefox", "Profiles"),
            Path.Combine(LocalAppData, "Microsoft", "Edge", "User Data", "Default", "History"),
        };

        string[] banAppealDomains = { "forum.cfx.re", "ban.cfx.re", "support.cfx.re" };

        foreach (var histPath in browserHistoryPaths)
        {
            if (ct.IsCancellationRequested) return;

            if (histPath.Contains("Firefox", StringComparison.OrdinalIgnoreCase))
            {
                if (!Directory.Exists(histPath)) continue;
                string[] profileDirs;
                try { profileDirs = Directory.GetDirectories(histPath); }
                catch { continue; }

                foreach (var profileDir in profileDirs)
                {
                    string placesSqlite = Path.Combine(profileDir, "places.sqlite");
                    if (!File.Exists(placesSqlite)) continue;

                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(placesSqlite, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.Latin1);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var domain in banAppealDomains)
                        {
                            if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Browser History: Cfx.re Ban Appeal Domain Visited ({domain})",
                                    Risk = RiskLevel.High,
                                    Location = placesSqlite,
                                    FileName = "places.sqlite",
                                    Reason = $"Firefox history at '{placesSqlite}' contains visits to CFX ban appeal domain '{domain}'. Visiting ban appeal pages proves the user has been banned; subsequent FiveM usage constitutes ban evasion.",
                                    Detail = $"Domain: {domain} | History: {placesSqlite}"
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
            else
            {
                if (!File.Exists(histPath)) continue;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(histPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.Latin1);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var domain in banAppealDomains)
                    {
                        if (content.Contains(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Browser History: Cfx.re Ban Appeal Domain Visited ({domain})",
                                Risk = RiskLevel.High,
                                Location = histPath,
                                FileName = Path.GetFileName(histPath),
                                Reason = $"Browser history at '{histPath}' contains visits to CFX ban appeal domain '{domain}'. Ban appeal page visits prove prior ban events; continued FiveM play after visiting appeal pages is strong evidence of ban evasion.",
                                Detail = $"Domain: {domain} | History: {histPath}"
                            });
                        }
                    }
                }
                catch { }
            }
        }

        var documentSearchDirs = new[] { Documents, Desktop, Downloads, UserProfile };

        foreach (var dir in documentSearchDirs)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(dir)) continue;

            string[] documentFiles;
            try
            {
                documentFiles = Directory.GetFiles(dir, "*.docx", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(dir, "*.txt", SearchOption.TopDirectoryOnly))
                    .Concat(Directory.GetFiles(dir, "*.pdf", SearchOption.TopDirectoryOnly))
                    .ToArray();
            }
            catch { continue; }

            foreach (var docFile in documentFiles)
            {
                if (ct.IsCancellationRequested) return;

                string ext = Path.GetExtension(docFile);
                bool isCheckable = BanAppealDocExtensions.Any(e =>
                    ext.Equals(e, StringComparison.OrdinalIgnoreCase));
                if (!isCheckable) continue;

                ctx.IncrementFiles();

                if (ext.Equals(".txt", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        using var fs = new FileStream(docFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        bool hasBanAppeal = BanAppealKeywords.Any(kw =>
                            content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                        bool mentionsCfx = content.Contains("cfx.re", StringComparison.OrdinalIgnoreCase) ||
                                           content.Contains("fivem", StringComparison.OrdinalIgnoreCase) ||
                                           content.Contains("citizenfx", StringComparison.OrdinalIgnoreCase);

                        if (hasBanAppeal && mentionsCfx)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Ban Appeal Document Found",
                                Risk = RiskLevel.High,
                                Location = docFile,
                                FileName = Path.GetFileName(docFile),
                                Reason = $"Text document '{Path.GetFileName(docFile)}' at '{docFile}' contains ban appeal language and references to FiveM/CFX. Ban appeal documents prove the user was banned; their presence alongside FiveM activity constitutes evidence of ban evasion.",
                                Detail = $"Document: {docFile}"
                            });
                        }
                    }
                    catch { }
                }
                else
                {
                    string fileName = Path.GetFileName(docFile);
                    bool hasBanKeywordInName = BanAppealKeywords.Any(kw =>
                        fileName.Contains(kw.Replace(" ", "_", StringComparison.OrdinalIgnoreCase),
                            StringComparison.OrdinalIgnoreCase) ||
                        fileName.Contains(kw.Replace(" ", "-", StringComparison.OrdinalIgnoreCase),
                            StringComparison.OrdinalIgnoreCase));

                    bool mentionsFiveM = fileName.Contains("fivem", StringComparison.OrdinalIgnoreCase) ||
                                        fileName.Contains("cfx", StringComparison.OrdinalIgnoreCase) ||
                                        fileName.Contains("ban", StringComparison.OrdinalIgnoreCase);

                    if (mentionsFiveM)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM-Related Document File Found: {fileName}",
                            Risk = RiskLevel.High,
                            Location = docFile,
                            FileName = fileName,
                            Reason = $"Document file '{fileName}' at '{docFile}' has a name referencing FiveM or ban-related terms. Documents named after FiveM ban topics (ban appeals, evidence, etc.) indicate prior ban history and potential ban evasion context.",
                            Detail = $"Document: {docFile}"
                        });
                    }
                }
            }
        }

        await Task.CompletedTask;
    }, ct);
}
