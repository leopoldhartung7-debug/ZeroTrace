using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class RageMPBanEvasionDeepForensicScanModule : IScanModule
{
    public string Name => "RageMP Ban Evasion Deep Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] RageMPPaths = {
        @"RAGEMP", @"RAGE Multiplayer", @"ragemp"
    };

    private static readonly string[] BanEvasionExeNames = {
        "ragemp_cleaner.exe", "rage_cleaner.exe", "ragemp_reset.exe", "rage_reset.exe",
        "ragemp_spoofer.exe", "rage_spoofer.exe", "hwid_spoofer.exe", "mac_spoofer.exe",
        "ragemp_antiban.exe", "rage_antiban.exe", "serial_spoofer.exe"
    };

    private static readonly string[] CleanerScriptKeywords = {
        "RAGEMP", "RAGE Multiplayer", "ragemp", "del /f", "Remove-Item", "rmdir",
        "AppData\\RAGEMP", "LocalAppData\\RAGEMP", "rage_mp", "updater"
    };

    private static readonly string[] AccountSwitcherNames = {
        "account_switcher.exe", "ragemp_switch.exe", "gta_account.exe",
        "rockstar_switch.exe", "social_club_switch.exe", "rsc_switch.exe"
    };

    private static readonly string[] BanListFileNames = {
        "banned_servers.json", "ban_list.txt", "ragemp_bans.txt", "server_bans.json",
        "my_bans.txt", "rage_bans.json", "banned.txt", "kick_log.txt"
    };

    private static readonly string[] AntiBanScriptNames = {
        "anti_ban.js", "antiban.js", "no_ban.js", "bypass.js", "rage_bypass.js",
        "anti_kick.js", "spoof.js", "rage_spoof.js"
    };

    private static readonly string[] RageMPClearedDirs = {
        @"RAGEMP\logs", @"RAGEMP\cache", @"RAGEMP\updater\cache",
        @"RAGEMP\client_packages", @"RAGEMP\cs_packages"
    };

    private static readonly string[] IPRotationKeywords = {
        "ragemp", "rage.mp", "rage-mp.com", "mtasa.com/ragemp",
        "api.rage.mp", "updater.rage.mp", "192.168.1"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localappdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var userprofile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var downloads = Path.Combine(userprofile, "Downloads");
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var temp = Path.GetTempPath();

        await Task.WhenAll(
            CheckMultipleRageMPProfilesArtifacts(ctx, ct, appdata, localappdata),
            CheckRageMPCacheCleanerArtifacts(ctx, ct, userprofile, desktop, downloads, documents, temp),
            CheckRageMPAccountSwitcherArtifacts(ctx, ct, userprofile, desktop, downloads, temp),
            CheckRageMPSteamAlternateAccountArtifacts(ctx, ct),
            CheckRageMPIPRotationArtifacts(ctx, ct, userprofile, desktop, downloads, documents),
            CheckRageMPHWIDSpoofArtifacts(ctx, ct, userprofile, desktop, downloads),
            CheckRageMPLogManipulationArtifacts(ctx, ct, localappdata),
            CheckRageMPBanListArtifacts(ctx, ct, userprofile, desktop, downloads, documents),
            CheckRageMPAntiBanScriptArtifacts(ctx, ct, localappdata, userprofile, downloads),
            CheckRageMPProfileBackupArtifacts(ctx, ct, userprofile, desktop, downloads),
            CheckRageMPBanEvasionRegistryArtifacts(ctx, ct),
            CheckRageMPPrefetchArtifacts(ctx, ct),
            CheckRageMPServerConnectionHistoryArtifacts(ctx, ct, localappdata),
            CheckRageMPAutoJoinScriptArtifacts(ctx, ct, userprofile, desktop, downloads, documents),
            CheckRageMPSocialClubManipulationArtifacts(ctx, ct, localappdata, userprofile),
            CheckRageMPVPNSpecificArtifacts(ctx, ct, userprofile, downloads, documents),
            CheckRageMPBanDatabaseQueryArtifacts(ctx, ct, localappdata),
            CheckRageMPTokenRotationArtifacts(ctx, ct, appdata, localappdata, userprofile)
        );
    }

    private Task CheckMultipleRageMPProfilesArtifacts(ScanContext ctx, CancellationToken ct, string appdata, string localappdata) =>
        Task.Run(async () =>
        {
            var ragePaths = new[]
            {
                Path.Combine(localappdata, "RAGEMP"),
                Path.Combine(appdata, "RAGEMP"),
                Path.Combine(localappdata, "RAGE Multiplayer")
            };
            foreach (var ragePath in ragePaths)
            {
                if (!Directory.Exists(ragePath)) continue;
                ctx.IncrementFiles();
                try
                {
                    var profileDirs = Directory.EnumerateDirectories(ragePath, "profile*", SearchOption.TopDirectoryOnly).ToList();
                    profileDirs.AddRange(Directory.EnumerateDirectories(ragePath, "backup*", SearchOption.TopDirectoryOnly));
                    profileDirs.AddRange(Directory.EnumerateDirectories(ragePath, "clean*", SearchOption.TopDirectoryOnly));
                    if (profileDirs.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Multiple RageMP Profile Directories",
                            Risk = RiskLevel.Critical,
                            Location = ragePath,
                            FileName = Path.GetFileName(ragePath),
                            Reason = $"Found {profileDirs.Count} RageMP profile/backup directories — indicates account/identity switching for ban evasion",
                            Detail = $"Directory: {ragePath} | Multiple profiles: {string.Join(", ", profileDirs.Select(Path.GetFileName).Take(5))}"
                        });
                    }

                    var dataDir = Path.Combine(ragePath, "data");
                    if (Directory.Exists(dataDir))
                    {
                        foreach (var file in Directory.EnumerateFiles(dataDir, "*.json", SearchOption.TopDirectoryOnly))
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementFiles();
                            try
                            {
                                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                string content = await sr.ReadToEndAsync(ct);
                                if ((content.IndexOf("license:", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     content.IndexOf("\"license\"", StringComparison.OrdinalIgnoreCase) >= 0) &&
                                    content.Length > 100)
                                {
                                    var licenseCount = 0;
                                    var idx = 0;
                                    while ((idx = content.IndexOf("license", idx, StringComparison.OrdinalIgnoreCase)) >= 0) { licenseCount++; idx++; }
                                    if (licenseCount > 3)
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = Name,
                                            Title = "RageMP Multiple License Identifiers",
                                            Risk = RiskLevel.Critical,
                                            Location = dataDir,
                                            FileName = Path.GetFileName(file),
                                            Reason = $"RageMP data file contains {licenseCount} license references — multiple accounts/identities stored",
                                            Detail = $"File: {file}"
                                        });
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }, ct);

    private Task CheckRageMPCacheCleanerArtifacts(ScanContext ctx, CancellationToken ct, string userprofile, string desktop, string downloads, string documents, string temp) =>
        Task.Run(async () =>
        {
            var searchDirs = new[] { desktop, downloads, documents, temp };
            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var exe in BanEvasionExeNames)
                    {
                        var exePath = Path.Combine(dir, exe);
                        if (File.Exists(exePath))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Ban Evasion Executable",
                                Risk = RiskLevel.Critical,
                                Location = dir,
                                FileName = exe,
                                Reason = $"Known RageMP ban evasion/cleaner executable found: {exe}",
                                Detail = $"File: {exePath}"
                            });
                        }
                    }

                    foreach (var file in Directory.EnumerateFiles(dir, "*.bat", SearchOption.TopDirectoryOnly)
                        .Concat(Directory.EnumerateFiles(dir, "*.ps1", SearchOption.TopDirectoryOnly))
                        .Concat(Directory.EnumerateFiles(dir, "*.cmd", SearchOption.TopDirectoryOnly)))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            int hits = 0;
                            foreach (var kw in CleanerScriptKeywords)
                                if (content.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0) hits++;
                            if (hits >= 3)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "RageMP Cleaner/Reset Script",
                                    Risk = RiskLevel.Critical,
                                    Location = dir,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Script contains {hits} patterns for deleting RageMP data/cache to evade bans",
                                    Detail = $"File: {file}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }, ct);

    private Task CheckRageMPAccountSwitcherArtifacts(ScanContext ctx, CancellationToken ct, string userprofile, string desktop, string downloads, string temp) =>
        Task.Run(async () =>
        {
            var searchDirs = new[] { desktop, downloads, temp };
            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var exeName in AccountSwitcherNames)
                    {
                        var path = Path.Combine(dir, exeName);
                        if (File.Exists(path))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Account Switcher Tool",
                                Risk = RiskLevel.Critical,
                                Location = dir,
                                FileName = exeName,
                                Reason = $"Known account switcher tool found: {exeName} — used to switch Rockstar accounts for RageMP ban evasion",
                                Detail = $"File: {path}"
                            });
                        }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }

            var launcherDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Rockstar Games", "Launcher");
            if (Directory.Exists(launcherDir))
            {
                ctx.IncrementFiles();
                try
                {
                    var accountDirs = Directory.EnumerateDirectories(launcherDir, "*", SearchOption.TopDirectoryOnly).ToList();
                    if (accountDirs.Count > 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Multiple Rockstar Launcher Account Directories",
                            Risk = RiskLevel.High,
                            Location = launcherDir,
                            FileName = "Launcher",
                            Reason = $"Found {accountDirs.Count} account data directories in Rockstar Launcher — multiple Social Club accounts installed",
                            Detail = $"Directory: {launcherDir} | Multiple accounts suggest identity switching for ban evasion"
                        });
                    }
                }
                catch { }
            }
        }, ct);

    private Task CheckRageMPSteamAlternateAccountArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var steamConfigPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Steam", "config", "loginusers.vdf"),
                @"C:\Program Files\Steam\config\loginusers.vdf"
            };
            foreach (var configPath in steamConfigPaths)
            {
                if (!File.Exists(configPath)) continue;
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    var accountCount = 0;
                    var idx = 0;
                    while ((idx = content.IndexOf("\"PersonaName\"", idx, StringComparison.OrdinalIgnoreCase)) >= 0) { accountCount++; idx++; }
                    if (accountCount > 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Multiple Steam Accounts on RageMP Machine",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(configPath) ?? string.Empty,
                            FileName = "loginusers.vdf",
                            Reason = $"Steam config contains {accountCount} remembered accounts — multiple Steam accounts suggest ban evasion through account switching",
                            Detail = $"File: {configPath} | RageMP links to Rockstar/Steam identity — multiple accounts = multiple ban-evading identities"
                        });
                    }
                }
                catch { }
            }
        }, ct);

    private Task CheckRageMPIPRotationArtifacts(ScanContext ctx, CancellationToken ct, string userprofile, string desktop, string downloads, string documents) =>
        Task.Run(async () =>
        {
            var hostsPath = @"C:\Windows\System32\drivers\etc\hosts";
            if (File.Exists(hostsPath))
            {
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (var kw in IPRotationKeywords)
                    {
                        if (content.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0 &&
                            !content.Contains($"# {kw}", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Domain Redirect in Hosts File",
                                Risk = RiskLevel.Critical,
                                Location = @"C:\Windows\System32\drivers\etc",
                                FileName = "hosts",
                                Reason = $"hosts file contains RageMP-related domain '{kw}' — may redirect RageMP API/updater to bypass ban checks",
                                Detail = $"Hosts modification: {kw} | IP rotation or ban check bypass for RageMP"
                            });
                            break;
                        }
                    }
                }
                catch { }
            }

            var vpnConfigDirs = new[]
            {
                Path.Combine(userprofile, "OpenVPN", "config"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "OpenVPN Connect", "profiles")
            };
            foreach (var vpnDir in vpnConfigDirs)
            {
                if (!Directory.Exists(vpnDir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(vpnDir, "*.ovpn", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            foreach (var kw in IPRotationKeywords)
                            {
                                if (content.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "VPN Config Targeting RageMP Domain",
                                        Risk = RiskLevel.High,
                                        Location = vpnDir,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"VPN config file references RageMP domain '{kw}' — VPN used specifically for RageMP ban evasion",
                                        Detail = $"File: {file}"
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }, ct);

    private Task CheckRageMPHWIDSpoofArtifacts(ScanContext ctx, CancellationToken ct, string userprofile, string desktop, string downloads) =>
        Task.Run(async () =>
        {
            var hwidspoofDirs = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HWIDSpoofer"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Spoofer"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HWIDSpoofer"),
                Path.Combine(desktop, "Spoofer"),
                Path.Combine(downloads, "HWIDSpoofer")
            };
            foreach (var dir in hwidspoofDirs)
            {
                if (!Directory.Exists(dir)) continue;
                ctx.IncrementFiles();
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.log", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            foreach (var rmpKw in new[] { "ragemp", "rage", "RAGE Multiplayer", "GTA" })
                            {
                                if (content.IndexOf(rmpKw, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "HWID Spoofer Log References RageMP",
                                        Risk = RiskLevel.Critical,
                                        Location = dir,
                                        FileName = Path.GetFileName(file),
                                        Reason = "HWID spoofer log contains RageMP/GTA references — HWID was spoofed specifically for RageMP ban evasion",
                                        Detail = $"File: {file}"
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "HWID Spoofer Directory Found",
                        Risk = RiskLevel.Critical,
                        Location = Path.GetDirectoryName(dir) ?? dir,
                        FileName = Path.GetFileName(dir),
                        Reason = "HWID spoofer application directory found alongside RageMP installation",
                        Detail = $"Directory: {dir} | HWID spoofing combined with RageMP indicates hardware ban evasion"
                    });
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }, ct);

    private Task CheckRageMPLogManipulationArtifacts(ScanContext ctx, CancellationToken ct, string localappdata) =>
        Task.Run(async () =>
        {
            var logPaths = new[]
            {
                Path.Combine(localappdata, "RAGEMP", "logs"),
                Path.Combine(localappdata, "RAGE Multiplayer", "logs")
            };
            foreach (var logPath in logPaths)
            {
                if (!Directory.Exists(logPath)) continue;
                ctx.IncrementFiles();
                try
                {
                    var logFiles = Directory.EnumerateFiles(logPath, "*.log", SearchOption.TopDirectoryOnly).ToList();
                    logFiles.AddRange(Directory.EnumerateFiles(logPath, "*.txt", SearchOption.TopDirectoryOnly));
                    if (logFiles.Count == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Log Directory Empty",
                            Risk = RiskLevel.High,
                            Location = logPath,
                            FileName = "logs",
                            Reason = "RageMP log directory exists but contains no log files — logs were likely deleted to hide cheat/ban activity",
                            Detail = $"Directory: {logPath} | Empty log directory after installation indicates deliberate log wiping"
                        });
                    }
                    else if (logFiles.Count > 0)
                    {
                        var allRecent = true;
                        var cutoff = DateTime.UtcNow.AddHours(-1);
                        foreach (var lf in logFiles)
                        {
                            if (File.GetCreationTimeUtc(lf) < cutoff) { allRecent = false; break; }
                        }
                        if (allRecent && logFiles.Count > 1)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Logs All Created Very Recently",
                                Risk = RiskLevel.High,
                                Location = logPath,
                                FileName = "logs",
                                Reason = "All RageMP log files were created within the last hour — indicates log wipe and recreation to hide ban evidence",
                                Detail = $"Directory: {logPath} | {logFiles.Count} log files all have recent creation timestamps"
                            });
                        }
                    }
                }
                catch { }
            }
        }, ct);

    private Task CheckRageMPBanListArtifacts(ScanContext ctx, CancellationToken ct, string userprofile, string desktop, string downloads, string documents) =>
        Task.Run(async () =>
        {
            var searchDirs = new[] { desktop, downloads, documents, userprofile };
            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var banFileName in BanListFileNames)
                {
                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(dir, banFileName, SearchOption.AllDirectories))
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementFiles();
                            try
                            {
                                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                string content = await sr.ReadToEndAsync(ct);
                                if (content.Length > 50 &&
                                    (content.IndexOf("server", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     content.IndexOf("ban", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     content.IndexOf("kick", StringComparison.OrdinalIgnoreCase) >= 0))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "RageMP Ban List File",
                                        Risk = RiskLevel.Critical,
                                        Location = Path.GetDirectoryName(file) ?? dir,
                                        FileName = banFileName,
                                        Reason = "Local ban list file found — ban evaders track which servers banned them",
                                        Detail = $"File: {file} | Content confirms ban/server tracking data"
                                    });
                                }
                            }
                            catch { }
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { }
                }
            }
        }, ct);

    private Task CheckRageMPAntiBanScriptArtifacts(ScanContext ctx, CancellationToken ct, string localappdata, string userprofile, string downloads) =>
        Task.Run(async () =>
        {
            var rageMPClientPkgPath = Path.Combine(localappdata, "RAGEMP", "client_packages");
            var searchPaths = new[] { rageMPClientPkgPath, downloads };
            foreach (var searchPath in searchPaths)
            {
                if (!Directory.Exists(searchPath)) continue;
                foreach (var antiBanName in AntiBanScriptNames)
                {
                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(searchPath, antiBanName, SearchOption.AllDirectories))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Anti-Ban Script",
                                Risk = RiskLevel.Critical,
                                Location = Path.GetDirectoryName(file) ?? searchPath,
                                FileName = antiBanName,
                                Reason = $"Anti-ban script '{antiBanName}' found in RageMP directories",
                                Detail = $"File: {file} | Client-side anti-ban scripts attempt to prevent server from detecting cheat usage"
                            });
                        }
                    }
                    catch { }
                }

                try
                {
                    foreach (var file in Directory.EnumerateFiles(searchPath, "*.js", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            bool hasAntiBan = content.IndexOf("anti_ban", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                              content.IndexOf("antiban", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                              content.IndexOf("bypass_ban", StringComparison.OrdinalIgnoreCase) >= 0;
                            bool hasRageMP = content.IndexOf("mp.events", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                             content.IndexOf("mp.game", StringComparison.OrdinalIgnoreCase) >= 0;
                            if (hasAntiBan && hasRageMP)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "RageMP Anti-Ban Script Content",
                                    Risk = RiskLevel.Critical,
                                    Location = Path.GetDirectoryName(file) ?? searchPath,
                                    FileName = Path.GetFileName(file),
                                    Reason = "JavaScript file contains both RageMP API usage and anti-ban/bypass patterns",
                                    Detail = $"File: {file}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }, ct);

    private Task CheckRageMPProfileBackupArtifacts(ScanContext ctx, CancellationToken ct, string userprofile, string desktop, string downloads) =>
        Task.Run(async () =>
        {
            var backupNames = new[] { "RAGEMP_backup", "ragemp_backup", "rage_backup", "clean_ragemp", "ragemp_clean", "rage_clean", "ragemp_backup.zip", "clean_rage.zip" };
            var searchDirs = new[] { desktop, downloads, userprofile };
            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var backupName in backupNames)
                {
                    try
                    {
                        var candidates = Directory.EnumerateFileSystemEntries(dir, backupName, SearchOption.TopDirectoryOnly);
                        foreach (var candidate in candidates)
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Profile Backup",
                                Risk = RiskLevel.Critical,
                                Location = dir,
                                FileName = Path.GetFileName(candidate),
                                Reason = $"RageMP profile backup found: '{backupName}' — ban evaders back up clean profiles before cheating",
                                Detail = $"Path: {candidate}"
                            });
                        }
                    }
                    catch { }
                }
            }
        }, ct);

    private Task CheckRageMPBanEvasionRegistryArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var evasionKeys = new[]
            {
                @"Software\RageMPCleaner", @"Software\RageMPSpoofer", @"Software\RageMPAntiban",
                @"Software\RageMPReset", @"Software\RAGEMP_Bypass"
            };
            foreach (var keyPath in evasionKeys)
            {
                ctx.IncrementRegistryKeys();
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                    if (key != null)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "RageMP Ban Evasion Tool Registry Key",
                            Risk = RiskLevel.Critical,
                            Location = $"HKCU\\{keyPath}",
                            FileName = keyPath,
                            Reason = $"Registry key for RageMP ban evasion tool found: HKCU\\{keyPath}",
                            Detail = $"Key: HKCU\\{keyPath}"
                        });
                    }
                }
                catch { }
            }

            ctx.IncrementRegistryKeys();
            try
            {
                using var runKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
                if (runKey != null)
                {
                    foreach (var valueName in runKey.GetValueNames())
                    {
                        var val = runKey.GetValue(valueName)?.ToString() ?? string.Empty;
                        if (val.IndexOf("ragemp", StringComparison.OrdinalIgnoreCase) >= 0 &&
                            (val.IndexOf("clean", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             val.IndexOf("spoof", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             val.IndexOf("bypass", StringComparison.OrdinalIgnoreCase) >= 0))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Ban Evasion Tool in Autostart",
                                Risk = RiskLevel.Critical,
                                Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                                FileName = valueName,
                                Reason = $"RageMP ban evasion tool configured to run at startup: {valueName} = {val}",
                                Detail = $"Registry Run key: {valueName} | Value: {val}"
                            });
                        }
                    }
                }
            }
            catch { }

            ctx.IncrementRegistryKeys();
            try
            {
                using var mruKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs");
                if (mruKey != null)
                {
                    foreach (var subKeyName in mruKey.GetSubKeyNames())
                    {
                        if (subKeyName.Equals(".exe", StringComparison.OrdinalIgnoreCase) || subKeyName.Equals(".zip", StringComparison.OrdinalIgnoreCase))
                        {
                            using var subKey = mruKey.OpenSubKey(subKeyName);
                            if (subKey == null) continue;
                            foreach (var valName in subKey.GetValueNames())
                            {
                                var rawData = subKey.GetValue(valName);
                                if (rawData is byte[] bytes)
                                {
                                    var str = Encoding.Unicode.GetString(bytes);
                                    if (str.IndexOf("ragemp", StringComparison.OrdinalIgnoreCase) >= 0 &&
                                        (str.IndexOf("spoof", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                         str.IndexOf("clean", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                         str.IndexOf("ban", StringComparison.OrdinalIgnoreCase) >= 0))
                                    {
                                        ctx.AddFinding(new Finding
                                        {
                                            Module = Name,
                                            Title = "RageMP Ban Evasion File in Recent Docs MRU",
                                            Risk = RiskLevel.High,
                                            Location = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
                                            FileName = valName,
                                            Reason = "Recent Documents MRU contains RageMP ban evasion file reference",
                                            Detail = $"MRU entry: {str.Substring(0, Math.Min(100, str.Length))}"
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }, ct);

    private Task CheckRageMPPrefetchArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var prefetchDir = @"C:\Windows\Prefetch";
            if (!Directory.Exists(prefetchDir)) return;
            var patterns = new[] { "RAGEMP_CLEAN", "RAGE_SPOOF", "RAGE_BYPASS", "RAGEMP_ANTIBAN", "RAGEMP_HACK", "RAGE_INJECT" };
            try
            {
                foreach (var file in Directory.EnumerateFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var fname = Path.GetFileName(file).ToUpperInvariant();
                    foreach (var pattern in patterns)
                    {
                        if (fname.StartsWith(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.IncrementFiles();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RageMP Ban Evasion Tool Prefetch Entry",
                                Risk = RiskLevel.High,
                                Location = prefetchDir,
                                FileName = Path.GetFileName(file),
                                Reason = $"Windows Prefetch entry for RageMP ban evasion executable: {Path.GetFileName(file)}",
                                Detail = $"File: {file} | Prefetch proves the executable was run on this system"
                            });
                            break;
                        }
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }, ct);

    private Task CheckRageMPServerConnectionHistoryArtifacts(ScanContext ctx, CancellationToken ct, string localappdata) =>
        Task.Run(async () =>
        {
            var ragePaths = new[]
            {
                Path.Combine(localappdata, "RAGEMP"),
                Path.Combine(localappdata, "RAGE Multiplayer")
            };
            foreach (var ragePath in ragePaths)
            {
                if (!Directory.Exists(ragePath)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(ragePath, "*.json", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fname = Path.GetFileName(file).ToLowerInvariant();
                        if (!fname.Contains("server", StringComparison.OrdinalIgnoreCase) &&
                            !fname.Contains("history", StringComparison.OrdinalIgnoreCase) &&
                            !fname.Contains("connect", StringComparison.OrdinalIgnoreCase)) continue;
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            if ((content.IndexOf("banned", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 content.IndexOf("kicked", StringComparison.OrdinalIgnoreCase) >= 0) &&
                                content.Length > 50)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "RageMP Server History Contains Ban/Kick Records",
                                    Risk = RiskLevel.High,
                                    Location = Path.GetDirectoryName(file) ?? ragePath,
                                    FileName = Path.GetFileName(file),
                                    Reason = "RageMP server connection history contains ban/kick records — evidence of previous bans",
                                    Detail = $"File: {file}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }, ct);

    private Task CheckRageMPAutoJoinScriptArtifacts(ScanContext ctx, CancellationToken ct, string userprofile, string desktop, string downloads, string documents) =>
        Task.Run(async () =>
        {
            var searchDirs = new[] { desktop, downloads, documents };
            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(dir, "*.ahk", SearchOption.AllDirectories)
                        .Concat(Directory.EnumerateFiles(dir, "*.bat", SearchOption.TopDirectoryOnly))
                        .Concat(Directory.EnumerateFiles(dir, "*.ps1", SearchOption.TopDirectoryOnly)))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            bool hasRageMP = content.IndexOf("ragemp", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                             content.IndexOf("RAGE Multiplayer", StringComparison.OrdinalIgnoreCase) >= 0;
                            bool hasJoin = content.IndexOf("connect", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                           content.IndexOf("join", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                           content.IndexOf("launch", StringComparison.OrdinalIgnoreCase) >= 0;
                            bool hasReset = content.IndexOf("reset", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                            content.IndexOf("clean", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                            content.IndexOf("spoof", StringComparison.OrdinalIgnoreCase) >= 0;
                            if (hasRageMP && hasJoin && hasReset)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "RageMP Auto-Join After Reset Script",
                                    Risk = RiskLevel.Critical,
                                    Location = dir,
                                    FileName = Path.GetFileName(file),
                                    Reason = "Script resets/cleans RageMP data then auto-joins server — classic ban evasion automation",
                                    Detail = $"File: {file}"
                                });
                            }
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }, ct);

    private Task CheckRageMPSocialClubManipulationArtifacts(ScanContext ctx, CancellationToken ct, string localappdata, string userprofile) =>
        Task.Run(async () =>
        {
            var socialClubPaths = new[]
            {
                Path.Combine(localappdata, "Rockstar Games", "Social Club"),
                Path.Combine(localappdata, "Rockstar Games", "Launcher", "data")
            };
            foreach (var scPath in socialClubPaths)
            {
                if (!Directory.Exists(scPath)) continue;
                ctx.IncrementFiles();
                try
                {
                    var profileFiles = Directory.EnumerateFiles(scPath, "*.json", SearchOption.AllDirectories).ToList();
                    profileFiles.AddRange(Directory.EnumerateFiles(scPath, "*.dat", SearchOption.AllDirectories));
                    if (profileFiles.Count == 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Rockstar Social Club Data Directory Empty",
                            Risk = RiskLevel.High,
                            Location = scPath,
                            FileName = "Social Club",
                            Reason = "Rockstar Social Club data directory is empty — data deleted to reset identity for RageMP ban evasion",
                            Detail = $"Directory: {scPath}"
                        });
                    }
                }
                catch { }
            }
        }, ct);

    private Task CheckRageMPVPNSpecificArtifacts(ScanContext ctx, CancellationToken ct, string userprofile, string downloads, string documents) =>
        Task.Run(async () =>
        {
            var wgConfigDirs = new[] { Path.Combine(userprofile, "AppData", "Roaming", "WireGuard") };
            foreach (var wgDir in wgConfigDirs)
            {
                if (!Directory.Exists(wgDir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(wgDir, "*.conf", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            foreach (var kw in new[] { "ragemp", "rage.mp", "gta" })
                            {
                                if (content.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "WireGuard Config Targeting RageMP",
                                        Risk = RiskLevel.High,
                                        Location = wgDir,
                                        FileName = Path.GetFileName(file),
                                        Reason = $"WireGuard VPN config references RageMP '{kw}' — VPN configured specifically for RageMP ban evasion",
                                        Detail = $"File: {file}"
                                    });
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }, ct);

    private Task CheckRageMPBanDatabaseQueryArtifacts(ScanContext ctx, CancellationToken ct, string localappdata) =>
        Task.Run(async () =>
        {
            var banCheckDomains = new[] { "ban.rage.mp", "bans.rage.mp", "rage-mp.com/ban", "forum.rage.mp/bans", "rage.mp/banned" };
            var browserHistoryPaths = new[]
            {
                Path.Combine(localappdata, "Google", "Chrome", "User Data", "Default", "History"),
                Path.Combine(localappdata, "Microsoft", "Edge", "User Data", "Default", "History"),
                Path.Combine(localappdata, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History")
            };
            foreach (var histPath in browserHistoryPaths)
            {
                if (!File.Exists(histPath)) continue;
                ctx.IncrementFiles();
                try
                {
                    var tempPath = Path.Combine(Path.GetTempPath(), $"zt_hist_{Guid.NewGuid():N}.db");
                    try
                    {
                        File.Copy(histPath, tempPath, true);
                        using var fs = new FileStream(tempPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                        string content = await sr.ReadToEndAsync(ct);
                        foreach (var domain in banCheckDomains)
                        {
                            if (content.IndexOf(domain, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "RageMP Ban Database Lookup in Browser History",
                                    Risk = RiskLevel.High,
                                    Location = Path.GetDirectoryName(histPath) ?? localappdata,
                                    FileName = Path.GetFileName(histPath),
                                    Reason = $"Browser history shows visit to RageMP ban database/forum: {domain}",
                                    Detail = $"History: {histPath} | Checking ban status before reconnecting indicates awareness of ban and evasion attempt"
                                });
                            }
                        }
                    }
                    finally { try { File.Delete(tempPath); } catch { } }
                }
                catch (OperationCanceledException) { throw; }
                catch { }
            }
        }, ct);

    private Task CheckRageMPTokenRotationArtifacts(ScanContext ctx, CancellationToken ct, string appdata, string localappdata, string userprofile) =>
        Task.Run(async () =>
        {
            var tokenFilePatterns = new[] { "token.json", "auth.json", "auth_token.txt", "ragemp_token.txt", "rage_token.json" };
            var searchPaths = new[]
            {
                Path.Combine(localappdata, "RAGEMP"),
                Path.Combine(appdata, "RAGEMP"),
                Path.Combine(userprofile, "Downloads"),
                Path.Combine(userprofile, "Desktop")
            };
            foreach (var searchPath in searchPaths)
            {
                if (!Directory.Exists(searchPath)) continue;
                var tokensFound = new List<string>();
                foreach (var pattern in tokenFilePatterns)
                {
                    try
                    {
                        foreach (var file in Directory.EnumerateFiles(searchPath, pattern, SearchOption.AllDirectories))
                        {
                            ct.ThrowIfCancellationRequested();
                            tokensFound.Add(file);
                            ctx.IncrementFiles();
                        }
                    }
                    catch { }
                }
                if (tokensFound.Count >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Multiple RageMP Auth Token Files",
                        Risk = RiskLevel.Critical,
                        Location = searchPath,
                        FileName = "token files",
                        Reason = $"Found {tokensFound.Count} auth/token files in RageMP directories — multiple tokens indicate identity rotation for ban evasion",
                        Detail = $"Directory: {searchPath} | Files: {string.Join(", ", tokensFound.Select(Path.GetFileName).Take(5))}"
                    });
                }
            }
        }, ct);
}
