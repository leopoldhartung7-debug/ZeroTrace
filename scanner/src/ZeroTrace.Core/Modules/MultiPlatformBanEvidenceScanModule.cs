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

public sealed class MultiPlatformBanEvidenceScanModule : IScanModule
{
    public string Name => "Multi-Platform Ban Evidence Forensic Scan (FiveM/RageMP/alt:V)";
    public double Weight => 4.0;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] BanLogKeywords =
    {
        "you have been banned", "you are banned", "ban reason",
        "ban duration", "banned for cheating", "banned for hacking",
        "banned for modding", "banned for exploiting", "banned permanently",
        "permanent ban", "global ban", "anticheat ban",
        "screamingbedwars ban", "easy anti-cheat ban", "eac ban",
        "battleye ban", "fairfight ban", "ricochet ban",
        "easyanticheat: ban", "battleye: ban", "vanguard: ban",
        "vac: ban", "vacban", "vac ban",
        "fivem ban", "ragemp ban", "altv ban", "alt:v ban", "alt v ban",
        "kicked for cheat", "kicked for hack", "kicked for mod",
        "kicked for exploit", "kicked for ban evasion",
        "license:bad", "license bad", "license revoked",
        "license blacklisted", "license banned", "license_ban",
        "license rejected", "hwid banned", "hwid blacklisted",
        "ip banned", "ip blacklisted", "ip blocked",
        "discord id banned", "social club banned", "rockstar banned",
        "screenshot detected", "detection: cheat", "detection: hack",
        "client tampering", "client modification", "client integrity",
        "memory tampering detected", "memory write detected",
        "module injection detected", "unauthorized module",
        "unauthorized dll", "unauthorized hook", "client crash banned",
        "kick: anticheat", "kick: detection", "kick: hack",
        "kick: cheat", "kick: tampering", "kick: integrity",
        "banlist updated", "banlist entry", "ban appeal",
        "ban evasion detected", "ban evasion attempt",
    };

    private static readonly string[] BanFileNames =
    {
        "ban.txt", "bans.txt", "banlist.txt", "banned.txt",
        "ban.json", "bans.json", "banlist.json", "banned.json",
        "ban.log", "bans.log", "banlist.log", "banned.log",
        "ban_evidence.txt", "ban_evidence.json", "ban_evidence.log",
        "ban_appeal.txt", "ban_appeal.json", "ban_appeal.log",
        "ban_reason.txt", "ban_reason.json", "ban_reason.log",
        "anticheat_log.txt", "anticheat_log.json", "anticheat_log.log",
        "ac_log.txt", "ac_log.json", "ac_log.log",
        "detection_log.txt", "detection_log.json", "detection_log.log",
        "tampering_log.txt", "tampering_log.json", "tampering_log.log",
        "screenshot_log.txt", "screenshot_log.json", "screenshot.png",
        "screenshot.jpg", "screenshot_evidence.png",
        "detection_evidence.png", "tampering_evidence.png",
        "ban_screenshot.png", "ban_screenshot.jpg",
        "evidence.zip", "evidence.rar", "evidence.7z",
        "anticheat_dump.txt", "anticheat_dump.json", "anticheat_dump.bin",
        "ac_dump.txt", "ac_dump.json", "ac_dump.bin",
    };

    private static readonly string[] BanReceiptLogPatterns =
    {
        "your ban id", "your case id", "case id:", "ban id:",
        "ticket id:", "appeal id:", "report id:",
        "banned by anticheat", "banned by admin", "banned by moderator",
        "banned by system", "banned automatically", "auto-banned",
        "kicked by anticheat", "kicked by admin", "kicked by system",
        "kicked automatically", "auto-kicked", "anticheat triggered",
        "anticheat alert", "anticheat detection",
        "your license was banned", "your hwid was banned",
        "your ip was banned", "your social club was banned",
        "your rockstar was banned", "your discord was banned",
        "you cannot rejoin", "you cannot join", "join rejected",
        "connection rejected", "connection denied",
    };

    private static readonly string[] FiveMBanArtifactPaths =
    {
        @"FiveM\FiveM.app\logs",
        @"FiveM\FiveM.app\data",
        @"FiveM\FiveM.app",
        @"CitizenFX\logs",
        @"CitizenFX",
    };

    private static readonly string[] RageMPBanArtifactPaths =
    {
        @"RAGEMP\logs",
        @"RAGEMP\client_resources",
        @"RAGEMP",
        @"RAGE Multiplayer\logs",
        @"RAGE Multiplayer\client_resources",
        @"RAGE Multiplayer",
    };

    private static readonly string[] AltVBanArtifactPaths =
    {
        @"altv\logs",
        @"altv\cache",
        @"altv",
        @"altV\logs",
        @"altV\cache",
        @"altV",
        @"alt-V\logs",
        @"alt-V\cache",
        @"alt-V",
    };

    private static readonly string[] EacBanRegistryKeys =
    {
        @"SOFTWARE\EasyAntiCheat",
        @"SOFTWARE\WOW6432Node\EasyAntiCheat",
        @"SOFTWARE\Classes\EasyAntiCheat",
    };

    private static readonly string[] BeBanRegistryKeys =
    {
        @"SOFTWARE\BattlEye",
        @"SOFTWARE\WOW6432Node\BattlEye",
        @"SOFTWARE\Classes\BattlEye",
    };

    private static readonly string[] BanRelatedRegistryValues =
    {
        "BanID", "CaseID", "BanReason", "BanDate", "BannedHwid",
        "BannedLicense", "BannedIP", "BannedDiscordID",
        "BannedSocialClub", "BannedRockstarID",
    };

    public Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        return Task.WhenAll(
            CheckFiveMBanLogs(ctx, ct),
            CheckRageMPBanLogs(ctx, ct),
            CheckAltVBanLogs(ctx, ct),
            CheckBanFileNames(ctx, ct),
            CheckBanReceiptLogs(ctx, ct),
            CheckEacBanRegistry(ctx, ct),
            CheckBeBanRegistry(ctx, ct),
            CheckScreenshotEvidence(ctx, ct),
            CheckBanArchives(ctx, ct),
            CheckBrowserHistoryForBanAppeals(ctx, ct),
            CheckDiscordBanMessages(ctx, ct),
            CheckHostsFileForServerBlocking(ctx, ct)
        );
    }

    private static IEnumerable<string> ExpandPaths(string[] relPaths)
    {
        var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
        var appData = Environment.GetEnvironmentVariable("APPDATA");
        var dirs = new List<string>();

        foreach (var rel in relPaths)
        {
            if (!string.IsNullOrEmpty(localAppData)) dirs.Add(Path.Combine(localAppData, rel));
            if (!string.IsNullOrEmpty(appData)) dirs.Add(Path.Combine(appData, rel));
        }

        return dirs.Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private async Task ScanForBanKeywordsInDir(ScanContext ctx, CancellationToken ct,
        string dir, string platform)
    {
        if (!Directory.Exists(dir)) return;
        string[] exts = { ".log", ".txt", ".json", ".cfg" };

        foreach (var ext in exts)
        {
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(dir, "*" + ext, SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

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
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var kw in BanLogKeywords)
                {
                    if (!content.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"{platform} Ban Evidence in Log",
                        Risk = RiskLevel.Critical,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"{platform} log file contains ban/kick evidence: '{kw}'",
                        Detail = "Client log records a previous ban or kick — strong forensic indicator of prior cheating.",
                    });
                    break;
                }
            }
        }
    }

    private Task CheckFiveMBanLogs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            foreach (var dir in ExpandPaths(FiveMBanArtifactPaths))
            {
                ct.ThrowIfCancellationRequested();
                await ScanForBanKeywordsInDir(ctx, ct, dir, "FiveM");
            }
        }, ct);

    private Task CheckRageMPBanLogs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            foreach (var dir in ExpandPaths(RageMPBanArtifactPaths))
            {
                ct.ThrowIfCancellationRequested();
                await ScanForBanKeywordsInDir(ctx, ct, dir, "RageMP");
            }
        }, ct);

    private Task CheckAltVBanLogs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            foreach (var dir in ExpandPaths(AltVBanArtifactPaths))
            {
                ct.ThrowIfCancellationRequested();
                await ScanForBanKeywordsInDir(ctx, ct, dir, "alt:V");
            }
        }, ct);

    private Task CheckBanFileNames(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var allPaths = ExpandPaths(FiveMBanArtifactPaths)
                .Concat(ExpandPaths(RageMPBanArtifactPaths))
                .Concat(ExpandPaths(AltVBanArtifactPaths));

            foreach (var dir in allPaths)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string name = Path.GetFileName(file);
                    foreach (var ban in BanFileNames)
                    {
                        if (!name.Equals(ban, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Ban Evidence File",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = name,
                            Reason = $"File named like ban evidence record: '{name}'",
                            Detail = "Filename matches known ban-receipt / detection-log naming convention.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckBanReceiptLogs(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var allPaths = ExpandPaths(FiveMBanArtifactPaths)
                .Concat(ExpandPaths(RageMPBanArtifactPaths))
                .Concat(ExpandPaths(AltVBanArtifactPaths));

            string[] exts = { ".log", ".txt", ".json" };

            foreach (var dir in allPaths)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                foreach (var ext in exts)
                {
                    IEnumerable<string> files;
                    try { files = Directory.EnumerateFiles(dir, "*" + ext, SearchOption.AllDirectories); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

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
                        catch (IOException) { continue; }
                        catch (UnauthorizedAccessException) { continue; }

                        foreach (var pat in BanReceiptLogPatterns)
                        {
                            if (!content.Contains(pat, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Ban/Kick Receipt in Log",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Log contains ban/kick receipt pattern: '{pat}'",
                                Detail = "Log entry suggests user received an explicit ban or kick notification.",
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    private Task CheckEacBanRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var keyPath in EacBanRegistryKeys)
            {
                foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    ct.ThrowIfCancellationRequested();

                    RegistryKey? key;
                    try { key = hive.OpenSubKey(keyPath); }
                    catch (System.Security.SecurityException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }
                    if (key == null) continue;

                    using (key)
                    {
                        string[] vals;
                        try { vals = key.GetValueNames(); }
                        catch (System.Security.SecurityException) { continue; }

                        foreach (var v in vals)
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();

                            if (!BanRelatedRegistryValues.Any(b =>
                                v.Contains(b, StringComparison.OrdinalIgnoreCase))) continue;

                            object? data;
                            try { data = key.GetValue(v); }
                            catch (System.Security.SecurityException) { continue; }

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "EasyAntiCheat Ban-Related Registry Value",
                                Risk = RiskLevel.Critical,
                                Location = $"{hive.Name}\\{keyPath}\\{v}",
                                Reason = $"EAC registry contains ban-related value: '{v}'",
                                Detail = $"Value data: {data}",
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckBeBanRegistry(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            foreach (var keyPath in BeBanRegistryKeys)
            {
                foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
                {
                    ct.ThrowIfCancellationRequested();

                    RegistryKey? key;
                    try { key = hive.OpenSubKey(keyPath); }
                    catch (System.Security.SecurityException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }
                    if (key == null) continue;

                    using (key)
                    {
                        string[] vals;
                        try { vals = key.GetValueNames(); }
                        catch (System.Security.SecurityException) { continue; }

                        foreach (var v in vals)
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();

                            if (!BanRelatedRegistryValues.Any(b =>
                                v.Contains(b, StringComparison.OrdinalIgnoreCase))) continue;

                            object? data;
                            try { data = key.GetValue(v); }
                            catch (System.Security.SecurityException) { continue; }

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "BattlEye Ban-Related Registry Value",
                                Risk = RiskLevel.Critical,
                                Location = $"{hive.Name}\\{keyPath}\\{v}",
                                Reason = $"BattlEye registry contains ban-related value: '{v}'",
                                Detail = $"Value data: {data}",
                            });
                        }
                    }
                }
            }
        }, ct);

    private Task CheckScreenshotEvidence(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");

            var dirs = new List<string>();
            if (!string.IsNullOrEmpty(localAppData))
            {
                dirs.Add(Path.Combine(localAppData, "FiveM"));
                dirs.Add(Path.Combine(localAppData, "RAGEMP"));
                dirs.Add(Path.Combine(localAppData, "altv"));
            }
            if (!string.IsNullOrEmpty(appData))
            {
                dirs.Add(Path.Combine(appData, "CitizenFX"));
            }
            if (!string.IsNullOrEmpty(userProfile))
            {
                dirs.Add(Path.Combine(userProfile, "Pictures"));
                dirs.Add(Path.Combine(userProfile, "Documents"));
            }

            string[] exts = { ".png", ".jpg", ".jpeg", ".bmp" };
            string[] keywords =
            {
                "ban", "banned", "anticheat", "detection",
                "tampering", "evidence", "kick", "screenshot",
            };

            foreach (var dir in dirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                foreach (var ext in exts)
                {
                    IEnumerable<string> files;
                    try { files = Directory.EnumerateFiles(dir, "*" + ext, SearchOption.AllDirectories); }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var file in files)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();

                        string fileName = Path.GetFileName(file);
                        foreach (var kw in keywords)
                        {
                            if (!fileName.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Ban Screenshot Evidence Artifact",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"Screenshot/image filename matches ban evidence keyword: '{kw}'",
                                Detail = "Image saved with ban/detection-related name — common for anti-cheat capture or user-saved appeal evidence.",
                            });
                            break;
                        }
                    }
                }
            }
        }, ct);

    private Task CheckBanArchives(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var userProfile = Environment.GetEnvironmentVariable("USERPROFILE");
            if (string.IsNullOrEmpty(userProfile)) return;

            string[] dirs =
            {
                Path.Combine(userProfile, "Downloads"),
                Path.Combine(userProfile, "Desktop"),
                Path.Combine(userProfile, "Documents"),
            };

            string[] exts = { ".zip", ".rar", ".7z", ".gz", ".cab", ".tar", ".iso" };
            string[] patterns =
            {
                "ban_evidence", "ban-evidence", "ban appeal",
                "ban_appeal", "ban-appeal", "anticheat_dump",
                "anticheat-dump", "ac_dump", "detection_evidence",
                "detection-evidence", "screenshot_evidence",
                "screenshot-evidence", "tampering_evidence",
                "tampering-evidence",
            };

            foreach (var dir in dirs)
            {
                if (!Directory.Exists(dir)) continue;
                ct.ThrowIfCancellationRequested();

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    string ext = Path.GetExtension(file);
                    if (!exts.Any(e => ext.Equals(e, StringComparison.OrdinalIgnoreCase))) continue;

                    string name = Path.GetFileName(file);
                    foreach (var pat in patterns)
                    {
                        if (!name.Contains(pat, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Ban Evidence Archive",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = name,
                            Reason = $"Archive named for ban/anticheat evidence: '{pat}'",
                            Detail = "User likely saved a ban evidence package for appeal or for distribution.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckBrowserHistoryForBanAppeals(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            if (string.IsNullOrEmpty(localAppData)) return;

            string[] history =
            {
                Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "History"),
                Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "History"),
                Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History"),
                Path.Combine(localAppData, "Vivaldi", "User Data", "Default", "History"),
                Path.Combine(localAppData, "Opera Software", "Opera Stable", "History"),
            };

            string[] appealPatterns =
            {
                "ban-appeal", "ban_appeal", "ban appeal",
                "unban-appeal", "unban_appeal", "unban appeal",
                "anticheat-appeal", "anticheat appeal",
                "ban evasion", "ban-evasion", "ban_evasion",
                "appeal.easyanticheat.net", "appeal.battleye.com",
                "support.fivem.net", "ragemp.com/support",
                "altv.mp/support", "report.eac", "report.battleye",
                "tickets.fivem", "tickets.ragemp", "tickets.altv",
            };

            foreach (var path in history)
            {
                if (!File.Exists(path)) continue;
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();

                string content;
                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var pat in appealPatterns)
                {
                    if (!content.Contains(pat, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Ban Appeal URL in Browser History",
                        Risk = RiskLevel.High,
                        Location = path,
                        FileName = Path.GetFileName(path),
                        Reason = $"Browser history contains ban appeal/support URL: '{pat}'",
                        Detail = "User visited a ban appeal or anti-cheat support page — typical post-ban activity.",
                    });
                    break;
                }
            }
        }, ct);

    private Task CheckDiscordBanMessages(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var appData = Environment.GetEnvironmentVariable("APPDATA");
            if (string.IsNullOrEmpty(appData)) return;

            string[] discords =
            {
                Path.Combine(appData, "discord"),
                Path.Combine(appData, "discordptb"),
                Path.Combine(appData, "discordcanary"),
            };

            string[] banDiscordPatterns =
            {
                "i got banned", "i was banned", "got banned for", "got a ban",
                "banned for cheating", "banned for hacking", "banned for modding",
                "ban appeal", "unban appeal", "anticheat banned",
                "eac banned", "battleye banned", "fivem banned",
                "ragemp banned", "altv banned", "vac banned",
                "global ban", "permanent ban", "perm ban",
            };

            foreach (var d in discords)
            {
                if (!Directory.Exists(d)) continue;
                ct.ThrowIfCancellationRequested();

                string cache = Path.Combine(d, "Cache");
                if (!Directory.Exists(cache)) continue;

                IEnumerable<string> files;
                try { files = Directory.EnumerateFiles(cache, "*", SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

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
                    catch (IOException) { continue; }
                    catch (UnauthorizedAccessException) { continue; }

                    foreach (var pat in banDiscordPatterns)
                    {
                        if (!content.Contains(pat, StringComparison.OrdinalIgnoreCase)) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Ban-Related Discord Message",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Discord cache contains ban-related message pattern: '{pat}'",
                            Detail = "User communicated about a previous ban via Discord — corroborating evidence of prior cheating.",
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckHostsFileForServerBlocking(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            const string hostsPath = @"C:\Windows\System32\drivers\etc\hosts";
            if (!File.Exists(hostsPath)) return;
            ct.ThrowIfCancellationRequested();
            ctx.IncrementFiles();

            string content;
            try
            {
                using var fs = new FileStream(hostsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                content = await sr.ReadToEndAsync(ct);
            }
            catch (IOException) { return; }
            catch (UnauthorizedAccessException) { return; }

            string[] suspicious =
            {
                "easyanticheat.net", "easyanticheat", "battleye.com",
                "vac.steampowered.com", "ricochet.activision",
                "vanguard.riotgames.com", "fairfight.gg",
                "fivem.net", "cfx.re", "ragemp.com", "altv.mp",
                "rage.mp",
            };

            foreach (var line in content.Split('\n'))
            {
                string trimmed = line.Trim();
                if (trimmed.StartsWith("#")) continue;
                if (string.IsNullOrWhiteSpace(trimmed)) continue;

                bool blockerLine = trimmed.StartsWith("0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
                                   trimmed.StartsWith("127.0.0.1", StringComparison.OrdinalIgnoreCase);
                if (!blockerLine) continue;

                foreach (var s in suspicious)
                {
                    if (!trimmed.Contains(s, StringComparison.OrdinalIgnoreCase)) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Hosts File Blocks Anti-Cheat or Multiplayer Service",
                        Risk = RiskLevel.Critical,
                        Location = hostsPath,
                        FileName = "hosts",
                        Reason = $"Hosts file blocks anti-cheat / multiplayer service domain: '{s}'",
                        Detail = $"Line: {trimmed}\n\nBlocking these endpoints disables telemetry/ban delivery — common ban evasion technique.",
                    });
                    break;
                }
            }
        }, ct);
}
