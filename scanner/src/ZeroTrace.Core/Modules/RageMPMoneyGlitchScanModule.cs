using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

public sealed class RageMPMoneyGlitchScanModule : IScanModule
{
    public string Name => "RageMP Economy Glitch & Money Cheat Forensic Scan";
    public double Weight => 3.9;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] MoneyCheatExecutables =
    {
        "ragemp_money.exe",
        "ragemp_cash.exe",
        "ragemp_bank.exe",
        "ragemp_money_hack.exe",
        "ragemp_economy.exe",
        "ragemp_cash_drop.exe",
        "ragemp_money_drop.exe",
        "gta5_ragemp_money.exe",
        "ragemp_glitch.exe",
        "ragemp_economy_hack.exe",
        "ragemp_money_cheat.exe",
        "ragemp_cash_hack.exe",
        "ragemp_bank_hack.exe",
        "ragemp_wallet.exe",
        "ragemp_currency.exe",
        "gta_ragemp_economy.exe",
        "ragemp_money_tool.exe",
        "ragemp_economy_glitch.exe",
        "ragemp_moneymod.exe",
        "ragemp_cashmod.exe",
        "ragemp_bank_glitch.exe",
        "ragemp_money_inject.exe",
        "ragemp_cash_inject.exe",
        "ragemp_economy_inject.exe",
        "ragemp_balance_hack.exe",
        "ragemp_balance_cheat.exe",
        "ragemp_money_dropper.exe",
    };

    private static readonly string[] EconomyExploitDlls =
    {
        "ragemp_money.dll",
        "ragemp_economy.dll",
        "money_exploit_ragemp.dll",
        "ragemp_bank_exploit.dll",
        "ragemp_cash_exploit.dll",
        "economy_hook_ragemp.dll",
        "ragemp_economy_hook.dll",
        "ragemp_transaction_hook.dll",
        "ragemp_money_hook.dll",
        "ragemp_cash_hook.dll",
        "ragemp_balance_hook.dll",
        "ragemp_inject_economy.dll",
        "money_glitch_ragemp.dll",
        "economy_glitch_ragemp.dll",
        "ragemp_wallet_exploit.dll",
    };

    private static readonly string[] EconomyPackageFiles =
    {
        "ragemp_packages_money.js",
        "money_drop_package.js",
        "economy_exploit.js",
        "ragemp_bank.js",
        "ragemp_money_package.js",
        "ragemp_cash_package.js",
        "ragemp_economy_package.js",
        "money_glitch_package.js",
        "economy_glitch.js",
        "ragemp_bank_package.js",
        "money_inject.js",
        "economy_inject.js",
        "cash_drop.js",
        "money_drop.js",
        "ragemp_wallet.js",
        "ragemp_balance.js",
        "ragemp_currency.js",
        "bank_exploit_package.js",
        "economy_exploit_package.js",
    };

    private static readonly string[] JsEconomyExploitPatterns =
    {
        "mp.events.add('economy'",
        "mp.events.add(\"economy\"",
        "mp.players.forEach",
        "player.call('addMoney'",
        "player.call(\"addMoney\"",
        "player.call('setBank'",
        "player.call(\"setBank\"",
        "playerMoney",
        "setAccountMoney",
        "addBankBalance",
        "player.call('giveCash'",
        "player.call(\"giveCash\"",
        "player.call('setMoney'",
        "player.call(\"setMoney\"",
        "mp.events.addCommand('givemoney'",
        "mp.events.addCommand(\"givemoney\"",
        "player.setVariable('money'",
        "player.setVariable(\"money\"",
        "player.setVariable('bank'",
        "player.setVariable(\"bank\"",
        "player.getVariable('money'",
        "player.getVariable(\"money\"",
        "mp.players.at(",
        "addPlayerMoney(",
        "setPlayerMoney(",
        "givePlayerMoney(",
        "economy.addMoney(",
        "economy.setMoney(",
        "bank.addBalance(",
        "bank.setBalance(",
        "addCash(",
        "setCash(",
        "giveCash(",
    };

    private static readonly string[] EconomyConfigArtifacts =
    {
        "ragemp_money_config.json",
        "economy_hack_config.txt",
        "ragemp_economy_config.json",
        "ragemp_cash_config.json",
        "ragemp_bank_config.json",
        "ragemp_glitch_config.txt",
        "ragemp_money_settings.json",
        "economy_exploit_config.json",
        "money_glitch_config.txt",
        "ragemp_economy_settings.cfg",
        "ragemp_money_cheat_config.json",
        "ragemp_balance_config.json",
        "economy_hack_settings.txt",
    };

    private static readonly string[] EconomyCheatLogFiles =
    {
        "ragemp_money_log.txt",
        "ragemp_economy_log.txt",
        "ragemp_bank_log.txt",
        "ragemp_cash_log.txt",
        "economy_exploit.log",
        "money_glitch.log",
        "ragemp_transaction.log",
        "ragemp_economy_exploit.log",
        "ragemp_money_exploit.log",
        "economy_hack.log",
        "ragemp_balance_log.txt",
        "ragemp_wallet_log.txt",
        "money_cheat_ragemp.log",
        "ragemp_economy_cheat.log",
    };

    private static readonly string[] ServerLogExploitSignatures =
    {
        "economy exploit",
        "money exploit",
        "money glitch",
        "economy glitch",
        "negative balance",
        "balance overflow",
        "impossible transfer",
        "invalid money",
        "balance manipulation",
        "money hack",
        "economy hack",
        "cash hack",
        "money inject",
        "economy inject",
        "illegal economy",
        "illegal money",
        "money dupe",
        "economy dupe",
        "cash dupe",
        "duplicate money",
        "balance inject",
        "bank exploit",
        "bank overflow",
        "wallet exploit",
        "currency exploit",
        "givemoney abuse",
        "setmoney abuse",
        "addmoney abuse",
        "transaction exploit",
        "transaction hack",
        "balance cheat",
        "economy bypass",
        "money bypass",
    };

    private static readonly string[] MuiCacheCheatKeywords =
    {
        "ragemp_money", "ragemp_cash", "ragemp_bank", "ragemp_economy",
        "ragemp_glitch", "money_hack_ragemp", "economy_hack_ragemp",
        "ragemp_money_hack", "ragemp_cash_drop", "ragemp_money_drop",
        "gta5_ragemp_money", "money_exploit_ragemp", "ragemp_economy_hack",
        "ragemp_bank_hack", "ragemp_balance_hack", "ragemp_money_cheat",
    };

    private static readonly string[] UserAssistCheatKeywords =
    {
        "ragemp_money", "ragemp_cash", "ragemp_bank", "ragemp_economy",
        "ragemp_glitch", "money_hack_ragemp", "economy_hack_ragemp",
        "ragemp_money_hack", "ragemp_cash_drop", "ragemp_money_drop",
        "gta5_ragemp_money", "ragemp_economy_hack", "ragemp_bank_hack",
        "ragemp_balance_hack", "ragemp_money_cheat", "ragemp_cash_hack",
    };

    private static readonly string[] RunKeyCheatNames =
    {
        "ragemp_money", "ragemp_cash", "ragemp_bank", "ragemp_economy",
        "ragemp_glitch", "ragemp_money_hack", "ragemp_cash_drop",
        "ragemp_money_drop", "gta5_ragemp_money", "ragemp_economy_hack",
        "ragemp_bank_hack", "ragemp_balance_hack", "ragemp_money_cheat",
        "money_exploit_ragemp", "economy_exploit_ragemp",
    };

    private static readonly string[] PrefetchCheatNames =
    {
        "RAGEMP_MONEY", "RAGEMP_CASH", "RAGEMP_BANK", "RAGEMP_ECONOMY",
        "RAGEMP_GLITCH", "RAGEMP_MONEY_HACK", "RAGEMP_CASH_DROP",
        "RAGEMP_MONEY_DROP", "GTA5_RAGEMP_MONEY", "RAGEMP_ECONOMY_HACK",
        "RAGEMP_BANK_HACK", "RAGEMP_BALANCE_HACK", "RAGEMP_MONEY_CHEAT",
    };

    private static readonly string[] AmcacheCheatKeywords =
    {
        "ragemp_money", "ragemp_cash", "ragemp_bank", "ragemp_economy",
        "ragemp_glitch", "ragemp_money_hack", "ragemp_economy_hack",
        "ragemp_bank_hack", "gta5_ragemp_money", "money_exploit_ragemp",
        "ragemp_money_drop", "ragemp_cash_drop", "ragemp_balance_hack",
    };

    private static readonly string[] FirewallLogExploitDomainFragments =
    {
        "ragemp-money",
        "ragemp-cheat",
        "ragemp-hack",
        "ragemp-economy",
        "ragemp-glitch",
        "ragemp_money",
        "economy-exploit",
        "money-exploit",
        "money-glitch",
        "economy-glitch",
        "ragemp-exploit",
        "economy-hack",
        "bank-exploit",
        "money-inject",
        "ragemp-cash",
    };

    private static readonly string[] ProxyConfigExploitKeywords =
    {
        "ragemp-money",
        "ragemp-cheat",
        "economy-exploit",
        "money-glitch",
        "ragemp-economy",
        "economy-hack",
        "money-inject",
        "bank-exploit",
        "ragemp-exploit",
        "money-exploit",
    };

    private static readonly string[] DownloadCheatFileKeywords =
    {
        "ragemp_money", "ragemp_cash", "ragemp_bank", "ragemp_economy",
        "ragemp_glitch", "ragemp_money_hack", "ragemp_economy_hack",
        "money_hack_ragemp", "economy_hack_ragemp", "ragemp_bank_hack",
        "money_exploit_ragemp", "economy_exploit_ragemp", "ragemp_balance",
        "ragemp_currency", "ragemp_wallet", "ragemp_cash_drop",
        "ragemp_money_drop", "gta5_ragemp_money",
    };

    private static readonly string[] ClientEventInjectionArtifacts =
    {
        "mp.events.add",
        "player.call",
        "mp.players.forEach",
        "economy.inject",
        "money.inject",
        "setAccountMoney",
        "addBankBalance",
        "playerMoney =",
        "mp.events.addCommand",
        "player.setVariable",
    };

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

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starting RageMP economy cheat forensic scan");

        await Task.WhenAll(
            CheckMoneyCheatExecutablesInRoamingAppData(ctx, ct),
            CheckMoneyCheatExecutablesInLocalAppData(ctx, ct),
            CheckMoneyCheatExecutablesInDownloads(ctx, ct),
            CheckEconomyExploitDlls(ctx, ct),
            CheckEconomyPackageFiles(ctx, ct),
            CheckJsFilesForEconomyPatterns(ctx, ct),
            CheckEconomyConfigArtifacts(ctx, ct),
            CheckEconomyCheatLogFiles(ctx, ct),
            CheckRageMPServerLogsForExploitSignatures(ctx, ct),
            CheckUserAssistForMoneyCheatExes(ctx, ct),
            CheckMuiCacheForMoneyCheatExes(ctx, ct),
            CheckRunKeysForMoneyCheatPersistence(ctx, ct),
            CheckPrefetchForMoneyCheatExecution(ctx, ct),
            CheckAmcacheForMoneyCheatArtifacts(ctx, ct),
            CheckFirewallLogsForEconomyExploitDomains(ctx, ct),
            CheckClientEventInjectionArtifacts(ctx, ct)
        );

        ctx.Report(1.0, Name, "RageMP economy cheat forensic scan complete");
    }

    private Task CheckMoneyCheatExecutablesInRoamingAppData(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var roamingAppData = KnownPaths.RoamingAppData;
            var searchRoots = new[]
            {
                Path.Combine(roamingAppData, "RAGEMP"),
                Path.Combine(roamingAppData, "RAGE Multiplayer"),
                roamingAppData,
            };

            foreach (var root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;
                ScanDirectoryForExecutables(ctx, root, MoneyCheatExecutables,
                    "RageMP Money Cheat EXE in RoamingAppData",
                    "RageMP economy/money cheat executable found in RoamingAppData. " +
                    "These tools exploit GTA-V RageMP server economy systems to add money, manipulate bank balances, or trigger money glitches.",
                    maxDepth: 4, ct);
            }
        }, ct);

    private Task CheckMoneyCheatExecutablesInLocalAppData(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = KnownPaths.LocalAppData;
            var searchRoots = new[]
            {
                Path.Combine(localAppData, "RAGEMP"),
                Path.Combine(localAppData, "RAGE Multiplayer"),
                localAppData,
            };

            foreach (var root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;
                ScanDirectoryForExecutables(ctx, root, MoneyCheatExecutables,
                    "RageMP Money Cheat EXE in LocalAppData",
                    "RageMP economy/money cheat executable found in LocalAppData. " +
                    "Economy exploit tools for RageMP frequently reside in LocalAppData to avoid detection by server-side anti-cheat.",
                    maxDepth: 4, ct);
            }
        }, ct);

    private Task CheckMoneyCheatExecutablesInDownloads(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var downloads = KnownPaths.Downloads;
            if (!Directory.Exists(downloads)) return;

            ScanDirectoryForExecutables(ctx, downloads, MoneyCheatExecutables,
                "RageMP Money Cheat EXE in Downloads",
                "RageMP economy/money cheat executable found in Downloads folder. " +
                "This is a strong indicator of recent acquisition of an economy exploit or money glitch tool for RageMP/GTA-V multiplayer servers.",
                maxDepth: 3, ct);

            foreach (var keyword in DownloadCheatFileKeywords)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(downloads, "*", SearchOption.TopDirectoryOnly))
                    {
                        var dirName = Path.GetFileName(dir);
                        if (dirName.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"RageMP Economy Cheat Folder in Downloads: {dirName}",
                                Risk = RiskLevel.High,
                                Location = dir,
                                FileName = dirName,
                                Reason = $"Downloads folder contains directory '{dirName}' matching RageMP economy cheat keyword '{keyword}'. " +
                                         "Money cheat packages for RageMP are frequently distributed as zip archives containing " +
                                         "scripts, executables, and configuration files targeting GTA-V multiplayer economy systems."
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    private Task CheckEconomyExploitDlls(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var searchRoots = new[]
            {
                KnownPaths.LocalAppData,
                KnownPaths.RoamingAppData,
                KnownPaths.Downloads,
                Path.Combine(KnownPaths.LocalAppData, "RAGEMP"),
                Path.Combine(KnownPaths.RoamingAppData, "RAGEMP"),
                Path.Combine(KnownPaths.RoamingAppData, "RAGE Multiplayer"),
            };

            foreach (var root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(root, maxDepth: 4, ct))
                    {
                        var fileName = Path.GetFileName(file);
                        foreach (var dll in EconomyExploitDlls)
                        {
                            if (fileName.Equals(dll, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.IncrementFiles();
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"RageMP Economy Exploit DLL: {fileName}",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"Economy exploit DLL '{fileName}' found at '{file}'. " +
                                             "This DLL is a known artifact of RageMP economy/money cheat tools. " +
                                             "These libraries are typically injected into the RageMP client process to intercept " +
                                             "and manipulate money transactions or player economy events on GTA-V multiplayer servers.",
                                    Detail = $"Matched known economy exploit DLL: {dll}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckEconomyPackageFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var ragempRoots = new[]
            {
                Path.Combine(KnownPaths.RoamingAppData, "RAGEMP"),
                Path.Combine(KnownPaths.RoamingAppData, "RAGE Multiplayer"),
                Path.Combine(KnownPaths.LocalAppData, "RAGEMP"),
                Path.Combine(KnownPaths.LocalAppData, "RAGE Multiplayer"),
                Path.Combine(KnownPaths.UserProfile, "Documents", "RAGEMP"),
                @"C:\RAGEMP",
                @"C:\Program Files\RAGE Multiplayer",
                @"C:\Program Files (x86)\RAGE Multiplayer",
            };

            foreach (var root in ragempRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(root, maxDepth: 5, ct))
                    {
                        var fileName = Path.GetFileName(file);
                        if (!Path.GetExtension(file).Equals(".js", StringComparison.OrdinalIgnoreCase))
                            continue;

                        foreach (var packageFile in EconomyPackageFiles)
                        {
                            if (fileName.Equals(packageFile, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.IncrementFiles();
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"RageMP Economy Exploit Package: {fileName}",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"RageMP economy exploit package file '{fileName}' found at '{file}'. " +
                                             "These JavaScript packages are injected into the RageMP client to call server-side money " +
                                             "functions, manipulate player bank balances, or trigger money glitches on GTA-V RP servers.",
                                    Detail = $"Matched known exploit package name: {packageFile}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckJsFilesForEconomyPatterns(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var ragempRoots = new[]
            {
                Path.Combine(KnownPaths.RoamingAppData, "RAGEMP"),
                Path.Combine(KnownPaths.RoamingAppData, "RAGE Multiplayer"),
                Path.Combine(KnownPaths.LocalAppData, "RAGEMP"),
                Path.Combine(KnownPaths.LocalAppData, "RAGE Multiplayer"),
                Path.Combine(KnownPaths.UserProfile, "Documents", "RAGEMP"),
                @"C:\RAGEMP",
                @"C:\Program Files\RAGE Multiplayer",
                @"C:\Program Files (x86)\RAGE Multiplayer",
            };

            foreach (var root in ragempRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(root, maxDepth: 6, ct))
                    {
                        if (!Path.GetExtension(file).Equals(".js", StringComparison.OrdinalIgnoreCase))
                            continue;

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

                        foreach (var pattern in JsEconomyExploitPatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"RageMP JS Economy Exploit Pattern: {Path.GetFileName(file)}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"JavaScript file '{Path.GetFileName(file)}' contains RageMP economy exploit pattern '{pattern}'. " +
                                             "This pattern is used in client-side RageMP economy cheats to call server money functions, " +
                                             "iterate over players to give them money, set bank balances, or trigger economy glitches.",
                                    Detail = $"Pattern matched: {pattern}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckEconomyConfigArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var searchRoots = new[]
            {
                KnownPaths.LocalAppData,
                KnownPaths.RoamingAppData,
                KnownPaths.Downloads,
                Path.Combine(KnownPaths.LocalAppData, "RAGEMP"),
                Path.Combine(KnownPaths.RoamingAppData, "RAGEMP"),
                Path.Combine(KnownPaths.RoamingAppData, "RAGE Multiplayer"),
                KnownPaths.UserProfile,
            };

            foreach (var root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(root, maxDepth: 4, ct))
                    {
                        var fileName = Path.GetFileName(file);
                        foreach (var configName in EconomyConfigArtifacts)
                        {
                            if (fileName.Equals(configName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.IncrementFiles();
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"RageMP Economy Cheat Config File: {fileName}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"RageMP economy cheat configuration file '{fileName}' found. " +
                                             "These configuration files are produced by RageMP money glitch and economy exploit tools " +
                                             "to store target server information, exploit parameters, and money injection amounts.",
                                    Detail = $"Matched known config artifact: {configName}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckEconomyCheatLogFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var searchRoots = new[]
            {
                Path.Combine(KnownPaths.LocalAppData, "RAGEMP"),
                Path.Combine(KnownPaths.RoamingAppData, "RAGEMP"),
                Path.Combine(KnownPaths.RoamingAppData, "RAGE Multiplayer"),
                KnownPaths.LocalAppData,
                KnownPaths.RoamingAppData,
                KnownPaths.Downloads,
            };

            foreach (var root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(root, maxDepth: 5, ct))
                    {
                        var fileName = Path.GetFileName(file);
                        foreach (var logName in EconomyCheatLogFiles)
                        {
                            if (fileName.Equals(logName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.IncrementFiles();
                                string? firstLines = null;
                                try
                                {
                                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                    using var sr = new StreamReader(fs);
                                    string content = await sr.ReadToEndAsync(ct);
                                    firstLines = content.Length > 512 ? content[..512] : content;
                                    firstLines = firstLines.Replace('\n', ' ').Replace('\r', ' ');
                                }
                                catch (IOException) { }

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"RageMP Economy Cheat Log File: {fileName}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"Economy cheat log file '{fileName}' found. " +
                                             "These log files are generated by RageMP money glitch tools and economy exploit scripts " +
                                             "to track successful exploits, server targets, and transaction results.",
                                    Detail = firstLines is not null ? $"Preview: {firstLines}" : null
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckRageMPServerLogsForExploitSignatures(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var logRoots = new[]
            {
                Path.Combine(KnownPaths.RoamingAppData, "RAGEMP"),
                Path.Combine(KnownPaths.RoamingAppData, "RAGE Multiplayer"),
                Path.Combine(KnownPaths.LocalAppData, "RAGEMP"),
                Path.Combine(KnownPaths.LocalAppData, "RAGE Multiplayer"),
                Path.Combine(KnownPaths.UserProfile, "Documents", "RAGEMP"),
                @"C:\RAGEMP",
                @"C:\Program Files\RAGE Multiplayer",
                @"C:\Program Files (x86)\RAGE Multiplayer",
            };

            foreach (var root in logRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(root, maxDepth: 5, ct))
                    {
                        var ext = Path.GetExtension(file);
                        if (!ext.Equals(".log", StringComparison.OrdinalIgnoreCase) &&
                            !ext.Equals(".txt", StringComparison.OrdinalIgnoreCase))
                            continue;

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

                        foreach (var sig in ServerLogExploitSignatures)
                        {
                            if (content.Contains(sig, StringComparison.OrdinalIgnoreCase))
                            {
                                var lineContext = FindLineContaining(content, sig);
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"RageMP Server Log Economy Exploit Signature: {Path.GetFileName(file)}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"RageMP log file '{Path.GetFileName(file)}' contains economy exploit signature '{sig}'. " +
                                             "This is indicative of money glitch activity, economy exploit use, or money cheat tool deployment " +
                                             "on a RageMP GTA-V server, such as negative balance attacks, balance overflow, or dupe exploits.",
                                    Detail = lineContext is not null ? $"Context: {lineContext}" : $"Signature: {sig}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckUserAssistForMoneyCheatExes(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string userAssistBase =
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

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
                            var decoded = Rot13Decode(encodedName);

                            var hit = UserAssistCheatKeywords.FirstOrDefault(k =>
                                decoded.Contains(k, StringComparison.OrdinalIgnoreCase));
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
                                    if (fileTime > 0)
                                        lastRun = DateTime.FromFileTimeUtc(fileTime);
                                }
                            }
                            catch { }

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"UserAssist: RageMP Money Cheat Executed: {Path.GetFileName(decoded)}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"Windows UserAssist record shows execution of '{Path.GetFileName(decoded)}' " +
                                         $"matching RageMP economy cheat keyword '{hit}'. " +
                                         $"Execution count: {runCount}" +
                                         (lastRun.HasValue ? $", last run: {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                         ". UserAssist entries persist after the binary is deleted, providing lasting forensic evidence.",
                                Detail = $"Decoded path: {decoded} | Runs: {runCount} | Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }, ct);

    private Task CheckMuiCacheForMoneyCheatExes(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string muiCacheKey =
                @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";

            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(muiCacheKey, writable: false);
                if (key is null) return;

                foreach (var valueName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();

                    var path = valueName;
                    var dotIdx = valueName.LastIndexOf('.');
                    if (dotIdx > 0 && !valueName[dotIdx..].Contains('\\'))
                        path = valueName[..dotIdx];

                    var friendlyName = key.GetValue(valueName) as string ?? string.Empty;
                    var combined = (path + " " + friendlyName).ToLowerInvariant();

                    var hit = MuiCacheCheatKeywords.FirstOrDefault(k =>
                        combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hit is null) continue;

                    bool fileExists = File.Exists(path);
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"MuiCache: RageMP Money Cheat Executed: {Path.GetFileName(path)}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{muiCacheKey}",
                        FileName = Path.GetFileName(path),
                        Reason = $"MuiCache entry proves execution of '{Path.GetFileName(path)}' " +
                                 $"matching RageMP economy cheat keyword '{hit}'. " +
                                 (fileExists ? "File still present on disk." : "File has been deleted but execution is forensically proven.") +
                                 " MuiCache entries survive binary deletion and provide reliable execution evidence.",
                        Detail = $"Path: {path} | Description: {friendlyName} | File exists: {fileExists}"
                    });
                }
            }
            catch { }
        }, ct);

    private Task CheckRunKeysForMoneyCheatPersistence(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var runKeyPaths = new[]
            {
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.CurrentUser),
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.CurrentUser),
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine),
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.LocalMachine),
                (@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine),
            };

            foreach (var (keyPath, hive) in runKeyPaths)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var key = hive.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();
                        var value = key.GetValue(valueName) as string ?? string.Empty;
                        var combined = (valueName + " " + value).ToLowerInvariant();

                        var hit = RunKeyCheatNames.FirstOrDefault(k =>
                            combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hit is null) continue;

                        var hiveName = ReferenceEquals(hive, Registry.CurrentUser) ? "HKCU" : "HKLM";
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Run Key: RageMP Money Cheat Persistence: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"{hiveName}\{keyPath}",
                            FileName = valueName,
                            Reason = $"Registry Run key entry '{valueName}' references a RageMP economy cheat tool matching keyword '{hit}'. " +
                                     "Persistence via Run keys indicates the cheat was configured to start automatically, " +
                                     "consistent with RageMP economy exploit tools that connect to game sessions at startup.",
                            Detail = $"Value: {value} | Key: {hiveName}\\{keyPath}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }, ct);

    private Task CheckPrefetchForMoneyCheatExecution(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var prefetchDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

            if (!Directory.Exists(prefetchDir)) return;

            try
            {
                foreach (var file in Directory.EnumerateFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var fileName = Path.GetFileNameWithoutExtension(file);

                    var hit = PrefetchCheatNames.FirstOrDefault(k =>
                        fileName.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hit is null) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Prefetch: RageMP Money Cheat Execution Evidence: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Windows Prefetch file '{Path.GetFileName(file)}' provides execution evidence for a RageMP money cheat matching keyword '{hit}'. " +
                                 "Prefetch files are created by Windows for applications that have been executed and persist after the binary is removed, " +
                                 "providing reliable forensic proof of economy exploit tool execution.",
                        Detail = $"Prefetch name matched: {hit}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }, ct);

    private Task CheckAmcacheForMoneyCheatArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            const string amcacheHive =
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Amcache";

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(amcacheHive, writable: false);
                if (key is null) return;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var sub = key.OpenSubKey(subKeyName, writable: false);
                        if (sub is null) continue;

                        foreach (var valueName in sub.GetValueNames())
                        {
                            ctx.IncrementRegistryKeys();
                            var value = sub.GetValue(valueName)?.ToString() ?? string.Empty;
                            var combined = (subKeyName + " " + valueName + " " + value).ToLowerInvariant();

                            var hit = AmcacheCheatKeywords.FirstOrDefault(k =>
                                combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (hit is null) continue;

                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Amcache: RageMP Money Cheat Artifact: {valueName}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{amcacheHive}\{subKeyName}",
                                FileName = valueName,
                                Reason = $"Amcache entry references RageMP economy cheat artifact matching keyword '{hit}'. " +
                                         "Amcache records application execution and file metadata and persists for deleted files, " +
                                         "providing forensic evidence of RageMP money glitch or economy exploit tool usage.",
                                Detail = $"Value: {value} | SubKey: {subKeyName}"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }, ct);

    private Task CheckFirewallLogsForEconomyExploitDomains(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var firewallLogPaths = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "System32", "LogFiles", "Firewall", "pfirewall.log"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "System32", "LogFiles", "Firewall", "pfirewall.log.old"),
            };

            var proxyConfigPaths = new[]
            {
                Path.Combine(KnownPaths.RoamingAppData, "RAGEMP", "proxy.cfg"),
                Path.Combine(KnownPaths.RoamingAppData, "RAGEMP", "settings.json"),
                Path.Combine(KnownPaths.RoamingAppData, "RAGE Multiplayer", "proxy.cfg"),
                Path.Combine(KnownPaths.RoamingAppData, "RAGE Multiplayer", "settings.json"),
                Path.Combine(KnownPaths.LocalAppData, "RAGEMP", "proxy.cfg"),
                Path.Combine(KnownPaths.LocalAppData, "RAGEMP", "settings.json"),
            };

            foreach (var logPath in firewallLogPaths)
            {
                if (!File.Exists(logPath)) continue;
                ct.ThrowIfCancellationRequested();

                string content;
                try
                {
                    using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var domainFragment in FirewallLogExploitDomainFragments)
                {
                    if (content.Contains(domainFragment, StringComparison.OrdinalIgnoreCase))
                    {
                        var lineContext = FindLineContaining(content, domainFragment);
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Firewall Log: RageMP Economy Exploit Domain Connection: {domainFragment}",
                            Risk = RiskLevel.High,
                            Location = logPath,
                            FileName = Path.GetFileName(logPath),
                            Reason = $"Windows Firewall log contains connection to RageMP economy exploit domain fragment '{domainFragment}'. " +
                                     "Connections to these domains indicate use of RageMP money cheat panels, economy exploit services, " +
                                     "or remote economy hack tools that communicate with external servers.",
                            Detail = lineContext is not null ? $"Log context: {lineContext}" : $"Domain fragment: {domainFragment}"
                        });
                        break;
                    }
                }
            }

            foreach (var proxyPath in proxyConfigPaths)
            {
                if (!File.Exists(proxyPath)) continue;
                ct.ThrowIfCancellationRequested();

                string content;
                try
                {
                    using var fs = new FileStream(proxyPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }
                catch (UnauthorizedAccessException) { continue; }

                foreach (var keyword in ProxyConfigExploitKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"RageMP Proxy Config Economy Exploit Reference: {Path.GetFileName(proxyPath)}",
                            Risk = RiskLevel.High,
                            Location = proxyPath,
                            FileName = Path.GetFileName(proxyPath),
                            Reason = $"RageMP proxy/settings configuration file '{Path.GetFileName(proxyPath)}' contains economy exploit keyword '{keyword}'. " +
                                     "Economy cheat proxies intercept and modify RageMP network traffic to inject money transactions or " +
                                     "manipulate server-side economy events.",
                            Detail = $"Keyword found: {keyword}"
                        });
                        break;
                    }
                }
            }
        }, ct);

    private Task CheckClientEventInjectionArtifacts(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var ragempClientPackageDirs = new[]
            {
                Path.Combine(KnownPaths.RoamingAppData, "RAGEMP", "client_packages"),
                Path.Combine(KnownPaths.RoamingAppData, "RAGE Multiplayer", "client_packages"),
                Path.Combine(KnownPaths.LocalAppData, "RAGEMP", "client_packages"),
                Path.Combine(KnownPaths.LocalAppData, "RAGE Multiplayer", "client_packages"),
                Path.Combine(@"C:\RAGEMP", "client_packages"),
                Path.Combine(@"C:\Program Files\RAGE Multiplayer", "client_packages"),
                Path.Combine(@"C:\Program Files (x86)\RAGE Multiplayer", "client_packages"),
            };

            foreach (var packageDir in ragempClientPackageDirs)
            {
                if (!Directory.Exists(packageDir)) continue;

                try
                {
                    foreach (var file in EnumerateFilesRecursive(packageDir, maxDepth: 4, ct))
                    {
                        if (!Path.GetExtension(file).Equals(".js", StringComparison.OrdinalIgnoreCase))
                            continue;

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

                        int matchCount = 0;
                        string? firstMatchedPattern = null;
                        foreach (var artifact in ClientEventInjectionArtifacts)
                        {
                            if (content.Contains(artifact, StringComparison.OrdinalIgnoreCase))
                            {
                                matchCount++;
                                firstMatchedPattern ??= artifact;
                            }
                        }

                        if (matchCount >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"RageMP Client Package Economy Event Injection: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"RageMP client package file '{Path.GetFileName(file)}' contains {matchCount} economy event injection patterns " +
                                         $"(first match: '{firstMatchedPattern}'). " +
                                         "Client packages with multiple economy event manipulation patterns are characteristic of " +
                                         "money injection scripts that exploit the RageMP client-server event system to grant players " +
                                         "unauthorized money or manipulate economy variables on GTA-V multiplayer servers.",
                                Detail = $"Pattern matches: {matchCount} | First match: {firstMatchedPattern}"
                            });
                        }
                        else if (matchCount == 1 && firstMatchedPattern is not null)
                        {
                            var fileName = Path.GetFileName(file).ToLowerInvariant();
                            bool nameIsSuspicious = DownloadCheatFileKeywords.Any(k =>
                                fileName.Contains(k, StringComparison.OrdinalIgnoreCase));

                            if (nameIsSuspicious)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"RageMP Client Package Suspicious Economy Pattern: {Path.GetFileName(file)}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"RageMP client package '{Path.GetFileName(file)}' has a suspicious economy-related name " +
                                             $"and contains economy event pattern '{firstMatchedPattern}'. " +
                                             "This combination of suspicious naming and economy event usage is indicative of money cheat or economy exploit packages.",
                                    Detail = $"Pattern: {firstMatchedPattern}"
                                });
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private static void ScanDirectoryForExecutables(
        ScanContext ctx,
        string root,
        string[] targetFileNames,
        string findingTitle,
        string findingReason,
        int maxDepth,
        CancellationToken ct)
    {
        try
        {
            foreach (var file in EnumerateFilesRecursive(root, maxDepth, ct))
            {
                var fileName = Path.GetFileName(file);
                foreach (var target in targetFileNames)
                {
                    if (fileName.Equals(target, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = "RageMP Economy Glitch & Money Cheat Forensic Scan",
                            Title = $"{findingTitle}: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = findingReason + $" File: '{file}'.",
                            Detail = $"Matched known artifact name: {target}"
                        });
                        break;
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
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
}
