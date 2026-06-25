using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMMoneyDropCheatScanModule : IScanModule
{
    public string Name => "FiveM Money Drop & Economy Cheat Forensic Scan";
    public double Weight => 4.0;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] MoneyDropExecutables =
    {
        "fivem_money.exe",
        "fivem_cash.exe",
        "fivem_drop.exe",
        "fivem_money_drop.exe",
        "fivem_cash_drop.exe",
        "money_drop_fivem.exe",
        "cash_drop_fivem.exe",
        "fivem_bank.exe",
        "fivem_bank_hack.exe",
        "fivem_rp_money.exe",
        "fivem_esx_money.exe",
        "fivem_vrp_money.exe",
        "fivem_qb_money.exe",
        "fivem_qbus_money.exe",
        "esx_money_drop.exe",
        "vrp_money_hack.exe",
        "qb_money_hack.exe",
        "fivem_economy_hack.exe",
        "fivem_money_cheat.exe",
        "fivem_money_tool.exe",
        "gtav_fivem_money.exe",
        "rp_money_dropper.exe",
        "esx_bank_hack.exe",
        "qbus_economy_hack.exe",
        "fivem_money_injector.exe",
        "fivem_cashapp.exe",
        "fivem_wallet_hack.exe",
        "economy_exploit_fivem.exe",
    };

    private static readonly string[] EconomyExploitDlls =
    {
        "fivem_money.dll",
        "fivem_economy.dll",
        "money_exploit.dll",
        "economy_exploit.dll",
        "esx_exploit.dll",
        "vrp_exploit.dll",
        "qb_exploit.dll",
        "qbus_exploit.dll",
        "fivem_bank_exploit.dll",
        "money_drop_hook.dll",
        "economy_hook.dll",
        "esx_money_hook.dll",
        "fivem_transaction_hook.dll",
        "give_money_hook.dll",
        "add_money_inject.dll",
        "fivem_economy_inject.dll",
        "rp_economy_exploit.dll",
    };

    private static readonly string[] EconomyResourceNames =
    {
        "money_drop",
        "cash_drop",
        "economy_exploit",
        "esx_hack",
        "vrp_hack",
        "qb_hack",
        "qbus_hack",
        "bank_hack",
        "give_money",
        "add_money",
        "set_money",
        "money_menu",
        "bank_menu",
        "economy_menu",
        "money_dropper",
        "cash_dropper",
        "esx_money_exploit",
        "vrp_economy_hack",
        "qb_economy_exploit",
        "fivem_bank_exploit",
        "wallet_hack",
        "transaction_exploit",
        "giveall_money",
        "setbalance",
        "addbalance",
        "bank_overflow",
        "economy_overflow",
        "money_bypass",
        "currency_exploit",
    };

    private static readonly string[] EconomyCheatConfigFiles =
    {
        "fivem_money_config.json",
        "esx_money_config.cfg",
        "money_drop_config.txt",
        "fivem_economy_config.json",
        "qb_money_config.json",
        "vrp_money_config.json",
        "cash_drop_config.txt",
        "bank_hack_config.json",
        "economy_exploit_config.cfg",
        "money_cheat_settings.json",
        "give_money_config.txt",
        "esx_exploit_config.json",
        "transaction_hack_config.json",
    };

    private static readonly string[] EconomyCheatLogFiles =
    {
        "money_drop_log.txt",
        "economy_exploit.log",
        "transaction_hack.log",
        "fivem_money_log.txt",
        "cash_drop_log.txt",
        "esx_money_log.txt",
        "bank_hack_log.txt",
        "give_money_log.txt",
        "economy_hack_log.txt",
        "money_exploit_log.txt",
        "vrp_hack_log.txt",
        "qb_money_log.txt",
        "fivem_economy_log.txt",
        "currency_exploit.log",
    };

    private static readonly string[] EconomyScriptPatterns =
    {
        "AddMoney",
        "GiveMoney",
        "SetMoney",
        "AddBankMoney",
        "SetBankMoney",
        "xPlayer.addMoney",
        "xPlayer.addBankMoney",
        "QBCore.Functions.GetPlayer",
        "Player.Functions.AddMoney",
        "addAccountMoney",
        "setAccountMoney",
        "removeAccountMoney",
        "xPlayer.getMoney",
        "xPlayer.setBankMoney",
        "TriggerServerEvent.*money",
        "TriggerServerEvent.*bank",
        "exports.esx_money",
        "exports.qb-banking",
        "MySQL.Async.execute.*money",
        "drops.money",
        "moneyDrop(",
        "giveCash(",
        "setCash(",
        "addCash(",
        "playerMoney =",
        "bankBalance =",
        "addBankBalance",
        "setWalletMoney",
        "addWalletMoney",
        "economy.addMoney",
        "economy.setMoney",
    };

    private static readonly string[] RunKeyCheatNames =
    {
        "fivem_money", "fivem_cash", "fivem_drop", "fivem_money_drop",
        "fivem_cash_drop", "money_drop_fivem", "cash_drop_fivem",
        "fivem_bank_hack", "fivem_rp_money", "fivem_esx_money",
        "fivem_vrp_money", "fivem_qb_money", "esx_money_drop",
        "vrp_money_hack", "qb_money_hack", "fivem_economy_hack",
        "esx_bank_hack", "economy_exploit_fivem", "fivem_money_cheat",
    };

    private static readonly string[] MuiCacheCheatKeywords =
    {
        "fivem_money", "fivem_cash", "money_drop", "cash_drop",
        "economy_exploit", "esx_money", "vrp_money", "qb_money",
        "bank_hack", "give_money", "add_money", "fivem_bank",
        "fivem_economy", "rp_money", "money_cheat", "economy_hack",
    };

    private static readonly string[] UserAssistCheatKeywords =
    {
        "fivem_money", "fivem_cash", "fivem_drop", "money_drop_fivem",
        "cash_drop_fivem", "fivem_bank_hack", "esx_money_drop",
        "vrp_money_hack", "qb_money_hack", "fivem_economy_hack",
        "fivem_rp_money", "economy_exploit_fivem", "fivem_money_cheat",
        "esx_bank_hack", "qbus_money_hack", "fivem_qb_money",
    };

    private static readonly string[] ServerLogExploitSignatures =
    {
        "negative balance",
        "balance overflow",
        "impossible transfer",
        "transaction exploit",
        "money exploit detected",
        "economy hack",
        "invalid money amount",
        "balance manipulation",
        "give_money abuse",
        "AddMoney overflow",
        "SetMoney bypass",
        "bank exploit",
        "duplicate transaction",
        "money dupe",
        "economy dupe",
        "cash dupe",
        "illegal economy",
        "balance inject",
        "economy inject",
        "illegal money",
        "money cheat",
        "cash cheat",
        "bank cheat",
        "economy abuse",
        "money laundering exploit",
        "wallet overflow",
    };

    private static readonly string[] FiveMAppDataSubPaths =
    {
        "FiveM.app",
        "FiveM.app\\logs",
        "FiveM.app\\server-data",
        "FiveM.app\\data",
        "FiveM.app\\citizen",
        "FiveM.app\\plugins",
        "FiveM.app\\crashes",
    };

    private static readonly string[] LuaEconomyCheatPatterns =
    {
        "AddMoney",
        "GiveMoney",
        "SetMoney",
        "xPlayer.addMoney",
        "xPlayer.addBankMoney",
        "QBCore.Functions.GetPlayer",
        "Player.Functions.AddMoney",
        "addAccountMoney",
        "setAccountMoney",
        "TriggerServerEvent.*money",
        "economy.setBalance",
        "SetPlayerMoney",
        "moneyDrop",
        "giveCash",
        "bank.addMoney",
        "economy.addMoney",
        "wallet.set",
        "mysql.*money",
        "oxmysql.*money",
    };

    private static readonly string[] JsEconomyCheatPatterns =
    {
        "addMoney(",
        "setMoney(",
        "giveMoney(",
        "addBankBalance(",
        "setAccountMoney(",
        "addAccountMoney(",
        "player.addMoney",
        "player.setMoney",
        "player.giveCash",
        "economy.addMoney",
        "economy.setBalance",
        "bank.addMoney",
        "bank.setBalance",
        "wallet.set(",
        "moneyDrop(",
    };

    private static readonly string[] DownloadCheatFileKeywords =
    {
        "fivem_money", "fivem_cash", "money_drop", "cash_drop",
        "economy_exploit", "esx_money", "vrp_money", "qb_money",
        "bank_hack", "give_money", "fivem_economy", "rp_money",
        "money_cheat", "economy_hack", "fivem_bank", "fivem_rp",
        "esx_exploit", "vrp_exploit", "qb_exploit", "qbus_exploit",
    };

    private static readonly string[] PrefetchCheatNames =
    {
        "FIVEM_MONEY", "FIVEM_CASH", "MONEY_DROP", "CASH_DROP",
        "ECONOMY_EXPLOIT", "ESX_MONEY_DROP", "VRP_MONEY_HACK",
        "QB_MONEY_HACK", "FIVEM_BANK_HACK", "ECONOMY_HACK",
        "FIVEM_ECONOMY_HACK", "FIVEM_MONEY_DROP", "FIVEM_CASH_DROP",
    };

    private static readonly string[] AmcacheCheatKeywords =
    {
        "fivem_money", "fivem_cash", "money_drop", "cash_drop",
        "economy_exploit", "esx_money_drop", "vrp_money_hack",
        "qb_money_hack", "fivem_bank_hack", "fivem_economy_hack",
        "fivem_money_drop", "fivem_rp_money",
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
        ctx.Report(0.0, Name, "Starting FiveM economy cheat forensic scan");

        await Task.WhenAll(
            CheckMoneyDropExecutablesInLocalAppData(ctx, ct),
            CheckMoneyDropExecutablesInRoamingAppData(ctx, ct),
            CheckMoneyDropExecutablesInDownloads(ctx, ct),
            CheckEconomyExploitDlls(ctx, ct),
            CheckEconomyResourceFolders(ctx, ct),
            CheckEconomyCheatConfigFiles(ctx, ct),
            CheckEconomyCheatLogFiles(ctx, ct),
            CheckLuaScriptsForEconomyPatterns(ctx, ct),
            CheckJsScriptsForEconomyPatterns(ctx, ct),
            CheckFiveMServerLogsForExploitSignatures(ctx, ct),
            CheckUserAssistForMoneyCheatExes(ctx, ct),
            CheckMuiCacheForMoneyCheatExes(ctx, ct),
            CheckRunKeysForMoneyCheatPersistence(ctx, ct),
            CheckPrefetchForMoneyCheatExecution(ctx, ct),
            CheckAmcacheForMoneyCheatArtifacts(ctx, ct),
            CheckFiveMAppDataForSuspiciousFiles(ctx, ct)
        );

        ctx.Report(1.0, Name, "FiveM economy cheat forensic scan complete");
    }

    private Task CheckMoneyDropExecutablesInLocalAppData(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var localAppData = KnownPaths.LocalAppData;
            var fivemLocalDir = Path.Combine(localAppData, "FiveM");
            var searchRoots = new[]
            {
                fivemLocalDir,
                localAppData,
            };

            foreach (var root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;
                ScanDirectoryForExecutables(ctx, root, MoneyDropExecutables,
                    "FiveM Money Drop EXE in LocalAppData",
                    "FiveM money drop cheat executable found in LocalAppData. " +
                    "This file is a known economy exploit tool for FiveM/GTA-V roleplay servers.",
                    maxDepth: 4, ct);
            }
        }, ct);

    private Task CheckMoneyDropExecutablesInRoamingAppData(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var roamingAppData = KnownPaths.RoamingAppData;
            var fivemRoamingDir = Path.Combine(roamingAppData, "FiveM");
            var searchRoots = new[]
            {
                fivemRoamingDir,
                roamingAppData,
            };

            foreach (var root in searchRoots)
            {
                if (!Directory.Exists(root)) continue;
                ScanDirectoryForExecutables(ctx, root, MoneyDropExecutables,
                    "FiveM Money Drop EXE in RoamingAppData",
                    "FiveM money drop cheat executable found in RoamingAppData. " +
                    "Economy exploit tools frequently install themselves in roaming AppData to persist across sessions.",
                    maxDepth: 4, ct);
            }
        }, ct);

    private Task CheckMoneyDropExecutablesInDownloads(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var downloads = KnownPaths.Downloads;
            if (!Directory.Exists(downloads)) return;

            ScanDirectoryForExecutables(ctx, downloads, MoneyDropExecutables,
                "FiveM Money Drop EXE in Downloads",
                "FiveM money drop cheat executable found in Downloads folder. " +
                "This is a strong indicator of recent acquisition of an economy exploit tool for FiveM/GTA-V RP servers.",
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
                                Title = $"FiveM Economy Cheat Folder in Downloads: {dirName}",
                                Risk = RiskLevel.High,
                                Location = dir,
                                FileName = dirName,
                                Reason = $"Directory in Downloads folder matches FiveM economy cheat keyword '{keyword}'. " +
                                         "Cheat packages for FiveM money drops are commonly distributed as named folders " +
                                         "containing scripts, executables, and configuration files."
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
                Path.Combine(KnownPaths.LocalAppData, "FiveM"),
                Path.Combine(KnownPaths.RoamingAppData, "FiveM"),
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
                                    Title = $"FiveM Economy Exploit DLL: {fileName}",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"Economy exploit DLL '{fileName}' found at '{file}'. " +
                                             "This DLL is a known artifact of FiveM economy/money cheat tools. " +
                                             "These libraries are typically injected into the FiveM process or loaded " +
                                             "as plugins to intercept and manipulate economy transactions on RP servers.",
                                    Detail = $"Matched known economy exploit DLL name: {dll}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckEconomyResourceFolders(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var fivemRoots = new[]
            {
                Path.Combine(KnownPaths.LocalAppData, "FiveM"),
                Path.Combine(KnownPaths.RoamingAppData, "FiveM"),
                Path.Combine(KnownPaths.LocalAppData, "FiveM", "FiveM.app"),
                Path.Combine(KnownPaths.LocalAppData, "FiveM", "FiveM.app", "data"),
                Path.Combine(KnownPaths.UserProfile, "FiveM"),
                Path.Combine(KnownPaths.UserProfile, "FiveM", "server-data"),
                Path.Combine(KnownPaths.UserProfile, "FiveM", "server-data", "resources"),
            };

            var resourcesFolderNames = new[] { "resources", "server-data", "data" };

            foreach (var root in fivemRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        var dirName = Path.GetFileName(dir);
                        foreach (var resourceName in EconomyResourceNames)
                        {
                            if (dirName.Equals(resourceName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"FiveM Economy Exploit Resource Folder: {dirName}",
                                    Risk = RiskLevel.Critical,
                                    Location = dir,
                                    FileName = dirName,
                                    Reason = $"FiveM resource folder '{dirName}' matches a known economy exploit resource name. " +
                                             "These server-side resources are used to inject money, manipulate bank balances, " +
                                             "or exploit ESX/vRP/QBCore economy frameworks on FiveM RP servers. " +
                                             $"Matched resource name: '{resourceName}'.",
                                    Detail = $"Resource path: {dir}"
                                });
                                break;
                            }
                        }

                        foreach (var resourceName in EconomyResourceNames)
                        {
                            if (!dirName.Equals(resourceName, StringComparison.OrdinalIgnoreCase) &&
                                dirName.Contains(resourceName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"FiveM Suspicious Economy Resource (Partial Match): {dirName}",
                                    Risk = RiskLevel.High,
                                    Location = dir,
                                    FileName = dirName,
                                    Reason = $"FiveM resource folder '{dirName}' partially matches known economy exploit keyword '{resourceName}'. " +
                                             "Economy cheats for FiveM often use slight name variations to evade detection.",
                                    Detail = $"Partial keyword match: {resourceName} in {dirName}"
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }, ct);

    private Task CheckEconomyCheatConfigFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(() =>
        {
            var searchRoots = new[]
            {
                KnownPaths.LocalAppData,
                KnownPaths.RoamingAppData,
                KnownPaths.Downloads,
                Path.Combine(KnownPaths.LocalAppData, "FiveM"),
                Path.Combine(KnownPaths.RoamingAppData, "FiveM"),
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
                        foreach (var configName in EconomyCheatConfigFiles)
                        {
                            if (fileName.Equals(configName, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.IncrementFiles();
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"FiveM Economy Cheat Config File: {fileName}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"Economy cheat configuration file '{fileName}' found. " +
                                             "These configuration files are created by FiveM money drop and economy exploit tools " +
                                             "to store target server addresses, exploit parameters, and money injection settings.",
                                    Detail = $"Matched config artifact: {configName}"
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
                Path.Combine(KnownPaths.LocalAppData, "FiveM"),
                Path.Combine(KnownPaths.RoamingAppData, "FiveM"),
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
                                }
                                catch (IOException) { }

                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"FiveM Economy Cheat Log File: {fileName}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = $"Economy cheat log file '{fileName}' found. " +
                                             "These log files are written by FiveM money drop tools and economy exploit scripts " +
                                             "to track successful transactions, server connections, and exploit results.",
                                    Detail = firstLines is not null ? $"Preview: {firstLines.Replace('\n', ' ').Replace('\r', ' ')}" : null
                                });
                                break;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
            }
        }, ct);

    private Task CheckLuaScriptsForEconomyPatterns(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var fivemRoots = new[]
            {
                Path.Combine(KnownPaths.LocalAppData, "FiveM"),
                Path.Combine(KnownPaths.RoamingAppData, "FiveM"),
                Path.Combine(KnownPaths.LocalAppData, "FiveM", "FiveM.app"),
                Path.Combine(KnownPaths.UserProfile, "FiveM"),
            };

            foreach (var root in fivemRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(root, maxDepth: 6, ct))
                    {
                        var ext = Path.GetExtension(file);
                        if (!ext.Equals(".lua", StringComparison.OrdinalIgnoreCase) &&
                            !ext.Equals(".luac", StringComparison.OrdinalIgnoreCase))
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

                        foreach (var pattern in LuaEconomyCheatPatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"FiveM Lua Economy Exploit Pattern: {Path.GetFileName(file)}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Lua script '{Path.GetFileName(file)}' contains economy exploit pattern '{pattern}'. " +
                                             "This pattern is associated with FiveM economy cheats that manipulate player balances, " +
                                             "bank accounts, or trigger unauthorized money transfers on ESX/QBCore/vRP frameworks.",
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

    private Task CheckJsScriptsForEconomyPatterns(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var fivemRoots = new[]
            {
                Path.Combine(KnownPaths.LocalAppData, "FiveM"),
                Path.Combine(KnownPaths.RoamingAppData, "FiveM"),
                Path.Combine(KnownPaths.UserProfile, "FiveM"),
            };

            foreach (var root in fivemRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(root, maxDepth: 6, ct))
                    {
                        var ext = Path.GetExtension(file);
                        if (!ext.Equals(".js", StringComparison.OrdinalIgnoreCase)) continue;

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

                        foreach (var pattern in JsEconomyCheatPatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"FiveM JS Economy Exploit Pattern: {Path.GetFileName(file)}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"JavaScript file '{Path.GetFileName(file)}' contains economy exploit pattern '{pattern}'. " +
                                             "FiveM JavaScript resources using these patterns may be used to manipulate economy " +
                                             "transactions, set arbitrary bank balances, or give players unlimited money.",
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

    private Task CheckFiveMServerLogsForExploitSignatures(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var logRoots = new[]
            {
                Path.Combine(KnownPaths.LocalAppData, "FiveM", "FiveM.app", "logs"),
                Path.Combine(KnownPaths.LocalAppData, "FiveM", "FiveM.app", "data", "logs"),
                Path.Combine(KnownPaths.LocalAppData, "FiveM"),
                Path.Combine(KnownPaths.RoamingAppData, "FiveM"),
                Path.Combine(KnownPaths.UserProfile, "FiveM", "server-data", "logs"),
                Path.Combine(KnownPaths.UserProfile, "FiveM"),
            };

            foreach (var root in logRoots)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(root, maxDepth: 4, ct))
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
                                var lineNum = FindLineContaining(content, sig);
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"FiveM Server Log Economy Exploit Signature: {Path.GetFileName(file)}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"FiveM log file '{Path.GetFileName(file)}' contains economy exploit signature '{sig}'. " +
                                             "This signature indicates the use of economy manipulation cheats, such as negative balance exploits, " +
                                             "impossible money transfers, or balance overflow attacks on FiveM RP servers.",
                                    Detail = lineNum is not null ? $"Signature '{sig}' found near: {lineNum}" : $"Signature: {sig}"
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
                                Title = $"UserAssist: FiveM Money Cheat Executed: {Path.GetFileName(decoded)}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                FileName = Path.GetFileName(decoded),
                                Reason = $"Windows UserAssist record shows execution of '{Path.GetFileName(decoded)}' " +
                                         $"which matches FiveM economy cheat keyword '{hit}'. " +
                                         $"Execution count: {runCount}" +
                                         (lastRun.HasValue ? $", last run: {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                         ". UserAssist entries persist even after the file is deleted.",
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
                        Title = $"MuiCache: FiveM Money Cheat Executed: {Path.GetFileName(path)}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{muiCacheKey}",
                        FileName = Path.GetFileName(path),
                        Reason = $"MuiCache entry proves execution of '{Path.GetFileName(path)}' " +
                                 $"matching FiveM economy cheat keyword '{hit}'. " +
                                 (fileExists ? "File still present on disk." : "File has been deleted; execution is still forensically proven.") +
                                 " MuiCache records persist after the binary is removed.",
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
                            Title = $"Run Key: FiveM Money Cheat Persistence: {valueName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"{hiveName}\{keyPath}",
                            FileName = valueName,
                            Reason = $"Registry Run key entry '{valueName}' references a FiveM economy cheat tool matching keyword '{hit}'. " +
                                     "This indicates the cheat was configured for automatic startup, a strong persistence indicator for economy exploit tools.",
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
                    var fileName = Path.GetFileNameWithoutExtension(file).ToUpperInvariant();

                    var hit = PrefetchCheatNames.FirstOrDefault(k =>
                        fileName.Contains(k, StringComparison.OrdinalIgnoreCase));
                    if (hit is null) continue;

                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Prefetch: FiveM Money Cheat Execution Evidence: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Windows Prefetch file '{Path.GetFileName(file)}' proves execution of a FiveM money cheat executable matching keyword '{hit}'. " +
                                 "Prefetch files are created by Windows for applications that have been run and persist even after the binary is deleted.",
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
                                Title = $"Amcache: FiveM Money Cheat Artifact: {valueName}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{amcacheHive}\{subKeyName}",
                                FileName = valueName,
                                Reason = $"Amcache entry references FiveM economy cheat artifact matching keyword '{hit}'. " +
                                         "Amcache records application execution history and persists for deleted files, " +
                                         "providing forensic evidence of money cheat tool usage.",
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

    private Task CheckFiveMAppDataForSuspiciousFiles(ScanContext ctx, CancellationToken ct) =>
        Task.Run(async () =>
        {
            var localAppData = KnownPaths.LocalAppData;
            var roamingAppData = KnownPaths.RoamingAppData;

            var subPaths = new[]
            {
                Path.Combine(localAppData, "FiveM", "FiveM.app"),
                Path.Combine(localAppData, "FiveM", "FiveM.app", "logs"),
                Path.Combine(localAppData, "FiveM", "FiveM.app", "data"),
                Path.Combine(localAppData, "FiveM", "FiveM.app", "citizen"),
                Path.Combine(localAppData, "FiveM", "FiveM.app", "plugins"),
                Path.Combine(localAppData, "FiveM", "FiveM.app", "crashes"),
                Path.Combine(roamingAppData, "FiveM"),
                Path.Combine(roamingAppData, "FiveM", "FiveM.app"),
            };

            var suspiciousFilePatterns = new[]
            {
                "money", "cash", "economy", "exploit", "hack", "cheat",
                "esx_money", "vrp_money", "qb_money", "bank_hack",
                "give_money", "add_money", "set_money", "money_drop",
                "cash_drop", "economy_exploit", "bank_exploit",
                "transaction_hack", "balance_hack", "wallet_hack",
            };

            foreach (var root in subPaths)
            {
                if (!Directory.Exists(root)) continue;
                try
                {
                    foreach (var file in EnumerateFilesRecursive(root, maxDepth: 3, ct))
                    {
                        ct.ThrowIfCancellationRequested();
                        var fileName = Path.GetFileName(file).ToLowerInvariant();
                        var ext = Path.GetExtension(file).ToLowerInvariant();

                        if (ext is not (".exe" or ".dll" or ".lua" or ".js" or ".cfg" or ".json" or ".txt" or ".log"))
                            continue;

                        var hit = suspiciousFilePatterns.FirstOrDefault(p =>
                            fileName.Contains(p, StringComparison.OrdinalIgnoreCase));
                        if (hit is null) continue;

                        ctx.IncrementFiles();

                        string? contentPreview = null;
                        if (ext is ".lua" or ".js" or ".cfg" or ".json" or ".txt" or ".log")
                        {
                            try
                            {
                                using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                string content = await sr.ReadToEndAsync(ct);
                                contentPreview = content.Length > 256 ? content[..256] : content;
                                contentPreview = contentPreview.Replace('\n', ' ').Replace('\r', ' ');
                            }
                            catch (IOException) { }
                        }

                        var risk = ext is ".exe" or ".dll" ? RiskLevel.Critical : RiskLevel.High;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM AppData Suspicious Economy File: {Path.GetFileName(file)}",
                            Risk = risk,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Suspicious file '{Path.GetFileName(file)}' found in FiveM AppData directory, " +
                                     $"matching economy cheat keyword '{hit}'. " +
                                     "Files with economy/money-related names in FiveM's application data directory " +
                                     "are strong indicators of money drop or economy exploit tools.",
                            Detail = contentPreview is not null ? $"Content preview: {contentPreview}" : null
                        });
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
                            Module = "FiveM Money Drop & Economy Cheat Forensic Scan",
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
