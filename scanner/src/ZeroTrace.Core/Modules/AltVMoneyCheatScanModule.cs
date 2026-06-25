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

public sealed class AltVMoneyCheatScanModule : IScanModule
{
    public string Name => "alt:V Money & Economy Cheat Forensic Scan";
    public double Weight => 4.1;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static readonly string[] MoneyCheatExecutables =
    [
        "altv_money.exe", "altv_moneydrop.exe", "altv_economy_hack.exe", "altv_cash_drop.exe",
        "economy_inject.exe", "altv_givemoney.exe", "altv_bank_hack.exe", "altv_account_hack.exe",
        "money_spawn.exe", "cash_spawn.exe", "altv_wealth.exe", "altv_infinite_money.exe",
        "altv_maxcash.exe", "cash_inject.exe", "money_exploit.exe", "give_cash.exe",
        "money_cheat.exe", "economy_bypass.exe", "cash_hack.exe", "altv_bank.exe",
        "bank_exploit.exe", "money_trainer.exe", "cash_trainer.exe", "altv_cheats.exe",
        "economy_cheat.exe", "money_grant.exe", "economy_granter.exe", "altv_money_drop.exe",
        "money_spawner.exe", "wealth_cheat.exe", "rich_hack.exe", "economy_trainer.exe",
        "max_money.exe", "infinite_cash.exe", "godmode_money.exe", "altv_rich.exe",
        "quick_cash.exe", "fast_money.exe", "money_boost.exe", "economy_mod.exe",
        "moneymod.exe", "cashmod.exe", "wealthmod.exe", "moneyloader.exe",
        "cashloader.exe", "moneyinjector.exe", "cashinjector.exe", "economymod.exe",
        "moneyspoof.exe", "cashspoof.exe", "wealthspoof.exe", "grantmoney.exe",
        "grantsuccess.exe", "moneygranter.exe", "altv_money_cheat.exe", "economy_hack_v2.exe",
        "money_drop_v2.exe", "cash_drop_v2.exe", "bank_hack_v2.exe", "altv_economy.exe",
        "cashflow_hack.exe",
    ];

    private static readonly string[] MoneyCheatDlls =
    [
        "money_inject.dll", "economy_hook.dll", "cash_bypass.dll", "bank_hook.dll",
        "money_hack.dll", "cash_hook.dll", "economy_bypass.dll", "altv_economy_dll.dll",
        "money_trainer.dll", "economy_trainer.dll", "cash_trainer.dll", "bank_bypass.dll",
        "grant_money.dll", "money_grant_dll.dll", "wealth_hook.dll", "infinite_cash_dll.dll",
        "max_money_dll.dll", "economy_inject.dll", "cash_inject_dll.dll", "money_spawner_dll.dll",
        "moneymod.dll", "cashmod.dll", "economymod.dll", "altv_money.dll",
        "economy_cheat.dll", "rich_hook.dll", "money_hook.dll", "money_evader.dll",
        "cash_evader.dll", "economy_evader.dll", "money_loader.dll", "cash_loader.dll",
        "economy_loader.dll", "bank_mod.dll", "wealth_mod.dll", "money_bypass.dll",
        "cash_bypass_v2.dll", "economy_bypass_v2.dll", "money_exploit.dll", "cash_exploit.dll",
    ];

    private static readonly string[] MoneyScriptKeywords =
    [
        "AddMoney", "SetMoney", "GiveMoney", "GrantMoney", "economy", "bank",
        "cashDrop", "moneyDrop", "infiniteMoney", "maxMoney", "setPlayerMoney",
        "grantCash", "setCash", "giveCash", "money_spawn", "cash_spawn",
        "bank_exploit", "economy_bypass", "money_hack", "grant_wealth",
    ];

    private static readonly string[] MoneyResourceFolderNames =
    [
        "money_drop", "cash_drop", "economy_cheat", "bank_hack", "money_hack",
        "give_money", "grant_money", "infinite_money", "max_money", "money_spawn",
        "cash_spawn", "money_trainer", "economy_trainer", "altv_economy", "altv_money",
        "cashmod", "moneymod", "economymod", "bank_bypass", "wealth_cheat",
        "quick_cash", "money_granter", "money_exploit", "economy_exploit", "cash_exploit",
        "bank_exploit", "money_loader", "cash_loader", "economy_loader", "money_inject",
        "cash_inject", "economy_inject", "money_evader", "cash_evader", "economy_evader",
        "altv_rich", "rich_mod", "wealth_mod", "money_bypass", "cash_bypass",
        "economy_bypass", "moneyspoof", "cashspoof", "wealthspoof", "richspoof",
        "economy_spoof", "bank_spoof", "money_cheat_v2", "cash_cheat_v2", "economy_cheat_v2",
    ];

    private static readonly string[] MoneyConfigFileNames =
    [
        "money_config.json", "economy_config.json", "cash_config.json",
        "bank_config.json", "grant_config.json", "money_offsets.txt",
        "cash_offsets.txt", "economy_offsets.txt", "bank_offsets.txt",
        "money_addresses.txt", "cash_addresses.txt", "economy_addresses.txt",
    ];

    private static readonly string[] MoneyConfigContentKeywords =
    [
        "money", "cash", "bank", "economy", "offset", "address", "amount", "grant",
    ];

    private static readonly string[] MoneyClientLogPatterns =
    [
        "money granted", "cash granted", "bank modified", "economy exploit",
        "givemoney", "grantmoney", "setmoney", "money_drop detected",
        "economy bypass", "bank_exploit", "infinite money", "max cash",
        "money hack", "cash hack", "economy hack", "player money set",
        "money value modified", "economy value modified", "bank balance modified",
        "cash value", "money: 999999", "cash: 999999", "balance: 999999",
        "money_spawn triggered", "cash_spawn triggered", "grant_success",
        "money_granted", "cash_granted", "bank_modified", "wallet_modified",
        "funds_modified", "balance_modified", "account_modified", "economy_triggered",
        "money_exploit_detected", "cash_exploit_detected", "economy_exploit_detected",
    ];

    private static readonly string[] MoneyServerLogPatterns =
    [
        "money exploit detected", "economy manipulation", "ban for money cheat",
        "money drop detected", "suspicious economy activity", "economy cheat detected",
        "cash exploit", "bank exploit", "money hack detected", "cash hack detected",
        "economy hack detected", "suspicious money grant", "suspicious cash grant",
        "economy bypass detected", "money value anomaly", "cash value anomaly",
        "economy value anomaly", "bank value anomaly", "anti-cheat: money",
        "ac: economy", "economy_kick", "money_kick", "cash_kick", "bank_kick",
        "economy_ban", "money_ban", "cash_ban", "bank_ban", "illegal money",
        "illegal cash", "money overflow", "cash overflow", "economy overflow",
        "money cap exceeded", "cash cap exceeded", "suspicious balance",
        "suspicious account", "suspicious wallet",
    ];

    private static readonly string[] MoneyDownloadArtifacts =
    [
        "altv_money_drop.zip", "altv_economy_hack.zip", "altv_cash_hack.zip",
        "altv_bank_hack.zip", "money_drop_altv.rar", "economy_cheat_altv.rar",
        "cash_cheat_altv.rar", "bank_cheat_altv.rar", "altv_money_cheat.zip",
        "altv_cash_drop.zip", "money_hack_altv.zip", "economy_hack_altv.zip",
        "altv_wealth_hack.zip", "altv_grant_money.zip", "altv_infinite_cash.zip",
        "altv_max_money.zip", "altv_money_trainer.zip", "altv_economy_trainer.zip",
        "altv_money_drop.rar", "altv_economy_hack.rar", "altv_cash_cheat.rar",
        "money_trainer_altv.zip", "economy_trainer_altv.zip", "cash_trainer_altv.zip",
        "altv_money_drop.7z", "altv_economy_hack.7z", "altv_bank_hack.7z",
        "money_spawn_altv.zip", "cash_spawn_altv.zip", "economy_spawn_altv.zip",
        "altv_money_setup.exe", "altv_economy_setup.exe", "altv_cash_setup.exe",
        "money_cheat_setup.exe", "economy_cheat_setup.exe", "cash_cheat_setup.exe",
        "altv_money_installer.exe", "altv_economy_installer.exe",
        "money_drop_installer.exe", "cash_drop_installer.exe",
        "economy_hack_installer.exe", "bank_hack_installer.exe",
        "altv_money_v2.zip", "altv_economy_v2.zip", "altv_cash_v2.zip",
    ];

    private static readonly string[] MoneyCheatRegistryKeys =
    [
        @"SOFTWARE\AltVMoney", @"SOFTWARE\AltVEconomy", @"SOFTWARE\AltVCash",
        @"SOFTWARE\AltVBank", @"SOFTWARE\MoneyDrop", @"SOFTWARE\CashDrop",
        @"SOFTWARE\EconomyCheat", @"SOFTWARE\BankHack", @"SOFTWARE\MoneyHack",
        @"SOFTWARE\CashHack", @"SOFTWARE\EconomyHack", @"SOFTWARE\GrantMoney",
        @"SOFTWARE\MoneySpawn", @"SOFTWARE\CashSpawn",
    ];

    private static readonly string[] MoneyCheatUserAssistNames =
    [
        "altv money", "altv economy", "altv cash", "altv bank", "money drop",
        "cash drop", "economy cheat", "bank hack", "money hack", "cash hack",
        "economy hack", "grant money", "money spawn", "cash spawn", "infinite money",
        "max money", "money trainer", "economy trainer", "cash trainer", "bank bypass",
        "altv_money", "altv_economy", "altv_cash", "altv_bank", "money_drop",
        "cash_drop", "economy_cheat", "bank_hack", "money_hack", "cash_hack",
        "economy_hack", "grant_money", "money_spawn", "cash_spawn", "infinite_money",
    ];

    private static readonly string[] MoneyCheatMuiCacheNames =
    [
        "altv money", "altv economy", "altv cash", "altv bank", "money drop",
        "cash drop", "economy cheat", "bank hack", "money hack", "economy hack",
        "grant money", "money spawn", "cash spawn", "money trainer", "cash trainer",
        "economy trainer", "bank bypass", "wealth cheat", "rich hack", "money granter",
        "cash granter", "economy granter", "money injector", "cash injector",
        "economy injector", "money loader", "cash loader", "economy loader",
        "money bypass", "cash bypass",
    ];

    private static readonly string[] AltVDataPaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "altv"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "altv"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "alt-v"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "alt-v"),
    ];

    private static readonly string[] AltVServerPaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "altv-server"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "alt-v-server"),
        @"C:\altv-server",
        @"C:\alt-v-server",
        @"C:\altv",
    ];

    private static readonly string[] MoneyCacheSubDirs =
    [
        "cache", "data", "storage", "local", "plugins", "modules",
    ];

    private static readonly string[] MoneyCheatBinaryKeywords =
    [
        "money_drop", "cash_drop", "economy_cheat", "grant_money", "give_money",
        "set_money", "add_money", "infinite_money", "max_money", "money_hack",
        "cash_hack", "economy_hack", "bank_hack", "money_bypass", "economy_bypass",
        "money_exploit", "cash_exploit", "economy_exploit", "bank_exploit",
        "money_inject", "cash_inject", "economy_inject", "money_spawn", "cash_spawn",
    ];

    private static readonly string[] MoneyAmcacheKeywords =
    [
        "altv_money", "altv_economy", "altv_cash", "altv_bank", "money_drop",
        "cash_drop", "economy_cheat", "bank_hack", "money_hack", "cash_hack",
        "grant_money", "money_spawn", "cash_spawn", "economy_exploit", "money_trainer",
        "cash_trainer", "economy_trainer", "money_granter", "cash_granter",
        "economy_granter", "money_injector", "cash_injector", "moneymod",
        "cashmod", "economymod", "money_bypass", "cash_bypass", "economy_bypass",
    ];

    private static readonly string[] MoneyLuaKeywords =
    [
        "AddMoney", "SetMoney", "GiveMoney", "GrantMoney", "economy", "bank",
        "cashDrop", "moneyDrop", "infiniteMoney", "maxMoney", "setPlayerMoney",
        "grantCash", "setCash", "giveCash", "money_spawn", "cash_spawn",
        "bank_exploit", "economy_bypass", "money_hack", "grant_wealth",
        "TriggerServerEvent", "money", "cash", "wallet", "balance",
    ];

    private static readonly string[] MoneyPackageArtifactPatterns =
    [
        "money-drop", "cash-drop", "economy-cheat", "bank-hack", "money-hack",
        "give-money", "grant-money", "infinite-money", "max-money", "money-spawn",
        "cash-spawn", "money-trainer", "economy-trainer", "altv-economy", "altv-money",
        "cashmod", "moneymod", "economymod", "bank-bypass", "wealth-cheat",
        "quick-cash", "money-granter", "money-exploit", "economy-exploit",
        "cash-exploit", "bank-exploit", "money-loader", "cash-loader",
        "economy-loader", "money-inject", "cash-inject", "economy-inject",
        "money-evader", "cash-evader", "economy-evader", "altv-rich",
        "rich-mod", "wealth-mod", "money-bypass", "cash-bypass",
        "economy-bypass", "moneyspoof", "cashspoof", "wealthspoof",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckAltVMoneyCheatExecutables(ctx, ct),
            CheckAltVMoneyCheatDlls(ctx, ct),
            CheckAltVMoneyScriptFiles(ctx, ct),
            CheckAltVMoneyResourceFolders(ctx, ct),
            CheckAltVMoneyConfigArtifacts(ctx, ct),
            CheckAltVMoneyClientLogs(ctx, ct),
            CheckAltVMoneyServerLogs(ctx, ct),
            CheckAltVMoneyDownloadArtifacts(ctx, ct),
            CheckRegistryKeysForAltVMoneyCheats(ctx, ct),
            CheckAltVMoneyInstallerRecords(ctx, ct)
        );
    }

    private Task CheckAltVMoneyCheatExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(AltVDataPaths)
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (MoneyCheatExecutables.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V money cheat executable: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known alt:V money/economy cheat executable '{fn}' found. " +
                                     "This tool is used to drop currency or manipulate the economy on alt:V servers.",
                            Detail = $"Path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVMoneyCheatDlls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new List<string>(AltVDataPaths)
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (MoneyCheatDlls.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V money cheat DLL: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known alt:V money/economy cheat DLL '{fn}' found. " +
                                     "This library is injected or loaded to manipulate in-game currency and economy values.",
                            Detail = $"Path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVMoneyScriptFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scriptDirs = new List<string>();
        foreach (var root in AltVDataPaths)
        {
            scriptDirs.Add(root);
            scriptDirs.Add(Path.Combine(root, "resources"));
            scriptDirs.Add(Path.Combine(root, "packages"));
        }

        var scriptExtensions = new[] { "*.js", "*.mjs", "*.cjs", "*.ts" };

        foreach (var dir in scriptDirs)
        {
            if (!Directory.Exists(dir)) continue;
            foreach (var ext in scriptExtensions)
            {
                IEnumerable<string> files;
                try
                {
                    files = Directory.EnumerateFiles(dir, ext, SearchOption.AllDirectories);
                }
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

                    int hits = 0;
                    var matchedKeywords = new List<string>();
                    foreach (var keyword in MoneyScriptKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            hits++;
                            matchedKeywords.Add(keyword);
                        }
                    }

                    if (hits >= 3)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V money cheat script: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = Path.GetFileName(file),
                            Reason = $"Script file contains {hits} money/economy cheat API patterns " +
                                     $"({string.Join(", ", matchedKeywords.Take(5))}). " +
                                     "Such scripts are used to grant unlimited currency on alt:V servers.",
                            Detail = $"Path: {file} | Matched: {string.Join("|", matchedKeywords)}",
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckAltVMoneyResourceFolders(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var root in AltVDataPaths)
        {
            var resourcesDirs = new[]
            {
                Path.Combine(root, "resources"),
                Path.Combine(root, "packages"),
            };

            foreach (var baseDir in resourcesDirs)
            {
                if (!Directory.Exists(baseDir)) continue;
                try
                {
                    foreach (var dir in Directory.EnumerateDirectories(baseDir, "*", SearchOption.TopDirectoryOnly))
                    {
                        ct.ThrowIfCancellationRequested();
                        var folderName = Path.GetFileName(dir);
                        if (MoneyResourceFolderNames.Any(n => folderName.Equals(n, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V money cheat resource folder: {folderName}",
                                Risk = RiskLevel.High,
                                Location = baseDir,
                                FileName = folderName,
                                Reason = $"alt:V resource or package folder '{folderName}' matches a known money/economy cheat resource name. " +
                                         "These resources are loaded by alt:V and grant players currency or bypass economy checks.",
                                Detail = $"Path: {dir}",
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckAltVMoneyConfigArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var scanDirs = new List<string>(AltVDataPaths)
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    var fn = Path.GetFileName(file);
                    if (!MoneyConfigFileNames.Any(n => fn.Equals(n, StringComparison.OrdinalIgnoreCase)))
                        continue;

                    ctx.IncrementFiles();
                    string content;
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    var lower = content.ToLowerInvariant();
                    var foundKeywords = MoneyConfigContentKeywords
                        .Where(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (foundKeywords.Count >= 2)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V money cheat config file: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Configuration file '{fn}' contains money/economy cheat keywords " +
                                     $"({string.Join(", ", foundKeywords)}). " +
                                     "This file is used to configure offset addresses or grant amounts for economy manipulation.",
                            Detail = $"Path: {file} | Keywords: {string.Join("|", foundKeywords)}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVMoneyClientLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        foreach (var altVDir in AltVDataPaths)
        {
            if (!Directory.Exists(altVDir)) continue;
            IEnumerable<string> logFiles;
            try
            {
                logFiles = Directory.EnumerateFiles(altVDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(altVDir, "*.txt", SearchOption.AllDirectories));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

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

                var lower = content.ToLowerInvariant();
                foreach (var pattern in MoneyClientLogPatterns)
                {
                    if (lower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V client log: money cheat evidence",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(logFile) ?? altVDir,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"alt:V client log contains money cheat pattern '{pattern}'. " +
                                     "This indicates economy manipulation or currency drop activity was logged on this client.",
                            Detail = $"Log: {logFile} | Pattern: {pattern}",
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckAltVMoneyServerLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var serverLogDirs = new List<string>();
        foreach (var serverPath in AltVServerPaths)
        {
            serverLogDirs.Add(Path.Combine(serverPath, "logs"));
            serverLogDirs.Add(serverPath);
        }

        foreach (var logDir in serverLogDirs)
        {
            if (!Directory.Exists(logDir)) continue;
            IEnumerable<string> logFiles;
            try
            {
                logFiles = Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(logDir, "*.txt", SearchOption.AllDirectories));
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

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

                var lower = content.ToLowerInvariant();
                foreach (var pattern in MoneyServerLogPatterns)
                {
                    if (lower.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V server log: money exploit evidence",
                            Risk = RiskLevel.High,
                            Location = logDir,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"alt:V server log records money/economy exploit activity: '{pattern}'. " +
                                     "Server-side logs recording this pattern indicate the player was involved in economy manipulation.",
                            Detail = $"Log: {logFile} | Pattern: {pattern}",
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckAltVMoneyDownloadArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        };

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (MoneyDownloadArtifacts.Any(a => fn.Equals(a, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V money cheat download artifact: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Cheat archive or installer '{fn}' found in user download/desktop area. " +
                                     "This is a known alt:V money drop or economy manipulation tool package.",
                            Detail = $"Path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRegistryKeysForAltVMoneyCheats(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var keyPath in MoneyCheatRegistryKeys)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.CurrentUser.OpenSubKey(keyPath);
                if (key != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V money cheat registry key: {keyPath}",
                        Risk = RiskLevel.High,
                        Location = @"HKCU\" + keyPath,
                        FileName = string.Empty,
                        Reason = $"Registry key '{keyPath}' under HKCU was left by an alt:V money or economy cheat tool installation.",
                        Detail = $"Key: HKCU\\{keyPath}",
                    });
                }
            }
            catch (Exception) { }

            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                if (key != null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V money cheat registry key (HKLM): {keyPath}",
                        Risk = RiskLevel.High,
                        Location = @"HKLM\" + keyPath,
                        FileName = string.Empty,
                        Reason = $"Registry key '{keyPath}' under HKLM was left by an alt:V money or economy cheat tool.",
                        Detail = $"Key: HKLM\\{keyPath}",
                    });
                }
            }
            catch (Exception) { }
        }

        // Scan Run/RunOnce keys for money cheat persistence
        var runPaths = new[]
        {
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.CurrentUser),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.CurrentUser),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", Registry.LocalMachine),
            (@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", Registry.LocalMachine),
        };

        foreach (var (runPath, hive) in runPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ctx.IncrementRegistryKeys();
                using var run = hive.OpenSubKey(runPath);
                if (run == null) continue;
                foreach (var valName in run.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var data = run.GetValue(valName)?.ToString() ?? string.Empty;
                    var lower = data.ToLowerInvariant();
                    bool isMoneyCheat = MoneyCheatExecutables.Any(e => lower.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase))
                        || lower.Contains("money cheat") || lower.Contains("economy hack")
                        || lower.Contains("cash drop") || lower.Contains("money drop")
                        || lower.Contains("bank hack") || lower.Contains("grant money");
                    if (isMoneyCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V money cheat autostart (Run key)",
                            Risk = RiskLevel.High,
                            Location = (hive == Registry.CurrentUser ? "HKCU" : "HKLM") + @"\" + runPath,
                            FileName = valName,
                            Reason = $"Run registry key '{valName}' references an alt:V money/economy cheat tool. " +
                                     "The cheat was configured to launch automatically at logon.",
                            Detail = $"Value: {valName} = {data}",
                        });
                    }
                }
            }
            catch (Exception) { }
        }

        // UserAssist ROT13 check for money cheat execution history
        const string uaPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        try
        {
            using var ua = Registry.CurrentUser.OpenSubKey(uaPath);
            if (ua != null)
            {
                foreach (var guidName in ua.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var count = Registry.CurrentUser.OpenSubKey($@"{uaPath}\{guidName}\Count");
                        if (count == null) continue;
                        foreach (var valName in count.GetValueNames())
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementRegistryKeys();
                            var decoded = Rot13Decode(valName).ToLowerInvariant();
                            bool isMoneyCheat = MoneyCheatUserAssistNames.Any(n => decoded.Contains(n, StringComparison.OrdinalIgnoreCase))
                                || MoneyCheatExecutables.Any(e => decoded.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase));
                            if (isMoneyCheat)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "alt:V money cheat execution (UserAssist)",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKCU\{uaPath}\{guidName}\Count",
                                    FileName = decoded,
                                    Reason = $"UserAssist registry records execution of alt:V money/economy cheat tool: '{decoded}'. " +
                                             "UserAssist entries prove the executable was launched by this user account.",
                                    Detail = $"ROT13 decoded: {decoded} | Raw: {valName}",
                                });
                            }
                        }
                    }
                    catch (Exception) { }
                }
            }
        }
        catch (Exception) { }

        // MUICache check for economy cheat execution
        var muiPaths = new[]
        {
            @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
            @"SOFTWARE\Microsoft\Windows\ShellNoRoam\MUICache",
        };
        foreach (var muiPath in muiPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var mui = Registry.CurrentUser.OpenSubKey(muiPath);
                if (mui == null) continue;
                foreach (var valName in mui.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    var lower = valName.ToLowerInvariant();
                    bool isMoneyCheat = MoneyCheatMuiCacheNames.Any(n => lower.Contains(n, StringComparison.OrdinalIgnoreCase))
                        || MoneyCheatExecutables.Any(e => lower.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase));
                    if (isMoneyCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V money cheat execution (MUICache)",
                            Risk = RiskLevel.High,
                            Location = @"HKCU\" + muiPath,
                            FileName = Path.GetFileName(valName),
                            Reason = $"MUICache records execution of alt:V money/economy cheat: '{Path.GetFileName(valName)}'. " +
                                     "MUICache stores application display names for recently launched executables.",
                            Detail = $"Entry: {valName}",
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckAltVMoneyInstallerRecords(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var uninstallPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        };

        var cheatNameKeywords = new[]
        {
            "money cheat", "money drop", "cash drop", "economy cheat", "bank hack",
            "money hack", "economy hack", "grant money", "cash hack", "money trainer",
            "economy trainer", "cash trainer", "altv money", "altv economy", "altv cash",
            "altv bank", "money spawn", "cash spawn", "wealth cheat", "rich hack",
            "infinite money", "max money", "money granter", "cash granter",
            "economy granter", "money injector", "cash injector", "money bypass",
            "cash bypass", "economy bypass",
        };

        foreach (var uninstallPath in uninstallPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var uninst = Registry.LocalMachine.OpenSubKey(uninstallPath);
                if (uninst == null) continue;
                foreach (var subKeyName in uninst.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    try
                    {
                        using var sub = uninst.OpenSubKey(subKeyName);
                        if (sub == null) continue;
                        var displayName = sub.GetValue("DisplayName")?.ToString() ?? string.Empty;
                        var lower = displayName.ToLowerInvariant();
                        if (cheatNameKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V money cheat installer record: {displayName}",
                                Risk = RiskLevel.High,
                                Location = $@"HKLM\{uninstallPath}\{subKeyName}",
                                FileName = displayName,
                                Reason = $"Windows uninstall record found for alt:V money/economy cheat software '{displayName}'. " +
                                         "This proves the cheat was formally installed on this system.",
                                Detail = $"Key: {subKeyName} | DisplayName: {displayName}",
                            });
                        }
                    }
                    catch (Exception) { }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckAltVMoneyLuaScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var resourceDirs = new List<string>();
        foreach (var root in AltVDataPaths)
        {
            resourceDirs.Add(Path.Combine(root, "resources"));
            resourceDirs.Add(Path.Combine(root, "packages"));
        }

        foreach (var dir in resourceDirs)
        {
            if (!Directory.Exists(dir)) continue;
            IEnumerable<string> luaFiles;
            try
            {
                luaFiles = Directory.EnumerateFiles(dir, "*.lua", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in luaFiles)
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

                int hits = 0;
                var matchedKeywords = new List<string>();
                foreach (var keyword in MoneyLuaKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        hits++;
                        matchedKeywords.Add(keyword);
                    }
                }

                if (hits >= 5)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V money cheat Lua script: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = Path.GetDirectoryName(file) ?? dir,
                        FileName = Path.GetFileName(file),
                        Reason = $"Lua script contains {hits} money/economy cheat API patterns " +
                                 $"({string.Join(", ", matchedKeywords.Take(5))}). " +
                                 "Such scripts manipulate in-game money, wallet balances, or bank values via server events.",
                        Detail = $"Path: {file} | Matched: {string.Join("|", matchedKeywords)}",
                    });
                }
            }
        }
    }, ct);

    private Task CheckAltVMoneyCacheDirs(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        foreach (var root in AltVDataPaths)
        {
            foreach (var sub in MoneyCacheSubDirs)
            {
                var subDir = Path.Combine(root, sub);
                if (!Directory.Exists(subDir)) continue;
                try
                {
                    foreach (var file in Directory.EnumerateFiles(subDir, "*.dll", SearchOption.AllDirectories)
                        .Concat(Directory.EnumerateFiles(subDir, "*.exe", SearchOption.AllDirectories)))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        var fn = Path.GetFileName(file);
                        bool isMoneyCheat = MoneyCheatExecutables.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase))
                            || MoneyCheatDlls.Any(d => fn.Equals(d, StringComparison.OrdinalIgnoreCase))
                            || MoneyCheatBinaryKeywords.Any(k => fn.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (isMoneyCheat)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V money cheat binary in cache: {fn}",
                                Risk = RiskLevel.High,
                                Location = subDir,
                                FileName = fn,
                                Reason = $"Money/economy cheat binary '{fn}' found in alt:V cache or data subdirectory '{sub}'. " +
                                         "Cheats are sometimes stored in cache directories to evade detection in main folders.",
                                Detail = $"Path: {file}",
                            });
                        }
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckAltVMoneyAmcacheArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var amcachePaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages",
        };

        foreach (var amPath in amcachePaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.LocalMachine.OpenSubKey(amPath);
                if (key == null) continue;
                foreach (var subName in key.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var lower = subName.ToLowerInvariant();
                    if (MoneyAmcacheKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V money cheat in App Repository: {subName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{amPath}\{subName}",
                            FileName = subName,
                            Reason = $"App model repository entry '{subName}' matches known alt:V money/economy cheat tool name. " +
                                     "This indicates the cheat was registered as an application package on this system.",
                            Detail = $"Key: HKLM\\{amPath}\\{subName}",
                        });
                    }
                }
            }
            catch (Exception) { }
        }

        // Also scan HKCU Software subkeys for money cheat tool registrations
        try
        {
            ctx.IncrementRegistryKeys();
            using var softKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE");
            if (softKey != null)
            {
                foreach (var subName in softKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var lower = subName.ToLowerInvariant();
                    if (MoneyAmcacheKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V money cheat HKCU Software key: {subName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\SOFTWARE\{subName}",
                            FileName = subName,
                            Reason = $"HKCU\\SOFTWARE\\{subName} matches a known alt:V money/economy cheat tool name. " +
                                     "Cheat tools often write configuration or license keys under HKCU\\Software.",
                            Detail = $"Key: HKCU\\SOFTWARE\\{subName}",
                        });
                    }
                }
            }
        }
        catch (Exception) { }

        // Scan HKLM Software for money cheat registrations
        try
        {
            ctx.IncrementRegistryKeys();
            using var softKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE");
            if (softKey != null)
            {
                foreach (var subName in softKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var lower = subName.ToLowerInvariant();
                    if (MoneyAmcacheKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.IncrementRegistryKeys();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V money cheat HKLM Software key: {subName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\SOFTWARE\{subName}",
                            FileName = subName,
                            Reason = $"HKLM\\SOFTWARE\\{subName} matches a known alt:V money/economy cheat tool name. " +
                                     "System-wide registrations under HKLM indicate a privileged or persistent cheat installation.",
                            Detail = $"Key: HKLM\\SOFTWARE\\{subName}",
                        });
                    }
                }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckAltVMoneyRecentDocuments(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var recentDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "Windows", "Recent");

        if (!Directory.Exists(recentDir)) return;

        try
        {
            foreach (var lnk in Directory.EnumerateFiles(recentDir, "*.lnk", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileNameWithoutExtension(lnk).ToLowerInvariant();
                bool isMoneyCheat = MoneyCheatExecutables.Any(e => fn.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase))
                    || MoneyDownloadArtifacts.Any(a =>
                        fn.Contains(a.Replace(".zip", "").Replace(".rar", "").Replace(".7z", "").Replace(".exe", ""),
                            StringComparison.OrdinalIgnoreCase))
                    || MoneyCheatBinaryKeywords.Any(k => fn.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (isMoneyCheat)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V money cheat recent document: {Path.GetFileName(lnk)}",
                        Risk = RiskLevel.Medium,
                        Location = recentDir,
                        FileName = Path.GetFileName(lnk),
                        Reason = $"Recent Documents shortcut '{fn}' points to an alt:V money/economy cheat file. " +
                                 "Recent Documents links are created when a file is opened by the user.",
                        Detail = $"Shortcut: {lnk}",
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckAltVMoneyTempArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var tempDirs = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        foreach (var tempDir in tempDirs)
        {
            if (!Directory.Exists(tempDir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(tempDir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    bool isMoneyCheat = MoneyCheatExecutables.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase))
                        || MoneyCheatDlls.Any(d => fn.Equals(d, StringComparison.OrdinalIgnoreCase))
                        || MoneyDownloadArtifacts.Any(a => fn.Equals(a, StringComparison.OrdinalIgnoreCase));

                    if (isMoneyCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"alt:V money cheat artifact in Temp: {fn}",
                            Risk = RiskLevel.High,
                            Location = tempDir,
                            FileName = fn,
                            Reason = $"Known alt:V money/economy cheat artifact '{fn}' found in system Temp directory. " +
                                     "Cheats often extract or stage components in Temp before loading them.",
                            Detail = $"Path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVMoneyPrefetchArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir)) return;

        try
        {
            foreach (var pf in Directory.EnumerateFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fn = Path.GetFileNameWithoutExtension(pf).ToLowerInvariant();
                bool isMoneyCheat = MoneyCheatExecutables.Any(e =>
                    fn.StartsWith(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase))
                    || MoneyCheatBinaryKeywords.Any(k => fn.Contains(k, StringComparison.OrdinalIgnoreCase));

                if (isMoneyCheat)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"alt:V money cheat prefetch artifact: {Path.GetFileName(pf)}",
                        Risk = RiskLevel.High,
                        Location = prefetchDir,
                        FileName = Path.GetFileName(pf),
                        Reason = $"Windows Prefetch file '{Path.GetFileName(pf)}' indicates past execution of an alt:V money/economy cheat. " +
                                 "Prefetch files are created by Windows for each launched executable and persist after deletion.",
                        Detail = $"Prefetch: {pf}",
                    });
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }, ct);

    private Task CheckAltVMoneyPackageManifests(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var manifestFileNames = new[] { "resource.cfg", "resource.toml", "manifest.json", "package.json" };

        foreach (var root in AltVDataPaths)
        {
            var searchDirs = new[]
            {
                Path.Combine(root, "resources"),
                Path.Combine(root, "packages"),
            };

            foreach (var dir in searchDirs)
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var manifestName in manifestFileNames)
                {
                    IEnumerable<string> manifests;
                    try
                    {
                        manifests = Directory.EnumerateFiles(dir, manifestName, SearchOption.AllDirectories);
                    }
                    catch (UnauthorizedAccessException) { continue; }
                    catch (IOException) { continue; }

                    foreach (var manifest in manifests)
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        string content;
                        try
                        {
                            using var fs = new FileStream(manifest, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            content = await sr.ReadToEndAsync(ct);
                        }
                        catch (IOException) { continue; }

                        var lower = content.ToLowerInvariant();
                        bool hasMoneyCheatPattern = MoneyPackageArtifactPatterns
                            .Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (hasMoneyCheatPattern)
                        {
                            var matched = MoneyPackageArtifactPatterns
                                .Where(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                                .Take(3)
                                .ToList();
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V money cheat manifest: {Path.GetFileName(manifest)}",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(manifest) ?? dir,
                                FileName = Path.GetFileName(manifest),
                                Reason = $"Resource manifest '{Path.GetFileName(manifest)}' contains money/economy cheat references " +
                                         $"({string.Join(", ", matched)}). " +
                                         "Cheat resources declare themselves in manifest files which are loaded by the alt:V runtime.",
                                Detail = $"Path: {manifest} | Patterns: {string.Join("|", matched)}",
                            });
                        }
                    }
                }
            }
        }
    }, ct);

    private Task CheckAltVMoneyJumplistArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var recentDirs = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", "Windows", "Recent", "AutomaticDestinations"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Microsoft", "Windows", "Recent", "CustomDestinations"),
        };

        foreach (var dir in recentDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    // Jumplist filenames encode application IDs; we look for suspiciously named dest files
                    // by reading their file size. Content parsing is binary; filename check is sufficient.
                    var fi = new FileInfo(file);
                    if (fi.Length < 100) continue;

                    // Read a small header slice to look for cheat name strings
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        var buf = new byte[Math.Min(4096, fi.Length)];
                        int read = fs.Read(buf, 0, buf.Length);
                        var text = System.Text.Encoding.Unicode.GetString(buf, 0, read);
                        var lower = text.ToLowerInvariant();
                        bool hasMoneyRef = MoneyCheatBinaryKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                            || MoneyCheatExecutables.Any(e => lower.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase));
                        if (hasMoneyRef)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"alt:V money cheat jumplist artifact: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Medium,
                                Location = dir,
                                FileName = Path.GetFileName(file),
                                Reason = "Windows Jumplist/AutomaticDestinations file references alt:V money cheat tool strings. " +
                                         "Jumplist files record recently opened files and applications.",
                                Detail = $"Path: {file}",
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckAltVMoneyAppCompatCache(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        // AppCompatCache (ShimCache) is stored in registry and records executed binaries
        var shimCachePaths = new[]
        {
            @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
            @"SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache",
        };

        foreach (var shimPath in shimCachePaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.LocalMachine.OpenSubKey(shimPath);
                if (key == null) continue;

                // AppCompatCache value is binary; convert to string for substring scanning
                var cacheData = key.GetValue("AppCompatCache") as byte[];
                if (cacheData == null) continue;

                var cacheText = System.Text.Encoding.Unicode.GetString(cacheData).ToLowerInvariant();
                foreach (var keyword in MoneyAmcacheKeywords)
                {
                    if (cacheText.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V money cheat in AppCompatCache (ShimCache)",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{shimPath}",
                            FileName = keyword,
                            Reason = $"AppCompatCache (ShimCache) contains reference to alt:V money cheat keyword '{keyword}'. " +
                                     "ShimCache records all executables that have been run on the system, surviving reboots.",
                            Detail = $"Key: HKLM\\{shimPath} | Keyword: {keyword}",
                        });
                        break;
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private Task CheckAltVMoneyNetworkArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        // Check Windows Firewall rules for money cheat tool exceptions
        try
        {
            ctx.IncrementRegistryKeys();
            using var fwKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules");
            if (fwKey != null)
            {
                foreach (var valName in fwKey.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    var data = fwKey.GetValue(valName)?.ToString() ?? string.Empty;
                    var lower = data.ToLowerInvariant();
                    bool isMoneyCheat = MoneyCheatBinaryKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                        || MoneyCheatExecutables.Any(e => lower.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase));
                    if (isMoneyCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V money cheat firewall exception",
                            Risk = RiskLevel.High,
                            Location = @"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
                            FileName = valName,
                            Reason = "Windows Firewall contains an exception rule referencing an alt:V money/economy cheat tool. " +
                                     "Cheat tools add firewall exceptions to allow outbound connections to cheat servers.",
                            Detail = $"Rule: {valName} = {data.Substring(0, Math.Min(200, data.Length))}",
                        });
                    }
                }
            }
        }
        catch (Exception) { }
    }, ct);

    private Task CheckAltVMoneyWindowsDefenderExclusions(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var exclusionPaths = new[]
        {
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
            @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
        };

        foreach (var exPath in exclusionPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                ctx.IncrementRegistryKeys();
                using var key = Registry.LocalMachine.OpenSubKey(exPath);
                if (key == null) continue;
                foreach (var valName in key.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementRegistryKeys();
                    var lower = valName.ToLowerInvariant();
                    bool isMoneyCheat = MoneyCheatBinaryKeywords.Any(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                        || MoneyCheatExecutables.Any(e => lower.Contains(e.Replace(".exe", ""), StringComparison.OrdinalIgnoreCase))
                        || lower.Contains("money") || lower.Contains("economy") || lower.Contains("cash");
                    if (isMoneyCheat)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "alt:V money cheat in Defender exclusions",
                            Risk = RiskLevel.High,
                            Location = $@"HKLM\{exPath}",
                            FileName = Path.GetFileName(valName),
                            Reason = $"Windows Defender exclusion references alt:V money/economy cheat path or process '{valName}'. " +
                                     "Adding Defender exclusions is a common cheat evasion technique to prevent AV detection.",
                            Detail = $"Exclusion: {valName}",
                        });
                    }
                }
            }
            catch (Exception) { }
        }
    }, ct);

    private static string Rot13Decode(string s)
    {
        return new string(s.Select(c =>
            c >= 'a' && c <= 'z' ? (char)('a' + (c - 'a' + 13) % 26) :
            c >= 'A' && c <= 'Z' ? (char)('A' + (c - 'A' + 13) % 26) : c).ToArray());
    }
}
