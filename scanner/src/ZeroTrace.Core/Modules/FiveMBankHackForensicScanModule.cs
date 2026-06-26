using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Util;

namespace ZeroTrace.Core.Modules;

public sealed class FiveMBankHackForensicScanModule : IScanModule
{
    public string Name => "FiveM Bank-Hack Forensik";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    private static readonly string[] BankHackFilePatterns =
    {
        "bankHack*", "bankExploit*", "robber_script*", "bank_rob_exploit*",
        "economy_hack*", "money_exploit_bank*", "qb_bank_hack*", "esx_bank_exploit*",
        "bank_bypass*", "bank_cheat*", "bank_dupe*", "economy_dupe*",
        "money_hack_fivem*", "fivem_bank*", "bank_money_hack*", "robbery_exploit*",
        "economy_exploit*", "qb_banking_hack*", "esx_banking_exploit*", "bank_rob*"
    };

    private static readonly string[] BankHackLogKeywords =
    {
        "bank hack", "bank exploit", "robbery exploit", "economy hack",
        "bank money", "bank rob script", "bank bypass", "unlimited money bank",
        "bank_hack", "bank_exploit", "rob_bank", "economy_exploit",
        "money dupe bank", "banking exploit", "fivem bank cheat",
        "qb bank hack", "esx bank exploit", "bank robbery cheat",
        "addmoney exploit", "givemoney exploit", "bank balance dupe"
    };

    private static readonly string[] BankHackScriptKeywords =
    {
        "AddMoney", "GiveMoney", "bank_hack", "rob_bank bypass",
        "economy exploit", "RemoveMoneyBank bypass", "bank.addBalance",
        "addBalance bypass", "setMoney bypass", "banking:addMoney",
        "banking:withdraw", "bank:addMoney", "esx:addMoney",
        "qb:AddMoney", "MoneyExploit", "BankExploit", "EconomyHack",
        "TriggerServerEvent('banking:addMoney')", "TriggerServerEvent(\"banking:addMoney\")",
        "exports.oxmysql", "money dupe", "bank.addBalance bypass",
        "banking.addCash", "banking:rob", "robbery:start bypass",
        "heist:bank bypass", "bank_robbery_bypass"
    };

    private static readonly string[] LuaEconomyPatterns =
    {
        "TriggerServerEvent('banking:addMoney')",
        "TriggerServerEvent(\"banking:addMoney\")",
        "TriggerServerEvent('esx:addMoney')",
        "TriggerServerEvent(\"esx:addMoney\")",
        "TriggerServerEvent('qb:AddMoney')",
        "TriggerServerEvent(\"qb:AddMoney\")",
        "exports.oxmysql",
        "money dupe",
        "bank.addBalance bypass",
        "banking:addCash",
        "banking:withdraw bypass",
        "esx_banking:addMoney",
        "addBalance(",
        "setAccountMoney(",
        "bank_bypass",
        "rob_bank exploit",
        "economy_hack",
        "RemoveMoney bypass",
        "AddMoney bypass",
        "GiveMoney bypass",
        "heist_bypass",
        "robbery_bypass",
        "bank_rob_bypass",
        "qb-banking exploit",
        "esx-banking exploit"
    };

    private static readonly string[] DiscordBankHackKeywords =
    {
        "fivem bank hack", "bank exploit fivem", "economy hack",
        "bank rob script", "money exploit fivem", "qb bank hack",
        "esx bank exploit", "bank bypass fivem", "economy exploit fivem",
        "fivem money hack", "bank dupe fivem", "robbery exploit fivem",
        "banking exploit", "fivem economy cheat", "bank cheat fivem",
        "give money fivem", "add money exploit", "unlimited money fivem"
    };

    private static readonly string[] KnownBankHackExeNames =
    {
        "BankHack.exe", "BankExploit.exe", "EconomyHack.exe", "MoneyExploitBank.exe",
        "QBBankHack.exe", "ESXBankExploit.exe", "BankBypass.exe", "RobberyExploit.exe",
        "BankRobExploit.exe", "FiveMBankHack.exe", "BankMoneyHack.exe",
        "EconomyExploit.exe", "BankDupe.exe", "MoneyDupe.exe", "BankRob.exe",
        "FiveMEconomyHack.exe", "BankScript.exe", "RobBank.exe", "BankCheat.exe"
    };

    private static readonly string[] CefCacheKeywords =
    {
        "bank_hack", "bankExploit", "addMoney", "addBalance", "bank_bypass",
        "economy_hack", "money_dupe", "robbery_exploit", "banking:addMoney",
        "rob_bank", "esx_bank", "qb_bank", "bank_cheat", "economy_exploit"
    };

    private static readonly string[] DatabaseManipulationKeywords =
    {
        "UPDATE accounts SET", "UPDATE bank SET", "UPDATE player_accounts SET",
        "INSERT INTO bank", "UPDATE ox_bank SET", "UPDATE qb_bank SET",
        "UPDATE esx_billing SET", "UPDATE fivem_banking SET",
        "addMoney(", "addBankMoney(", "addCash(", "setMoney(",
        "UPDATE users SET money", "UPDATE characters SET money",
        "bank_exploit", "economy_dupe", "money_inject"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starte FiveM Bank-Hack Forensik-Scan...");

        await Task.WhenAll(
            CheckCitizenFxAppDataFiles(ctx, ct),
            CheckFiveMCacheDirs(ctx, ct),
            CheckLogFilesForBankHackKeywords(ctx, ct),
            CheckFiveMResourceDirScripts(ctx, ct),
            CheckRegistryBankHackKeys(ctx, ct),
            CheckPrefetchBankHackExecutables(ctx, ct),
            CheckUserAssistBankHackTools(ctx, ct),
            CheckDiscordArtifactsBankHack(ctx, ct),
            CheckLuaJsEconomyManipulationFiles(ctx, ct),
            CheckTempScriptFiles(ctx, ct),
            CheckCefBrowserCacheBankHack(ctx, ct),
            CheckDatabaseManipulationScripts(ctx, ct),
            CheckKnownBankHackExecutables(ctx, ct),
            CheckFiveMResourceFolderBankKeywords(ctx, ct),
            CheckESXQBFrameworkFiles(ctx, ct)
        );

        ctx.Report(1.0, Name, "FiveM Bank-Hack Forensik-Scan abgeschlossen.");
    }

    private Task CheckCitizenFxAppDataFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var roaming = KnownPaths.RoamingAppData;
        var citizenFxDir = Path.Combine(roaming, "citizenfx");

        if (!Directory.Exists(citizenFxDir))
            return;

        foreach (var pattern in BankHackFilePatterns)
        {
            ct.ThrowIfCancellationRequested();
            string[] matches;
            try
            {
                matches = Directory.GetFiles(citizenFxDir, pattern, SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in matches)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                try
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Bank-Hack Datei in CitizenFX AppData: {Path.GetFileName(file)}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Datei mit bank-hack-typischem Namensschema gefunden in %APPDATA%\\citizenfx\\. " +
                                 $"Dateimuster '{pattern}' entspricht bekannten FiveM Bank-Exploit-Tools. " +
                                 "Diese Dateien deuten auf den Einsatz von Bank-Hack- oder Economy-Exploit-Werkzeugen hin."
                    });
                }
                catch (IOException) { }
            }
        }

        var allCfxFiles = Array.Empty<string>();
        try
        {
            allCfxFiles = Directory.GetFiles(citizenFxDir, "*", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException) { }

        foreach (var file in allCfxFiles)
        {
            ct.ThrowIfCancellationRequested();
            var name = Path.GetFileName(file);
            if (ContainsBankHackKeywordInName(name))
            {
                ctx.IncrementFiles();
                try
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Verdaechtige Bank-Hack-Datei: {name}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = name,
                        Reason = $"Dateiname '{name}' enthaelt bank-hack-relevante Schluesselwoerter im CitizenFX-Verzeichnis. " +
                                 "Typischer Artifact-Fund nach Verwendung von FiveM Economy- oder Bank-Exploit-Tools."
                    });
                }
                catch (IOException) { }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMCacheDirs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var local = KnownPaths.LocalAppData;
        var roaming = KnownPaths.RoamingAppData;

        var cacheDirs = new[]
        {
            Path.Combine(local, "FiveM", "FiveM.app", "cache"),
            Path.Combine(local, "FiveM", "FiveM.app", "citizen", "cache"),
            Path.Combine(local, "FiveM", "FiveM.app", "data", "cache"),
            Path.Combine(local, "FiveM", "cache"),
            Path.Combine(roaming, "citizenfx", "cache"),
            Path.Combine(roaming, "citizenfx"),
        };

        foreach (var cacheDir in cacheDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(cacheDir))
                continue;

            foreach (var pattern in BankHackFilePatterns)
            {
                ct.ThrowIfCancellationRequested();
                string[] matches;
                try
                {
                    matches = Directory.GetFiles(cacheDir, pattern, SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in matches)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Bank-Hack-Datei in FiveM Cache: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Datei mit bank-hack-typischem Namensschema '{pattern}' im FiveM-Cache-Verzeichnis gefunden. " +
                                     "Cache-Verzeichnisse werden von FiveM-Cheats haeufig als Ablageort fuer exploit-bezogene Dateien genutzt."
                        });
                    }
                    catch (IOException) { }
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckLogFilesForBankHackKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var roaming = KnownPaths.RoamingAppData;
        var local = KnownPaths.LocalAppData;

        var logDirs = new[]
        {
            Path.Combine(roaming, "citizenfx"),
            Path.Combine(local, "FiveM"),
            Path.Combine(local, "FiveM", "FiveM.app"),
            Path.Combine(local, "FiveM", "FiveM.app", "logs"),
            Path.Combine(roaming, "citizenfx", "logs"),
            KnownPaths.Temp,
            Path.Combine(local, "Temp")
        };

        var logExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".log", ".txt", ".cfg", ".ini", ".json", ".xml"
        };

        foreach (var dir in logDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] logFiles;
            try
            {
                logFiles = Directory.GetFiles(dir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in logFiles)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!logExtensions.Contains(ext))
                    continue;

                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var keyword in BankHackLogKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Bank-Hack-Schluesselwort in Log-Datei: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Log-Datei enthaelt das Schluesselwort '{keyword}', das auf den Einsatz von " +
                                         "FiveM Bank-Hack- oder Economy-Exploit-Tools hinweist. " +
                                         "Solche Eintraege werden von cheat-seitigen Logging-Komponenten hinterlassen."
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckFiveMResourceDirScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var local = KnownPaths.LocalAppData;
        var fivemRoot = KnownPaths.FindFiveMDirectory();

        var resourceDirs = new List<string>();
        if (fivemRoot != null)
        {
            resourceDirs.Add(Path.Combine(fivemRoot, "resources"));
            resourceDirs.Add(Path.Combine(fivemRoot, "citizen", "resources"));
            resourceDirs.Add(Path.Combine(fivemRoot, "FiveM.app", "resources"));
            resourceDirs.Add(fivemRoot);
        }

        resourceDirs.Add(Path.Combine(local, "FiveM", "FiveM.app", "resources"));
        resourceDirs.Add(Path.Combine(local, "FiveM", "resources"));

        var scriptExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".lua", ".luac", ".js", ".json", ".cfg", ".cs", ".ts"
        };

        foreach (var dir in resourceDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] scriptFiles;
            try
            {
                scriptFiles = Directory.GetFiles(dir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in scriptFiles)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!scriptExtensions.Contains(ext))
                    continue;

                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var keyword in BankHackScriptKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Bank-Hack-Skript in FiveM Resource: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Skript-Datei im FiveM-Resource-Verzeichnis enthaelt den Ausdruck '{keyword}', " +
                                         "der auf einen Bank-Hack oder Economy-Exploit hindeutet. " +
                                         "ESX/QB-Framework-Exploits verwenden haeufig solche Funktionsaufrufe zur Geld-Manipulation."
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckRegistryBankHackKeys(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var registryPaths = new[]
        {
            (@"Software\FiveM\BankHack", RegistryHive.CurrentUser),
            (@"Software\FiveMEconomyHack", RegistryHive.CurrentUser),
            (@"Software\FiveM\EconomyHack", RegistryHive.CurrentUser),
            (@"Software\FiveM\BankExploit", RegistryHive.CurrentUser),
            (@"Software\FiveM\MoneyExploit", RegistryHive.CurrentUser),
            (@"Software\FiveM\BankBypass", RegistryHive.CurrentUser),
            (@"Software\ESXBankExploit", RegistryHive.CurrentUser),
            (@"Software\QBBankHack", RegistryHive.CurrentUser),
            (@"Software\FiveMBankHack", RegistryHive.CurrentUser),
            (@"Software\BankRobExploit", RegistryHive.CurrentUser),
        };

        foreach (var (keyPath, hive) in registryPaths)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var subKey = baseKey.OpenSubKey(keyPath);
                ctx.IncrementRegistryKeys();

                if (subKey is not null)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Bank-Hack Registry-Schluessel gefunden: {keyPath}",
                        Risk = RiskLevel.High,
                        Location = $"{(hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM")}\\{keyPath}",
                        Reason = $"Registry-Schluessel '{keyPath}' existiert und ist typisch fuer FiveM Bank-Hack- oder " +
                                 "Economy-Exploit-Software. Solche Schluessel werden von cheat-Tools zur Konfigurationsspeicherung angelegt."
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (Exception) { }
        }

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var fivemKey = baseKey.OpenSubKey(@"Software\FiveM");
            ctx.IncrementRegistryKeys();

            if (fivemKey is not null)
            {
                foreach (var subName in fivemKey.GetSubKeyNames())
                {
                    ct.ThrowIfCancellationRequested();
                    if (ContainsBankHackKeywordInName(subName))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger FiveM Registry-Unterschluessel: {subName}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\Software\FiveM\{subName}",
                            Reason = $"FiveM Registry-Unterschluessel '{subName}' enthaelt bank-hack-bezogene Begriffe. " +
                                     "Solche Eintraege deuten auf installierte oder verwendete Exploit-Tools hin."
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception) { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckPrefetchBankHackExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        string[] pfFiles;
        try
        {
            pfFiles = Directory.GetFiles(prefetchDir, "*.pf");
        }
        catch (UnauthorizedAccessException)
        {
            await Task.CompletedTask;
            return;
        }
        catch (IOException)
        {
            await Task.CompletedTask;
            return;
        }

        foreach (var pf in pfFiles)
        {
            ct.ThrowIfCancellationRequested();
            var baseName = Path.GetFileNameWithoutExtension(pf);
            int dash = baseName.LastIndexOf('-');
            var exeName = dash > 0 ? baseName[..dash] : baseName;

            if (ContainsBankHackKeywordInName(exeName))
            {
                ctx.IncrementFiles();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Bank-Hack-Executable in Prefetch: {exeName}",
                    Risk = RiskLevel.High,
                    Location = pf,
                    FileName = exeName,
                    Reason = $"Prefetch-Datei '{Path.GetFileName(pf)}' belegt die Ausfuehrung von '{exeName}', " +
                             "dessen Name auf ein FiveM Bank-Hack- oder Economy-Exploit-Tool hindeutet. " +
                             "Das Programm wurde ausgefuehrt, auch wenn die Original-Datei bereits geloescht wurde."
                });
                continue;
            }

            foreach (var knownExe in KnownBankHackExeNames)
            {
                if (exeName.Equals(Path.GetFileNameWithoutExtension(knownExe), StringComparison.OrdinalIgnoreCase))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Bekanntes Bank-Hack-Tool in Prefetch: {exeName}",
                        Risk = RiskLevel.Critical,
                        Location = pf,
                        FileName = exeName,
                        Reason = $"Prefetch-Eintrag '{Path.GetFileName(pf)}' entspricht dem bekannten Bank-Hack-Tool '{knownExe}'. " +
                                 "Das Programm wurde auf diesem System ausgefuehrt."
                    });
                    break;
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckUserAssistBankHackTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Default);
            using var ua = baseKey.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            if (ua is null)
            {
                await Task.CompletedTask;
                return;
            }

            foreach (var guid in ua.GetSubKeyNames())
            {
                ct.ThrowIfCancellationRequested();
                using var count = ua.OpenSubKey($@"{guid}\Count");
                if (count is null)
                    continue;

                ctx.IncrementRegistryKeys();

                foreach (var valueName in count.GetValueNames())
                {
                    ct.ThrowIfCancellationRequested();
                    var decoded = Rot13Decode(valueName);
                    if (string.IsNullOrWhiteSpace(decoded))
                        continue;

                    if (ContainsBankHackKeywordInName(decoded))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Bank-Hack-Tool in UserAssist: {Path.GetFileName(decoded.TrimEnd('\\', '/'))}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count",
                            FileName = Path.GetFileName(decoded.TrimEnd('\\', '/')),
                            Reason = $"UserAssist-Eintrag (ROT13-dekodiert: '{decoded}') weist auf die Ausfuehrung eines " +
                                     "FiveM Bank-Hack- oder Economy-Exploit-Tools hin. " +
                                     "UserAssist protokolliert GUI-Programm-Starts durch den Benutzer."
                        });
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (Exception) { }

        await Task.CompletedTask;
    }, ct);

    private Task CheckDiscordArtifactsBankHack(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var roaming = KnownPaths.RoamingAppData;
        var local = KnownPaths.LocalAppData;

        var discordDirs = new[]
        {
            Path.Combine(roaming, "discord", "Cache"),
            Path.Combine(roaming, "discord", "Local Storage", "leveldb"),
            Path.Combine(roaming, "discord", "Session Storage"),
            Path.Combine(roaming, "discordcanary", "Cache"),
            Path.Combine(roaming, "discordcanary", "Local Storage", "leveldb"),
            Path.Combine(roaming, "discordptb", "Cache"),
            Path.Combine(roaming, "discordptb", "Local Storage", "leveldb"),
            Path.Combine(local, "Discord", "Cache"),
            Path.Combine(local, "Discord", "Local Storage", "leveldb"),
        };

        foreach (var dir in discordDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] cacheFiles;
            try
            {
                cacheFiles = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in cacheFiles)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext is ".png" or ".jpg" or ".jpeg" or ".gif" or ".mp4" or ".webm")
                    continue;

                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var keyword in DiscordBankHackKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Bank-Hack-Bezug in Discord-Cache: {Path.GetFileName(file)}",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Discord-Cache-Datei enthaelt Schluesselwort '{keyword}', das auf " +
                                         "Austausch ueber FiveM Bank-Hack- oder Economy-Exploit-Tools hinweist. " +
                                         "Solche Artefakte entstehen beim Empfangen/Senden von Nachrichten in einschlaegigen Servern."
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckLuaJsEconomyManipulationFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            KnownPaths.Downloads,
            Path.Combine(KnownPaths.UserProfile, "Desktop"),
            Path.Combine(KnownPaths.UserProfile, "Documents"),
            KnownPaths.RoamingAppData,
            KnownPaths.LocalAppData,
        };

        var scriptExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".lua", ".luac", ".js", ".ts", ".json"
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!scriptExtensions.Contains(ext))
                    continue;

                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var pattern in LuaEconomyPatterns)
                    {
                        if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Economy-Manipulations-Skript gefunden: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Skript-Datei '{Path.GetFileName(file)}' enthaelt Economy-Manipulations-Muster '{pattern}'. " +
                                         "Solche LUA/JS-Dateien werden von FiveM Bank-Hack-Tools verwendet, um Server-Events " +
                                         "auszuloesen oder Datenbankbefehle direkt abzusetzen."
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckTempScriptFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var tempDirs = new[]
        {
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"),
        };

        foreach (var tempDir in tempDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(tempDir))
                continue;

            string[] tempFiles;
            try
            {
                tempFiles = Directory.GetFiles(tempDir, "*bank*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in tempFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                try
                {
                    if (ContainsBankHackKeywordInName(Path.GetFileName(file)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Bank-Exploit Temp-Datei: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = $"Temporaere Datei '{Path.GetFileName(file)}' im Temp-Verzeichnis enthaelt bank-hack-relevante " +
                                     "Zeichenketten im Namen. Solche Dateien entstehen bei Ausfuehrung von FiveM Bank-Exploit-Werkzeugen."
                        });
                        continue;
                    }

                    var ext = Path.GetExtension(file);
                    if (ext is ".lua" or ".js" or ".json" or ".cfg" or ".txt" or ".log")
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var keyword in BankHackLogKeywords)
                        {
                            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Bank-Hack-Inhalt in Temp-Datei: {Path.GetFileName(file)}",
                                    Risk = RiskLevel.Medium,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"Temporaere Datei enthaelt bank-hack-bezogenes Schluesselwort '{keyword}'. " +
                                             "Temporaere Skript-Dateien werden von Bank-Exploit-Tools waehrend der Ausfuehrung erstellt."
                                });
                                break;
                            }
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }

            string[] exploitFiles;
            try
            {
                exploitFiles = Directory.GetFiles(tempDir, "*exploit*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in exploitFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                try
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Exploit-Temp-Datei: {Path.GetFileName(file)}",
                        Risk = RiskLevel.Medium,
                        Location = file,
                        FileName = Path.GetFileName(file),
                        Reason = $"Temporaere Datei '{Path.GetFileName(file)}' traegt 'exploit' im Namen. " +
                                 "Exploit-Tools legen temporaere Arbeitsdateien mit exploit-bezogenen Namen an."
                    });
                }
                catch (IOException) { }
            }
        }
    }, ct);

    private Task CheckCefBrowserCacheBankHack(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var local = KnownPaths.LocalAppData;
        var fivemRoot = KnownPaths.FindFiveMDirectory();

        var cefCacheDirs = new List<string>();
        if (fivemRoot != null)
        {
            cefCacheDirs.Add(Path.Combine(fivemRoot, "FiveM.app", "cef_cache"));
            cefCacheDirs.Add(Path.Combine(fivemRoot, "cef_cache"));
            cefCacheDirs.Add(Path.Combine(fivemRoot, "FiveM.app", "cef"));
            cefCacheDirs.Add(Path.Combine(fivemRoot, "cef"));
            cefCacheDirs.Add(Path.Combine(fivemRoot, "FiveM.app", "data", "nui-storage"));
            cefCacheDirs.Add(Path.Combine(fivemRoot, "FiveM.app", "user", "nui-storage"));
        }

        cefCacheDirs.Add(Path.Combine(local, "FiveM", "FiveM.app", "cef_cache"));
        cefCacheDirs.Add(Path.Combine(local, "FiveM", "FiveM.app", "nui-storage"));
        cefCacheDirs.Add(Path.Combine(local, "FiveM", "FiveM.app", "user", "nui-storage"));

        foreach (var cefDir in cefCacheDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(cefDir))
                continue;

            string[] cefFiles;
            try
            {
                cefFiles = Directory.GetFiles(cefDir, "*", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in cefFiles)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext is ".png" or ".jpg" or ".gif" or ".ico" or ".woff" or ".woff2")
                    continue;

                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var keyword in CefCacheKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Bank-Hack-Payload in CEF-Cache: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"FiveM CEF/NUI-Browser-Cache-Datei enthaelt das Schluesselwort '{keyword}', " +
                                         "das auf bank-hack-bezogene JavaScript-Payloads hindeutet. " +
                                         "CEF-basierte Exploits injizieren JavaScript in FiveMsNUI-Fenster, " +
                                         "um Server-Events zu manipulieren."
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckDatabaseManipulationScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            KnownPaths.Downloads,
            Path.Combine(KnownPaths.UserProfile, "Desktop"),
            Path.Combine(KnownPaths.UserProfile, "Documents"),
            KnownPaths.RoamingAppData,
        };

        var sqlExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".sql", ".lua", ".js", ".json", ".php", ".py", ".txt", ".cfg"
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in files)
            {
                ct.ThrowIfCancellationRequested();
                var ext = Path.GetExtension(file);
                if (!sqlExtensions.Contains(ext))
                    continue;

                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var keyword in DatabaseManipulationKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Datenbank-Manipulations-Skript: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Datei '{Path.GetFileName(file)}' enthaelt Datenbank-Manipulations-Muster '{keyword}'. " +
                                         "ESX/QB-Framework-Exploits verwenden direkte SQL-Befehle zur Geldmanipulation in der " +
                                         "FiveM-Server-Datenbank. Solche Skripte werden lokal als Beweis-Artefakt hinterlassen."
                            });
                            break;
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private Task CheckKnownBankHackExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchDirs = new[]
        {
            KnownPaths.Temp,
            Path.Combine(KnownPaths.LocalAppData, "Temp"),
            KnownPaths.Downloads,
            Path.Combine(KnownPaths.UserProfile, "Desktop"),
            Path.Combine(KnownPaths.UserProfile, "Documents"),
            KnownPaths.RoamingAppData,
            KnownPaths.LocalAppData,
            Path.Combine(KnownPaths.LocalAppData, "Programs"),
        };

        foreach (var dir in searchDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] exeFiles;
            try
            {
                exeFiles = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in exeFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                foreach (var knownExe in KnownBankHackExeNames)
                {
                    if (fileName.Equals(knownExe, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Bekanntes Bank-Hack-Tool gefunden: {fileName}",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason = $"Executable '{fileName}' entspricht einem bekannten FiveM Bank-Hack- oder " +
                                         "Economy-Exploit-Tool. Diese Werkzeuge werden eingesetzt um Bank-Skripte zu umgehen " +
                                         "oder die FiveM-Server-Wirtschaft zu manipulieren."
                            });
                        }
                        catch (IOException) { }
                        break;
                    }
                }

                if (ContainsBankHackKeywordInName(fileName))
                {
                    try
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiges Bank-Hack-Executable: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Executable '{fileName}' enthaelt bank-hack-typische Begriffe im Namen. " +
                                     "Solche Programme werden zum Ausnutzen von FiveM-Bank- und Economy-Skript-Luecken eingesetzt."
                        });
                    }
                    catch (IOException) { }
                }
            }
        }

        await Task.CompletedTask;
    }, ct);

    private Task CheckFiveMResourceFolderBankKeywords(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var fivemRoot = KnownPaths.FindFiveMDirectory();
        if (fivemRoot is null)
        {
            await Task.CompletedTask;
            return;
        }

        var resourceFolders = new[]
        {
            Path.Combine(fivemRoot, "resources"),
            Path.Combine(fivemRoot, "FiveM.app", "resources"),
            Path.Combine(fivemRoot, "citizen", "resources"),
        };

        foreach (var resDir in resourceFolders)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(resDir))
                continue;

            string[] subDirs;
            try
            {
                subDirs = Directory.GetDirectories(resDir);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var subDir in subDirs)
            {
                ct.ThrowIfCancellationRequested();
                var dirName = Path.GetFileName(subDir);

                if (ContainsBankHackKeywordInName(dirName))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Bank-Hack-Resource-Ordner: {dirName}",
                        Risk = RiskLevel.High,
                        Location = subDir,
                        Reason = $"FiveM-Resource-Verzeichnis '{dirName}' traegt bank-hack-bezogene Begriffe. " +
                                 "Solche Resources werden als FiveM-serverseitige oder clientseitige Exploit-Pakete eingesetzt."
                    });
                }

                string[] resourceFiles;
                try
                {
                    resourceFiles = Directory.GetFiles(subDir, "*", SearchOption.AllDirectories);
                }
                catch (UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var file in resourceFiles)
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    if (ContainsBankHackKeywordInName(Path.GetFileName(file)))
                    {
                        try
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Bank-Hack-Datei in Resource: {Path.GetFileName(file)}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = $"Datei '{Path.GetFileName(file)}' in FiveM-Resource '{dirName}' hat bank-hack-typischen Namen. " +
                                         "Exploit-Ressourcen tarnen sich oft als legitime Skripte."
                            });
                        }
                        catch (IOException) { }
                    }
                }
            }
        }
    }, ct);

    private Task CheckESXQBFrameworkFiles(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var fivemRoot = KnownPaths.FindFiveMDirectory();
        var local = KnownPaths.LocalAppData;
        var roaming = KnownPaths.RoamingAppData;

        var frameworkDirs = new List<string>();
        if (fivemRoot != null)
        {
            frameworkDirs.Add(Path.Combine(fivemRoot, "resources", "[esx]"));
            frameworkDirs.Add(Path.Combine(fivemRoot, "resources", "[qb]"));
            frameworkDirs.Add(Path.Combine(fivemRoot, "resources", "esx_banking"));
            frameworkDirs.Add(Path.Combine(fivemRoot, "resources", "qb-banking"));
            frameworkDirs.Add(Path.Combine(fivemRoot, "resources", "esx_jobs"));
            frameworkDirs.Add(Path.Combine(fivemRoot, "resources"));
        }

        frameworkDirs.Add(Path.Combine(local, "FiveM", "FiveM.app", "resources"));
        frameworkDirs.Add(Path.Combine(roaming, "citizenfx"));

        var esxQbKeywords = new[]
        {
            "esx:addMoney", "esx:removeMoney", "esx:getSharedObject",
            "qb:AddMoney", "qb:RemoveMoney", "QBCore:GetObject",
            "exports['esx']", "exports[\"esx\"]", "exports['qb-core']", "exports[\"qb-core\"]",
            "ESX.AddMoney", "ESX.RemoveMoney", "ESX.SetMoney",
            "QBCore.Functions.AddMoney", "QBCore.Functions.RemoveMoney",
            "oxmysql:execute", "mysql-async:mysql-scalar",
            "bank_hack", "economy_exploit", "money_bypass",
            "TriggerServerEvent('esx:addMoney')", "TriggerServerEvent(\"esx:addMoney\")",
            "TriggerServerEvent('qb:AddMoney')", "TriggerServerEvent(\"qb:AddMoney\")",
            "banking:addMoney bypass", "esx_banking exploit", "qb-banking exploit"
        };

        foreach (var dir in frameworkDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir))
                continue;

            string[] luaFiles;
            try
            {
                luaFiles = Directory.GetFiles(dir, "*.lua", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in luaFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    foreach (var keyword in esxQbKeywords)
                    {
                        if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            bool isSuspicious = keyword.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                                || keyword.Contains("exploit", StringComparison.OrdinalIgnoreCase)
                                || keyword.Contains("hack", StringComparison.OrdinalIgnoreCase);

                            if (isSuspicious)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"ESX/QB-Framework-Exploit-LUA: {Path.GetFileName(file)}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = $"LUA-Datei im ESX/QB-Framework-Bereich enthaelt exploit-bezogenen Ausdruck '{keyword}'. " +
                                             "ESX- und QB-Core-Framework-Exploits zielen auf AddMoney/RemoveMoney-Server-Events " +
                                             "und Datenbankfunktionen ab, um Spielwirtschaft zu manipulieren."
                                });
                                break;
                            }
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }

            string[] jsFiles;
            try
            {
                jsFiles = Directory.GetFiles(dir, "*.js", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var file in jsFiles)
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = await sr.ReadToEndAsync(ct);

                    bool hasMoneyKeyword = content.Contains("AddMoney", StringComparison.OrdinalIgnoreCase)
                        || content.Contains("addBalance", StringComparison.OrdinalIgnoreCase)
                        || content.Contains("setMoney", StringComparison.OrdinalIgnoreCase);

                    bool hasBypassKeyword = content.Contains("bypass", StringComparison.OrdinalIgnoreCase)
                        || content.Contains("exploit", StringComparison.OrdinalIgnoreCase)
                        || content.Contains("hack", StringComparison.OrdinalIgnoreCase);

                    if (hasMoneyKeyword && hasBypassKeyword)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiges ESX/QB JS-Skript: {Path.GetFileName(file)}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "JavaScript-Datei kombiniert Geld-Manipulations-Funktionen (AddMoney/addBalance/setMoney) " +
                                     "mit Bypass/Exploit-Mustern. Dies ist ein starkes Indiz fuer ein bank-hack-bezogenes NUI-Skript."
                        });
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }, ct);

    private static bool ContainsBankHackKeywordInName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;

        var keywords = new[]
        {
            "bankhack", "bankexploit", "bankbypass", "bank_hack", "bank_exploit",
            "bank_bypass", "bankrob", "bank_rob", "robbank", "rob_bank",
            "economyhack", "economy_hack", "economyexploit", "economy_exploit",
            "moneyexploit", "money_exploit", "moneyhack", "money_hack",
            "qbbankh", "esxbank", "fivembank", "bankcheat", "bank_cheat",
            "robscript", "rob_script", "robberyexploit", "robbery_exploit",
            "moneydupe", "money_dupe", "bankdupe", "bank_dupe", "addbankmon",
            "givemoney", "addmoney", "unlimitedmoney"
        };

        foreach (var kw in keywords)
        {
            if (name.Contains(kw, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
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
}
