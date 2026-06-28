using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

[SupportedOSPlatform("windows")]
public sealed class FiveMServerSideCheatForensicScanModule : IScanModule
{
    public string Name => "FiveM Server-Side Cheat Forensics";
    public double Weight => 1.0;
    public int ParallelGroup => 4;

    private static readonly string[] ESXExploitFileNames = { "esx_exploit.lua", "esx_sql_inject.lua", "esx_dupe.lua", "esx_bypass.lua", "esx_admin_bypass.lua" };
    private static readonly string[] QBCoreExploitFileNames = { "qbcore_exploit.lua", "qb_dupe.lua", "qb_inject.lua", "qb_admin_bypass.lua", "qb_exploit.lua" };
    private static readonly string[] ServerCrashToolNames = { "fivem_crasher.exe", "server_crasher.exe", "citizenfx_exploit.exe", "onesync_exploit.exe", "udp_flood.exe", "net_crasher.exe" };
    private static readonly string[] RconExploitKeywords = { "rcon_password", "rconpassword", "rcon_exploit", "rcon_brute", "convar_set sv_", "set sv_" };
    private static readonly string[] ClientSideAdminKeywords = { "ExecuteCommand('give')", "ExecuteCommand('god')", "ExecuteCommand('kick')", "ExecuteCommand('ban')", "ExecuteCommand('unban')" };
    private static readonly string[] WebhookExfilKeywords = { "discord.com/api/webhooks/", "discordapp.com/api/webhooks/", "GetPlayerIdentifiers", "GetPlayerName", "GetPlayerPing" };
    private static readonly string[] BackdoorKeywords = { "os.execute", "io.popen", "loadstring(", "require(", "os.popen", "io.read", "powershell" };

    private static string AppData => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static string Downloads => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
    private static string Documents => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    private static string Desktop => Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static string FiveMAppData => Path.Combine(AppData, "citizenfx", "FiveM", "FiveM.app");
    private static string FiveMLocalAppData => Path.Combine(LocalAppData, "FiveM", "FiveM.app");

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckTxAdminArtifacts(ctx, ct),
            CheckESXFrameworkExploit(ctx, ct),
            CheckQBCoreFrameworkExploit(ctx, ct),
            CheckServerConsoleCommandArtifacts(ctx, ct),
            CheckFiveMServerCrashTools(ctx, ct),
            CheckFiveMNetEventExploits(ctx, ct),
            CheckFiveMMoneyDuplication(ctx, ct),
            CheckFiveMDatabaseExploitTools(ctx, ct),
            CheckFiveMIdentifierSpoofing(ctx, ct),
            CheckFiveMCustomResourceBackdoors(ctx, ct),
            CheckFiveMServerCFGExploits(ctx, ct),
            CheckFiveMAdminMenuAbuse(ctx, ct),
            CheckFiveMOneDesyncExploit(ctx, ct),
            CheckFiveMCheatSubscriptionArtifacts(ctx, ct),
            CheckFiveMTokenGrabbers(ctx, ct),
            CheckFiveMCheatDiscordWebhooks(ctx, ct),
            CheckFiveMServerAccessLogs(ctx, ct),
            CheckFiveMCheatToolSuites(ctx, ct)
        );
    }

    private Task CheckTxAdminArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var txDataRoots = new[]
        {
            Path.Combine(FiveMAppData, "data", "txData"),
            Path.Combine(FiveMLocalAppData, "data", "txData"),
        };

        var profileFileNames = new[] { "txAdmin_config.json", "admins.json" };

        foreach (var root in txDataRoots)
        {
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "txData_*.json", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        if (content.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                            content.Contains("admin", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "txAdmin Profile Data File Found",
                                Risk = RiskLevel.Medium,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "txAdmin profile data file containing potential admin credentials or configuration was found in the FiveM data directory.",
                                Detail = $"Path: {file}"
                            });
                        }
                    }
                    catch { }
                }

                foreach (var profileFile in profileFileNames)
                {
                    var filePath = Path.Combine(root, profileFile);
                    if (!File.Exists(filePath)) continue;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"txAdmin Configuration File Found: {profileFile}",
                            Risk = RiskLevel.Medium,
                            Location = filePath,
                            FileName = profileFile,
                            Reason = "A txAdmin configuration file was found which may contain admin credentials or panel configuration.",
                            Detail = $"File size: {content.Length} characters"
                        });
                    }
                    catch { }
                }

                foreach (var logFile in Directory.EnumerateFiles(root, "*.log", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        if (content.Contains("banned", StringComparison.OrdinalIgnoreCase) ||
                            content.Contains("kicked", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "txAdmin Log With Ban/Kick Records Found",
                                Risk = RiskLevel.Medium,
                                Location = logFile,
                                FileName = Path.GetFileName(logFile),
                                Reason = "A txAdmin log file containing ban or kick records was found, indicating server administration activity.",
                                Detail = $"Log file: {Path.GetFileName(logFile)}"
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

    private Task CheckESXFrameworkExploit(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
            Downloads,
            Documents,
        };

        var esxContentKeywords = new[]
        {
            "exports['es_extended']:getPlayerFromIdentifier",
            "MySQL.Async.execute",
            "TriggerEvent('esx:setJob')",
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (ESXExploitFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ESX Framework Exploit Script Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = "A known ESX framework exploit Lua script was found by filename. These scripts are used to abuse ESX server-side functions.",
                            Detail = $"Matched known exploit filename: {fileName}"
                        });
                        continue;
                    }

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        int matchCount = esxContentKeywords.Count(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase));
                        if (matchCount >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "ESX Framework Exploit Pattern Detected in Script",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason = "A Lua script contains multiple ESX framework exploit patterns including identifier lookups, SQL execution, and job assignment without server validation.",
                                Detail = $"Matched {matchCount} ESX exploit keyword(s)"
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

    private Task CheckQBCoreFrameworkExploit(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var searchRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
            Downloads,
            Documents,
        };

        var qbContentKeywords = new[]
        {
            "QBCore.Functions.GetPlayer",
            "Player.Functions.AddMoney",
            "Player.Functions.AddItem",
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (QBCoreExploitFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"QBCore Framework Exploit Script Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = "A known QBCore exploit Lua script was found by filename. These scripts are used to abuse QBCore server-side functions for item/money duplication or privilege escalation.",
                            Detail = $"Matched known exploit filename: {fileName}"
                        });
                        continue;
                    }

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        int matchCount = qbContentKeywords.Count(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase));
                        if (matchCount >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "QBCore Framework Exploit Pattern Detected in Script",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason = "A Lua script contains multiple QBCore framework exploit patterns including player object access and money/item manipulation functions.",
                                Detail = $"Matched {matchCount} QBCore exploit keyword(s)"
                            });
                        }
                    }
                    catch { }
                }

                foreach (var file in Directory.EnumerateFiles(root, "*.lua", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    var fileName = Path.GetFileName(file);
                    if (QBCoreExploitFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.IncrementFiles();
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"QBCore Exploit Tool Found in Downloads: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = "A known QBCore exploit script was found in the Downloads folder.",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckServerConsoleCommandArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var rconToolNames = new[] { "fivem_rcon.exe", "rcon_client.exe", "txadmin_exploit.exe" };
        var searchDirs = new[] { Downloads, Desktop, Documents };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    if (rconToolNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM RCON Exploit Tool Found: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = "A known FiveM RCON or server console exploitation tool was found. These tools are used to send unauthorized commands to FiveM servers.",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        var scriptRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
        };

        foreach (var root in scriptRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        int matchCount = RconExploitKeywords.Count(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase));
                        if (matchCount >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "RCON/Server Console Exploit Pattern in Script",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "A script contains multiple RCON or server console command patterns that may indicate unauthorized server control attempts.",
                                Detail = $"Matched {matchCount} RCON keyword(s)"
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

    private Task CheckFiveMServerCrashTools(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var searchDirs = new[] { Downloads, Desktop, Documents };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    if (ServerCrashToolNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM Server Crash Tool Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = "A known FiveM server crash or packet flood tool was found. These tools are used to forcibly crash or disconnect FiveM servers.",
                            Detail = $"Path: {file}"
                        });
                    }
                }

                foreach (var file in Directory.EnumerateFiles(dir, "*.zip", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    if (fileName.Contains("crash", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM Crash Exploit Package Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = "A zip archive with 'crash' in its name was found in a user download location, suggesting a server crash exploit package.",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckFiveMNetEventExploits(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var netEventExploitFiles = new[] { "event_spam.lua", "netevent_exploit.lua", "triggernetspam.lua" };
        var searchRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
            Downloads,
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (netEventExploitFiles.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Net Event Exploit Script Found: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = "A known FiveM net event spam/exploit script was found by filename. These scripts flood the server with network events to degrade performance or trigger bugs.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        int triggerCount = 0;
                        int idx = 0;
                        while ((idx = content.IndexOf("TriggerNetEvent", idx, StringComparison.OrdinalIgnoreCase)) >= 0)
                        {
                            triggerCount++;
                            idx++;
                        }
                        if (triggerCount >= 50)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Excessive TriggerNetEvent Calls in Script",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = "A script contains an unusually high number of TriggerNetEvent calls without apparent rate limiting, which is a pattern associated with network event spam abuse.",
                                Detail = $"TriggerNetEvent call count: {triggerCount}"
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

    private Task CheckFiveMMoneyDuplication(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var dupeFileNames = new[] { "dupe_money.lua", "money_glitch.lua", "item_dupe.lua" };
        var dupeKeywords = new[] { "xPlayer.addMoney(", "Player.Functions.AddMoney(" };

        var searchRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
            Downloads,
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (dupeFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Money/Item Duplication Exploit Script Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = "A known FiveM money or item duplication exploit script was found. These scripts abuse server-side economy functions to generate unlimited in-game resources.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        foreach (var kw in dupeKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Money Duplication Pattern in Client-Side Script",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = fileName,
                                    Reason = "A script contains server-side economy manipulation functions being called without proper server-side validation, indicating a money or item duplication exploit.",
                                    Detail = $"Matched pattern: {kw}"
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

    private Task CheckFiveMDatabaseExploitTools(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var dbToolFileNames = new[] { "mysqldump_fivem.exe", "fivem_db_inject.exe" };
        var sqlExploitFiles = new[] { "esx_db_exploit.sql" };
        var sqlInjectionKeywords = new[] { "' OR '1'='1", "DROP TABLE", "SELECT * FROM users" };

        var searchDirs = new[] { Downloads, Desktop, Documents };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    if (dbToolFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM Database Exploit Tool Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = "A known FiveM database exploitation tool was found. These tools target FiveM MySQL databases to extract or manipulate player data.",
                            Detail = $"Path: {file}"
                        });
                    }
                }

                foreach (var file in Directory.EnumerateFiles(dir, "*.sql", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    if (sqlExploitFiles.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM Database Exploit SQL File Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = "A known FiveM ESX database exploit SQL file was found.",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        var scriptRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
        };

        foreach (var root in scriptRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var ext in new[] { "*.lua", "*.js" })
                {
                    foreach (var file in Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            foreach (var kw in sqlInjectionKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "SQL Injection Pattern in FiveM Script",
                                        Risk = RiskLevel.Critical,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = "A FiveM script contains SQL injection patterns targeting FiveM database tables, suggesting database exploitation attempts.",
                                        Detail = $"Matched SQL injection string: {kw}"
                                    });
                                    break;
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

    private Task CheckFiveMIdentifierSpoofing(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var identifierKeywords = new[] { "GetPlayerIdentifier", "steam:", "license:", "xbl:", "live:", "discord:" };
        var forgeKeywords = new[] { "SetPlayerIdentifier", "OverrideIdentifier", "FakeIdentifier", "SpoofIdentifier" };
        var steamSwitcherNames = new[] { "steam_switcher.exe", "account_switcher.exe", "steam_account_manager.exe", "steamaccountmanager.exe" };

        var searchRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        bool hasIdentifierAccess = identifierKeywords.Any(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase));
                        bool hasForgeAttempt = forgeKeywords.Any(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase));
                        if (hasIdentifierAccess && hasForgeAttempt)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Player Identifier Spoofing Pattern Detected",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = Path.GetFileName(file),
                                Reason = "A FiveM script contains both identifier access patterns and identifier forgery/spoofing patterns, indicating an attempt to manipulate player identity data.",
                                Detail = $"Path: {file}"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        var searchDirs = new[] { Downloads, Desktop, Documents };
        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);
                    if (steamSwitcherNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Steam Account Switcher Tool Found: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = "A Steam account switcher tool was found. These tools are commonly used in combination with FiveM to cycle identifiers and evade bans.",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);

    private Task CheckFiveMCustomResourceBackdoors(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var resourceRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
        };

        foreach (var root in resourceRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var ext in new[] { "*.lua", "*.js" })
                {
                    foreach (var file in Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            foreach (var kw in BackdoorKeywords)
                            {
                                if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                                {
                                    bool isPowerShell = kw.Equals("powershell", StringComparison.OrdinalIgnoreCase);
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = isPowerShell
                                            ? "PowerShell Execution in FiveM Resource Script"
                                            : "Backdoor Pattern in FiveM Resource Script",
                                        Risk = RiskLevel.Critical,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = isPowerShell
                                            ? "A FiveM resource script attempts to execute PowerShell via os.execute, indicating a backdoor that can run arbitrary system commands."
                                            : "A FiveM resource script contains a known backdoor pattern that can execute arbitrary code or access the local filesystem.",
                                        Detail = $"Matched backdoor keyword: {kw}"
                                    });
                                    break;
                                }
                            }

                            if (content.Contains("http://", StringComparison.OrdinalIgnoreCase) ||
                                content.Contains("https://", StringComparison.OrdinalIgnoreCase))
                            {
                                bool hasExternalLoad = content.Contains("require(", StringComparison.OrdinalIgnoreCase) ||
                                                       content.Contains("loadstring(", StringComparison.OrdinalIgnoreCase) ||
                                                       content.Contains("WebSocket", StringComparison.OrdinalIgnoreCase);
                                bool isNonFiveM = !content.Contains("cfx.re", StringComparison.OrdinalIgnoreCase) &&
                                                  !content.Contains("citizenfx.com", StringComparison.OrdinalIgnoreCase);
                                if (hasExternalLoad && isNonFiveM)
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "External URL Code Loading in FiveM Resource",
                                        Risk = RiskLevel.Critical,
                                        Location = file,
                                        FileName = Path.GetFileName(file),
                                        Reason = "A FiveM resource script loads or executes code from an external non-FiveM URL, indicating a remote code execution backdoor.",
                                        Detail = $"File: {Path.GetFileName(file)}"
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

    private Task CheckFiveMServerCFGExploits(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var cfgSearchRoots = new[]
        {
            Path.Combine(FiveMAppData, "data"),
            Path.Combine(FiveMLocalAppData, "data"),
        };

        var suspiciousCfgKeywords = new[]
        {
            "set sv_licenseKeyToken",
            "sv_authMaxVariance",
            "sv_authMinTrust",
            "sv_filterRequestControl 0",
            "sv_filterRequestControl false",
        };

        foreach (var root in cfgSearchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "server.cfg", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var kw in suspiciousCfgKeywords)
                        {
                            if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Suspicious FiveM server.cfg Configuration Found",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = "A FiveM server.cfg file contains suspicious configuration values that may weaken server security, including disabled request filtering or manipulated trust settings.",
                                    Detail = $"Matched configuration keyword: {kw}"
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

    private Task CheckFiveMAdminMenuAbuse(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var adminMenuFileNames = new[] { "admin_menu.lua", "admin_panel.lua" };

        var resourceRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
        };

        foreach (var root in resourceRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (adminMenuFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Local Admin Menu Script Found: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = "A local admin menu script was found in FiveM resource directories. Unauthorized admin menu scripts can be used to execute privileged commands.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        int matchCount = ClientSideAdminKeywords.Count(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase));
                        if (matchCount >= 2)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Admin Command Abuse Pattern Detected in Script",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = "A script contains multiple client-side ExecuteCommand calls for privileged admin actions such as give, god, kick, or ban, indicating admin command abuse from a client context.",
                                Detail = $"Matched {matchCount} admin command keyword(s)"
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

    private Task CheckFiveMOneDesyncExploit(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var oneDesyncExploitKeywords = new[]
        {
            "NetworkRequestControlOfEntity",
            "SetNetworkIdCanMigrate",
            "SetEntityAsMissionEntity",
        };

        var resourceRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
        };

        foreach (var root in resourceRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        int matchCount = oneDesyncExploitKeywords.Count(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase));
                        if (matchCount >= 2)
                        {
                            int callCount = 0;
                            int idx = 0;
                            foreach (var kw in oneDesyncExploitKeywords)
                            {
                                int searchIdx = 0;
                                while ((searchIdx = content.IndexOf(kw, searchIdx, StringComparison.OrdinalIgnoreCase)) >= 0)
                                {
                                    callCount++;
                                    searchIdx++;
                                }
                            }
                            if (callCount >= 5)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "OneSync Entity Desync Exploit Pattern Detected",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = "A FiveM script contains multiple OneSync entity control functions being called rapidly in patterns consistent with entity desync exploitation.",
                                    Detail = $"Matched {matchCount} OneSync keyword(s) with {callCount} total calls"
                                });
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

    private Task CheckFiveMCheatSubscriptionArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var cheatShopKeywords = new[]
        {
            "fivemcheats", "fivem-cheat", "fivem_cheat", "fivem cheat shop",
            "fivem exploit", "fivem hack", "buy fivem cheat",
        };

        var browserHistoryPaths = new[]
        {
            Path.Combine(LocalAppData, "Google", "Chrome", "User Data", "Default", "History"),
            Path.Combine(LocalAppData, "Microsoft", "Edge", "User Data", "Default", "History"),
        };

        foreach (var historyPath in browserHistoryPaths)
        {
            if (!File.Exists(historyPath)) continue;
            ctx.IncrementFiles();
            try
            {
                var tempCopy = Path.Combine(Path.GetTempPath(), $"zt_history_{Guid.NewGuid():N}.tmp");
                try
                {
                    File.Copy(historyPath, tempCopy, overwrite: true);
                    using var fs = new FileStream(tempCopy, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs, Encoding.UTF8);
                    string content = await sr.ReadToEndAsync(ct);
                    foreach (var kw in cheatShopKeywords)
                    {
                        if (content.Contains(kw, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Cheat Shop Visit in Browser History",
                                Risk = RiskLevel.High,
                                Location = historyPath,
                                FileName = Path.GetFileName(historyPath),
                                Reason = "Browser history contains references to FiveM cheat shop or purchase sites, indicating potential cheat subscription activity.",
                                Detail = $"Matched keyword: {kw}"
                            });
                            break;
                        }
                    }
                }
                finally
                {
                    try { File.Delete(tempCopy); } catch { }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }

        if (!Directory.Exists(Downloads)) return;
        try
        {
            foreach (var file in Directory.EnumerateFiles(Downloads, "*.zip", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);
                if (fileName.Contains("cheat", StringComparison.OrdinalIgnoreCase) &&
                    (fileName.Contains("fivem", StringComparison.OrdinalIgnoreCase) ||
                     fileName.Contains("resource", StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"FiveM Cheat Resource Package Found: {fileName}",
                        Risk = RiskLevel.High,
                        Location = file,
                        FileName = fileName,
                        Reason = "A zip file matching the naming pattern of FiveM cheat resource packages was found in the Downloads folder.",
                        Detail = $"Path: {file}"
                    });
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { }
    }, ct);

    private Task CheckFiveMTokenGrabbers(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var tokenGrabberFileNames = new[] { "token_grabber.lua", "auth_steal.lua" };
        var authTokenPath = Path.Combine(FiveMAppData, "data");
        var webhookPattern = "https://discord.com/api/webhooks/";

        var searchRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.lua", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    if (tokenGrabberFileNames.Contains(fileName, StringComparer.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM Token/Auth Grabber Script Found: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = "A known FiveM authentication token grabber script was found. These scripts steal FiveM auth tokens or credentials from the local data directory.",
                            Detail = $"Path: {file}"
                        });
                        continue;
                    }

                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        bool readsAuthData = content.Contains(authTokenPath, StringComparison.OrdinalIgnoreCase) ||
                                             content.Contains("FiveM.app\\data", StringComparison.OrdinalIgnoreCase);
                        bool exfiltrates = content.Contains(webhookPattern, StringComparison.OrdinalIgnoreCase);
                        if (readsAuthData && exfiltrates)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "FiveM Auth Token Exfiltration Pattern Detected",
                                Risk = RiskLevel.Critical,
                                Location = file,
                                FileName = fileName,
                                Reason = "A FiveM script reads from the auth data directory and sends data to a Discord webhook, a pattern consistent with FiveM token or credential theft.",
                                Detail = $"File: {fileName}"
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

    private Task CheckFiveMCheatDiscordWebhooks(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var webhookUrls = new[] { "https://discord.com/api/webhooks/", "https://discordapp.com/api/webhooks/" };
        var playerDataKeywords = new[] { "GetPlayerIdentifiers", "GetPlayerName", "GetPlayerPing" };

        var searchRoots = new[]
        {
            Path.Combine(FiveMAppData, "citizen", "resources"),
            Path.Combine(FiveMLocalAppData, "cache"),
        };

        foreach (var root in searchRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var ext in new[] { "*.lua", "*.js" })
                {
                    foreach (var file in Directory.EnumerateFiles(root, ext, SearchOption.AllDirectories))
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementFiles();
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);

                            bool hasWebhook = webhookUrls.Any(url => content.Contains(url, StringComparison.OrdinalIgnoreCase));
                            bool hasPlayerData = playerDataKeywords.Any(kw => content.Contains(kw, StringComparison.OrdinalIgnoreCase));

                            if (hasWebhook && hasPlayerData)
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Discord Webhook Player Data Exfiltration in FiveM Script",
                                    Risk = RiskLevel.Critical,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = "A FiveM script combines Discord webhook calls with player data access functions, indicating unauthorized exfiltration of player identifiers, names, or connection data to an external Discord channel.",
                                    Detail = $"File: {Path.GetFileName(file)}"
                                });
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

    private Task CheckFiveMServerAccessLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logRoots = new[]
        {
            Path.Combine(FiveMAppData, "logs"),
            Path.Combine(FiveMLocalAppData, "logs"),
        };

        var suspiciousLogPatterns = new[]
        {
            "BANNED",
            "admin access denied",
            "unauthorized command",
            "ACCESS DENIED",
            "admin bypass",
        };

        foreach (var root in logRoots)
        {
            if (!Directory.Exists(root)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(root, "*.log", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var pattern in suspiciousLogPatterns)
                        {
                            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Suspicious FiveM Server Access Log Entry Found",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = Path.GetFileName(file),
                                    Reason = "A FiveM log file contains entries indicating unauthorized server access attempts, admin bypass, or repeated ban events, which may be artifacts of server-side cheat abuse.",
                                    Detail = $"Matched log pattern: {pattern}"
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

    private Task CheckFiveMCheatToolSuites(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var suiteFolderKeywords = new[] { "FiveM_Suite", "FiveM_CheatPack", "FiveM_Tools_v", "FiveM_Exploit_Pack" };
        var exploitFrameworkNames = new[] { "lua_executor_fivem", "fivem_internal_framework" };
        var searchDirs = new[] { Downloads, Desktop, Documents };

        foreach (var dir in searchDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var subDir in Directory.EnumerateDirectories(dir, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    var dirName = Path.GetFileName(subDir);

                    bool isSuiteFolder = suiteFolderKeywords.Any(kw =>
                        dirName.StartsWith(kw, StringComparison.OrdinalIgnoreCase) ||
                        dirName.Equals(kw, StringComparison.OrdinalIgnoreCase));

                    bool isFramework = exploitFrameworkNames.Any(kw =>
                        dirName.Contains(kw, StringComparison.OrdinalIgnoreCase));

                    if (isSuiteFolder || isFramework)
                    {
                        int resourceCount = 0;
                        try { resourceCount = Directory.GetFiles(subDir, "*.lua", SearchOption.AllDirectories).Length; } catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM Cheat Tool Suite Directory Found: {dirName}",
                            Risk = RiskLevel.Critical,
                            Location = subDir,
                            FileName = dirName,
                            Reason = isFramework
                                ? "A FiveM exploit framework directory was found. These frameworks provide comprehensive tools for server-side exploitation."
                                : "A FiveM cheat tool suite directory was found containing multiple bundled cheat resources. These packs typically include exploit scripts, admin bypasses, and server-side manipulation tools.",
                            Detail = $"Directory: {subDir} | Lua files found: {resourceCount}"
                        });
                    }
                }

                foreach (var file in Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileNameWithoutExtension(file);
                    if (exploitFrameworkNames.Any(kw => fileName.Contains(kw, StringComparison.OrdinalIgnoreCase)))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"FiveM Exploit Framework Executable Found: {Path.GetFileName(file)}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = Path.GetFileName(file),
                            Reason = "A FiveM exploit framework executable was found. These tools provide scripted access to FiveM server internals for exploitation purposes.",
                            Detail = $"Path: {file}"
                        });
                    }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch { }
        }
    }, ct);
}
