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

public sealed class GTA5ModMenuForensicScanModule : IScanModule
{
    public string Name => "GTA V Mod Menu Forensic Scan";
    public double Weight => 4.0;
    public int ParallelGroup => 4;
    public int ModuleTimeoutSeconds => 0;

    private static string AppData => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static string Desktop => Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
    private static string Downloads => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
    private static string Temp => Path.GetTempPath();
    private static string Documents => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

    private static IEnumerable<string> GetGTAVGameDirs()
    {
        var candidates = new List<string>
        {
            @"C:\Program Files\Rockstar Games\Grand Theft Auto V",
            @"C:\Program Files (x86)\Rockstar Games\Grand Theft Auto V",
            @"C:\Games\Grand Theft Auto V",
            @"C:\Games\GTAV",
            @"D:\Games\Grand Theft Auto V",
            @"D:\Rockstar Games\Grand Theft Auto V",
            @"E:\Games\Grand Theft Auto V",
            @"E:\Rockstar Games\Grand Theft Auto V",
        };

        try
        {
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                using var key = hive.OpenSubKey(@"SOFTWARE\Rockstar Games\Grand Theft Auto V", writable: false)
                             ?? hive.OpenSubKey(@"SOFTWARE\WOW6432Node\Rockstar Games\Grand Theft Auto V", writable: false);
                var path = key?.GetValue("InstallFolder")?.ToString()
                        ?? key?.GetValue("InstallFolderSteam")?.ToString();
                if (!string.IsNullOrEmpty(path) && Directory.Exists(path))
                    candidates.Insert(0, path);
            }
        }
        catch { }

        try
        {
            using var steamKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Valve\Steam", writable: false)
                              ?? Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Valve\Steam", writable: false);
            var steamPath = steamKey?.GetValue("SteamPath")?.ToString();
            if (!string.IsNullOrEmpty(steamPath))
            {
                candidates.Add(Path.Combine(steamPath, "steamapps", "common", "Grand Theft Auto V"));
            }
        }
        catch { }

        return candidates.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase);
    }

    private static readonly string[] GenericGTAModMenuExecutables =
    [
        "gtav_menu.exe", "gta_menu.exe", "gta_mod_menu.exe", "gta_cheat_menu.exe",
        "gtav_cheat.exe", "gtav_hack.exe", "gta_hack.exe", "gta_inject.exe",
        "gta_injector.exe", "gta_loader.exe", "gta_bypass.exe", "gta_native.exe",
        "gta_trainer.exe", "gta_mod.exe", "gtav_trainer.exe", "gtav_mod.exe",
        "gtav_loader.exe", "gtav_inject.exe", "gtav_bypass.exe", "gtav_native.exe",
        "menyoo.exe", "menyoo_loader.exe", "menyooStuff.exe", "lambda_menu.exe",
        "atm_menu.exe", "phantom_menu.exe", "ozarks.exe", "ozarks_menu.exe",
        "nought.exe", "nought_menu.exe", "yamyam.exe", "yamyam_menu.exe",
        "horsepower.exe", "horsepower_menu.exe", "force.exe", "force_menu.exe",
        "nova.exe", "nova_menu.exe", "nova_gta.exe", "oshgun.exe", "oshgun_menu.exe",
        "rockstar_menu.exe", "online_menu.exe", "gta_online_menu.exe",
        "gta_online_cheat.exe", "gta_online_hack.exe", "online_hack.exe",
        "online_cheat.exe", "menu_gta.exe", "menu_gtav.exe", "cheat_menu.exe",
        "hack_menu.exe", "modmenu.exe", "mod_menu.exe", "gtav_modmenu.exe",
        "gtav_cheatmenu.exe", "gta5_menu.exe", "gta5_cheat.exe", "gta5_hack.exe",
    ];

    private static readonly string[] GTAModMenuDlls =
    [
        "modest_menu.asi", "kiddions.asi", "eulen.dll", "cherax.dll", "stand.dll",
        "midnight.dll", "phantom_x.dll", "2take1.dll", "paragon.dll", "luna.dll",
        "impulse.dll", "yamyam.dll", "nought.dll", "ozarks.dll", "nova.dll",
        "force.dll", "oshgun.dll", "lambda.dll", "atm.dll", "horsepower.dll",
        "menyoo.dll", "menyooStuff.asi", "gtav_menu.dll", "gta_menu.dll",
        "gta_cheat.dll", "gta_hack.dll", "gta_inject.dll", "gta_bypass.dll",
        "gta_native.dll", "gta_mod.dll", "online_menu.dll", "cheat_menu.dll",
        "hack_menu.dll", "mod_menu.dll", "modmenu.dll", "menu_gta.dll",
        "gtav_cheat.dll", "gtav_hack.dll", "gtav_inject.dll", "gtav_bypass.dll",
        "gtav_native.dll", "gtav_mod.dll", "gta5_menu.dll", "gta5_cheat.dll",
        "gta5_hack.dll", "gta5_inject.dll", "gta5_bypass.dll", "gta5_native.dll",
        "gta5_mod.dll",
    ];

    private static readonly string[] ScriptHookFiles =
    [
        "ScriptHookV.dll", "ScriptHookVDotNet.dll", "ScriptHookVDotNet2.dll",
        "ScriptHookVDotNet3.dll", "ScriptHookVDotNet4.dll", "dinput8.dll",
        "dsound.dll", "winmm.dll", "version.dll",
    ];

    private static readonly string[] GTAModMenuLogPatterns =
    [
        "money drop", "god mode", "teleport", "esp", "aimbot", "unlock all",
        "ban bypass", "gta+ bypass", "kik ban", "bypass rockstar", "modder detected",
        "using menu", "mod menu active", "cheat detected", "anti-cheat bypass",
        "menu injected", "protection bypassed", "ban evasion", "rockstar ban bypass",
        "player crash", "player kick", "money spawn", "cash drop", "vehicle spawn",
        "object spawn", "speed hack", "no clip", "invincible", "unlimited ammo",
        "super jump", "session griefing", "player teleport", "freeze player",
        "explode player", "kick player", "crash session", "session crash",
        "lobby crash", "godmode", "noclip", "moneymod", "spawnvehicle",
        "spawncash", "giveweapon", "kickplayer", "freezeplayer", "explodevehicle",
    ];

    private static readonly string[] ModMenuUserAssistNames =
    [
        "xvqqvbaf.rkr", "xvqqvbaf_zrah.rkr", "zbqrfg_zrah.nfv", "xvqqvbaf.nfv",
        "rhyra.rkr", "rhyra_zrah.rkr", "rhyra_ybnqre.rkr", "rhyra_vawrpgbe.rkr",
        "pureNK.rkr", "pureNK_ybnqre.rkr", "pureNK_zrah.rkr", "pureNK_vawrpgbe.rkr",
        "fgnaq.rkr", "fgnaq_ybnqre.rkr", "fgnaq_zrah.rkr", "fgnaq_vawrpgbe.rkr",
        "zvqavtug.rkr", "zvqavtug_ybnqre.rkr", "zvqavtug_zrah.rkr",
        "cunagbz_k.rkr", "cunagbzk.rkr", "cunagbzk_ybnqre.rkr",
        "2gnxr1.rkr", "2gnxr1_ybnqre.rkr", "2gnxr1_zrah.rkr",
        "cneniba.rkr", "cneniba_tgn.rkr", "cneniba_ybnqre.rkr",
        "yhan.rkr", "yhan_zrah.rkr", "yhan_tgn.rkr", "yhan_ybnqre.rkr",
        "vzcHYfr.rkr", "vzcHYfr_zrah.rkr", "vzcHYfr_tgn.rkr",
        "tgni_zrah.rkr", "tgn_zrah.rkr", "zbqzrah.rkr", "zra_Hzrah.rkr",
        "unpx_zrah.rkr", "purng_zrah.rkr", "tgni_zbqzrah.rkr",
    ];

    private static readonly string[] MuiCacheModMenuNames =
    [
        "kiddions", "modest_menu", "eulen", "cherax", "stand", "midnight",
        "phantom_x", "phantomx", "2take1", "paragon", "luna", "impulse",
        "yamyam", "nought", "ozarks", "nova", "force", "oshgun", "lambda",
        "menyoo", "gtav_menu", "gta_menu", "gta_mod", "gta_cheat", "gta_hack",
        "online_menu", "modmenu", "mod_menu", "gta5_menu", "gta5_cheat",
        "gta5_hack", "menu_gta",
    ];

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.WhenAll(
            CheckKiddionsModeModMenu(ctx, ct),
            CheckEulenModMenu(ctx, ct),
            CheckCheraxModMenu(ctx, ct),
            CheckStandModMenu(ctx, ct),
            CheckMidnightModMenu(ctx, ct),
            CheckPhantomXModMenu(ctx, ct),
            Check2Take1ModMenu(ctx, ct),
            CheckParagonModMenu(ctx, ct),
            CheckLunaModMenu(ctx, ct),
            CheckImpulseModMenu(ctx, ct),
            CheckGenericGTAModMenuExecutables(ctx, ct),
            CheckGTAModMenuDlls(ctx, ct),
            CheckGTAScriptHookArtifacts(ctx, ct),
            CheckGTAModMenuLogs(ctx, ct),
            CheckRegistryForGTAModMenus(ctx, ct)
        );
    }

    private Task CheckKiddionsModeModMenu(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var kiddionsFiles = new[]
        {
            "config.json", "modest_menu.asi", "kiddions.asi",
            "kiddions_menu.exe", "kiddions.exe",
        };
        var kiddionsWildcards = new[] { "kiddions_v*.exe", "modest_menu_v*.zip" };

        var scanDirs = new[]
        {
            Path.Combine(AppData, "Kiddions"),
            Path.Combine(LocalAppData, "Kiddions"),
            Desktop,
            Downloads,
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
                    bool match = kiddionsFiles.Any(k => fn.Equals(k, StringComparison.OrdinalIgnoreCase))
                              || fn.StartsWith("kiddions_v", StringComparison.OrdinalIgnoreCase)
                              || fn.StartsWith("modest_menu_v", StringComparison.OrdinalIgnoreCase);
                    if (match)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Kiddions Modest Menu artifact detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Kiddions Modest Menu forensic artifact found: '{fn}'. " +
                                     "Kiddions is a popular GTA V online mod menu used for money drops, god mode, " +
                                     "ESP and other gameplay-breaking cheats.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var configDir = Path.Combine(AppData, "Kiddions");
        if (Directory.Exists(configDir))
        {
            try
            {
                foreach (var cfgFile in Directory.EnumerateFiles(configDir, "*.json", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(configDir, "*.ini", SearchOption.AllDirectories)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(cfgFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        if (content.Contains("kiddion", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("modest_menu", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("money_drop", StringComparison.OrdinalIgnoreCase)
                            || content.Contains("godmode", StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Kiddions config file artifact",
                                Risk = RiskLevel.High,
                                Location = Path.GetDirectoryName(cfgFile) ?? configDir,
                                FileName = Path.GetFileName(cfgFile),
                                Reason = "Kiddions Modest Menu configuration file found in AppData. " +
                                         "Config files persist even after the menu is deleted.",
                                Detail = $"Config file: {cfgFile}",
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

    private Task CheckEulenModMenu(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var eulenExecutables = new[]
        {
            "eulen.exe", "eulen_menu.exe", "eulen.dll", "eulen_loader.exe",
            "eulen_injector.exe", "eulen_cheat.exe", "eulen_hack.exe",
        };
        var eulenArchivePatterns = new[] { "eulen*.zip", "eulen*.rar" };

        var scanDirs = new List<string>
        {
            Desktop, Downloads, Temp,
            Path.Combine(LocalAppData, "Temp"),
        };
        var eulenAppData = Path.Combine(AppData, "Eulen");
        if (Directory.Exists(eulenAppData)) scanDirs.Add(eulenAppData);

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
                    bool isExe = eulenExecutables.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase));
                    bool isArchive = fn.StartsWith("eulen", StringComparison.OrdinalIgnoreCase)
                                 && (fn.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)
                                  || fn.EndsWith(".rar", StringComparison.OrdinalIgnoreCase));
                    if (isExe || isArchive)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Eulen GTA V mod menu artifact detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Eulen mod menu forensic artifact found: '{fn}'. " +
                                     "Eulen is a subscription-based GTA V mod menu with money drops, vehicle spawning and god mode.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        if (Directory.Exists(eulenAppData))
        {
            try
            {
                foreach (var f in Directory.EnumerateFiles(eulenAppData, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var ext = Path.GetExtension(f);
                    if (ext.Equals(".json", StringComparison.OrdinalIgnoreCase)
                     || ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase)
                     || ext.Equals(".log", StringComparison.OrdinalIgnoreCase)
                     || ext.Equals(".ini", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            if (content.Contains("eulen", StringComparison.OrdinalIgnoreCase)
                             || content.Contains("money", StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "Eulen mod menu config/log artifact",
                                    Risk = RiskLevel.High,
                                    Location = Path.GetDirectoryName(f) ?? eulenAppData,
                                    FileName = Path.GetFileName(f),
                                    Reason = "Eulen mod menu configuration or log file found in AppData. " +
                                             "These files remain as forensic evidence after menu removal.",
                                    Detail = $"File: {f}",
                                });
                                break;
                            }
                        }
                        catch (IOException) { }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckCheraxModMenu(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var cheraxExecutables = new[]
        {
            "cherax.exe", "cherax_loader.exe", "cherax.dll",
            "cherax_menu.exe", "cherax_injector.exe",
        };

        var scanDirs = new List<string> { Desktop, Downloads, Temp };
        var cheraxAppData = Path.Combine(AppData, "Cherax");
        if (Directory.Exists(cheraxAppData)) scanDirs.Add(cheraxAppData);

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
                    bool isExe = cheraxExecutables.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase));
                    bool isArchive = fn.StartsWith("cherax", StringComparison.OrdinalIgnoreCase)
                                 && (fn.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)
                                  || fn.EndsWith(".rar", StringComparison.OrdinalIgnoreCase));
                    if (isExe || isArchive)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Cherax GTA V mod menu artifact detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Cherax mod menu forensic artifact found: '{fn}'. " +
                                     "Cherax is a paid GTA V mod menu featuring god mode, money drops, vehicle spawning and anti-ban features.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        if (Directory.Exists(cheraxAppData))
        {
            try
            {
                foreach (var f in Directory.EnumerateFiles(cheraxAppData, "*", SearchOption.AllDirectories))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Cherax mod menu AppData artifact",
                        Risk = RiskLevel.High,
                        Location = cheraxAppData,
                        FileName = Path.GetFileName(f),
                        Reason = "File found in Cherax mod menu AppData directory. " +
                                 "Presence of the Cherax AppData folder indicates prior or current use.",
                        Detail = $"File: {f}",
                    });
                    break;
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckStandModMenu(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var standExecutables = new[]
        {
            "stand.exe", "stand_loader.exe", "stand.dll", "stand_menu.exe",
            "stand_injector.exe", "stand_gta.exe",
        };

        var scanDirs = new List<string> { Desktop, Downloads, Temp };
        var standAppData = Path.Combine(AppData, "Stand");
        var standLocalAppData = Path.Combine(LocalAppData, "Stand");
        if (Directory.Exists(standAppData)) scanDirs.Add(standAppData);
        if (Directory.Exists(standLocalAppData)) scanDirs.Add(standLocalAppData);

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
                    bool isExe = standExecutables.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase));
                    bool isArchive = fn.StartsWith("stand", StringComparison.OrdinalIgnoreCase)
                                 && (fn.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)
                                  || fn.EndsWith(".rar", StringComparison.OrdinalIgnoreCase));
                    if (isExe || isArchive)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Stand GTA V mod menu artifact detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Stand mod menu forensic artifact found: '{fn}'. " +
                                     "Stand is a premium GTA V mod menu with advanced features including recovery, griefing tools and anti-ban bypasses.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        foreach (var standDir in new[] { standAppData, standLocalAppData })
        {
            if (!Directory.Exists(standDir)) continue;
            try
            {
                foreach (var f in Directory.EnumerateFiles(standDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(standDir, "*.json", SearchOption.AllDirectories))
                    .Take(5))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        if (content.Length > 10)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = "Stand mod menu config/log artifact",
                                Risk = RiskLevel.High,
                                Location = standDir,
                                FileName = Path.GetFileName(f),
                                Reason = "Stand mod menu data file found. Configuration and log artifacts persist as forensic evidence.",
                                Detail = $"File: {f}",
                            });
                            break;
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckMidnightModMenu(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var midnightExecutables = new[]
        {
            "midnight.exe", "midnight_loader.exe", "midnight.dll",
            "midnight_menu.exe", "midnight_injector.exe",
        };

        var scanDirs = new List<string> { Desktop, Downloads, Temp };
        var midnightAppData = Path.Combine(AppData, "Midnight");
        if (Directory.Exists(midnightAppData)) scanDirs.Add(midnightAppData);

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
                    bool isExe = midnightExecutables.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase));
                    bool isArchive = fn.StartsWith("midnight_gta", StringComparison.OrdinalIgnoreCase)
                                 && fn.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);
                    if (isExe || isArchive)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Midnight GTA V mod menu artifact detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Midnight mod menu forensic artifact found: '{fn}'. " +
                                     "Midnight is a GTA V mod menu targeting Online gameplay with god mode and money features.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        if (Directory.Exists(midnightAppData))
        {
            try
            {
                foreach (var f in Directory.EnumerateFiles(midnightAppData, "*", SearchOption.AllDirectories).Take(3))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Midnight mod menu AppData artifact",
                        Risk = RiskLevel.High,
                        Location = midnightAppData,
                        FileName = Path.GetFileName(f),
                        Reason = "File found in Midnight mod menu AppData directory. " +
                                 "This directory is created by the Midnight GTA V mod menu during installation or use.",
                        Detail = $"File: {f}",
                    });
                    break;
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckPhantomXModMenu(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var phantomExecutables = new[]
        {
            "phantom_x.exe", "phantom-x.exe", "phantomx.exe", "phantomx_loader.exe",
            "phantom_x.dll", "phantomx.dll",
        };

        var scanDirs = new List<string> { Desktop, Downloads, Temp };
        var phantomAppData = Path.Combine(AppData, "PhantomX");
        if (Directory.Exists(phantomAppData)) scanDirs.Add(phantomAppData);

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
                    bool isExe = phantomExecutables.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase));
                    bool isArchive = (fn.StartsWith("phantom_x", StringComparison.OrdinalIgnoreCase)
                                   && fn.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                                 || (fn.StartsWith("phantomx", StringComparison.OrdinalIgnoreCase)
                                   && fn.EndsWith(".rar", StringComparison.OrdinalIgnoreCase));
                    if (isExe || isArchive)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Phantom-X GTA V mod menu artifact detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Phantom-X mod menu forensic artifact found: '{fn}'. " +
                                     "Phantom-X is a GTA V mod menu with bypasses for Rockstar anti-cheat measures.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        if (Directory.Exists(phantomAppData))
        {
            try
            {
                foreach (var f in Directory.EnumerateFiles(phantomAppData, "*", SearchOption.AllDirectories).Take(3))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Phantom-X mod menu AppData artifact",
                        Risk = RiskLevel.High,
                        Location = phantomAppData,
                        FileName = Path.GetFileName(f),
                        Reason = "File found in Phantom-X mod menu AppData directory. " +
                                 "This directory is created by the Phantom-X GTA V mod menu.",
                        Detail = $"File: {f}",
                    });
                    break;
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task Check2Take1ModMenu(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var take1Executables = new[]
        {
            "2take1.exe", "2take1_loader.exe", "2take1.dll", "2take1_menu.exe",
        };

        var scanDirs = new List<string> { Desktop, Downloads, Temp };
        var take1AppData = Path.Combine(AppData, "2Take1");
        var take1LocalAppData = Path.Combine(LocalAppData, "2Take1");
        if (Directory.Exists(take1AppData)) scanDirs.Add(take1AppData);
        if (Directory.Exists(take1LocalAppData)) scanDirs.Add(take1LocalAppData);

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
                    bool isExe = take1Executables.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase));
                    bool isArchive = fn.StartsWith("2take1", StringComparison.OrdinalIgnoreCase)
                                 && (fn.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)
                                  || fn.EndsWith(".rar", StringComparison.OrdinalIgnoreCase));
                    if (isExe || isArchive)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "2Take1 GTA V mod menu artifact detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"2Take1 mod menu forensic artifact found: '{fn}'. " +
                                     "2Take1 is a notorious GTA V mod menu with session crashers, player harassment and money drop features.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        foreach (var appDataDir in new[] { take1AppData, take1LocalAppData })
        {
            if (!Directory.Exists(appDataDir)) continue;
            try
            {
                foreach (var f in Directory.EnumerateFiles(appDataDir, "*", SearchOption.AllDirectories).Take(3))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "2Take1 mod menu AppData artifact",
                        Risk = RiskLevel.High,
                        Location = appDataDir,
                        FileName = Path.GetFileName(f),
                        Reason = "File found in 2Take1 mod menu AppData directory. " +
                                 "2Take1 config/data directories persist as strong forensic evidence of use.",
                        Detail = $"File: {f}",
                    });
                    break;
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckParagonModMenu(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var paragonExecutables = new[]
        {
            "paragon.exe", "paragon_gta.exe", "paragon_loader.exe",
            "paragon.dll", "paragon_menu.exe",
        };

        var scanDirs = new List<string> { Desktop, Downloads, Temp };
        var paragonAppData = Path.Combine(AppData, "Paragon");
        if (Directory.Exists(paragonAppData)) scanDirs.Add(paragonAppData);

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
                    bool isExe = paragonExecutables.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase));
                    bool isArchive = fn.StartsWith("paragon_gta", StringComparison.OrdinalIgnoreCase)
                                 && fn.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);
                    if (isExe || isArchive)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Paragon GTA V mod menu artifact detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Paragon mod menu forensic artifact found: '{fn}'. " +
                                     "Paragon is a GTA V mod menu with money recovery, session control and griefing capabilities.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        if (Directory.Exists(paragonAppData))
        {
            try
            {
                foreach (var f in Directory.EnumerateFiles(paragonAppData, "*", SearchOption.AllDirectories).Take(3))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Paragon mod menu AppData artifact",
                        Risk = RiskLevel.High,
                        Location = paragonAppData,
                        FileName = Path.GetFileName(f),
                        Reason = "File found in Paragon mod menu AppData directory.",
                        Detail = $"File: {f}",
                    });
                    break;
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckLunaModMenu(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var lunaExecutables = new[]
        {
            "luna.exe", "luna_menu.exe", "luna_gta.exe", "luna.dll", "luna_loader.exe",
        };

        var scanDirs = new List<string> { Desktop, Downloads, Temp };
        var lunaAppData = Path.Combine(AppData, "Luna");
        if (Directory.Exists(lunaAppData)) scanDirs.Add(lunaAppData);

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
                    bool isExe = lunaExecutables.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase));
                    bool isArchive = fn.StartsWith("luna_gta", StringComparison.OrdinalIgnoreCase)
                                     && fn.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)
                                  || fn.StartsWith("luna", StringComparison.OrdinalIgnoreCase)
                                     && fn.EndsWith(".rar", StringComparison.OrdinalIgnoreCase);
                    if (isExe || isArchive)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Luna GTA V mod menu artifact detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Luna mod menu forensic artifact found: '{fn}'. " +
                                     "Luna is a GTA V mod menu with recovery, trolling and session manipulation features.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        if (Directory.Exists(lunaAppData))
        {
            try
            {
                foreach (var f in Directory.EnumerateFiles(lunaAppData, "*", SearchOption.AllDirectories).Take(3))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Luna mod menu AppData artifact",
                        Risk = RiskLevel.High,
                        Location = lunaAppData,
                        FileName = Path.GetFileName(f),
                        Reason = "File found in Luna mod menu AppData directory.",
                        Detail = $"File: {f}",
                    });
                    break;
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckImpulseModMenu(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var impulseExecutables = new[]
        {
            "impulse.exe", "impulse_menu.exe", "impulse_gta.exe",
            "impulse.dll", "impulse_loader.exe",
        };

        var scanDirs = new List<string> { Desktop, Downloads, Temp };
        var impulseAppData = Path.Combine(AppData, "Impulse");
        if (Directory.Exists(impulseAppData)) scanDirs.Add(impulseAppData);

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
                    bool isExe = impulseExecutables.Any(e => fn.Equals(e, StringComparison.OrdinalIgnoreCase));
                    bool isArchive = fn.StartsWith("impulse", StringComparison.OrdinalIgnoreCase)
                                  && fn.EndsWith(".zip", StringComparison.OrdinalIgnoreCase);
                    if (isExe || isArchive)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Impulse GTA V mod menu artifact detected",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Impulse mod menu forensic artifact found: '{fn}'. " +
                                     "Impulse is a GTA V mod menu featuring money drops, god mode, ESP and vehicle spawning.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        if (Directory.Exists(impulseAppData))
        {
            try
            {
                foreach (var f in Directory.EnumerateFiles(impulseAppData, "*", SearchOption.AllDirectories).Take(3))
                {
                    ctx.IncrementFiles();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Impulse mod menu AppData artifact",
                        Risk = RiskLevel.High,
                        Location = impulseAppData,
                        FileName = Path.GetFileName(f),
                        Reason = "File found in Impulse mod menu AppData directory.",
                        Detail = $"File: {f}",
                    });
                    break;
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckGenericGTAModMenuExecutables(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var scanDirs = new[]
        {
            Desktop, Downloads, Temp,
            Path.Combine(LocalAppData, "Temp"),
            AppData, LocalAppData,
        };

        var nameSet = new HashSet<string>(GenericGTAModMenuExecutables, StringComparer.OrdinalIgnoreCase);

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
                    if (nameSet.Contains(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Generic GTA V mod menu executable: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known GTA V mod menu executable name detected: '{fn}'. " +
                                     "This file name matches a pattern associated with GTA V mod menus or cheat tools.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckGTAModMenuDlls(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        var dllSet = new HashSet<string>(GTAModMenuDlls, StringComparer.OrdinalIgnoreCase);

        var scanDirs = new List<string> { Documents, AppData, Temp };
        scanDirs.AddRange(GetGTAVGameDirs());

        foreach (var dir in scanDirs)
        {
            if (!Directory.Exists(dir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, "*.dll", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(dir, "*.asi", SearchOption.AllDirectories)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (dllSet.Contains(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"GTA V mod menu DLL/ASI artifact: {fn}",
                            Risk = RiskLevel.High,
                            Location = Path.GetDirectoryName(file) ?? dir,
                            FileName = fn,
                            Reason = $"Known GTA V mod menu DLL or ASI plugin detected: '{fn}'. " +
                                     "ASI plugins are loaded by ScriptHookV and DLLs may be injected by mod menu loaders. " +
                                     "This file is associated with GTA V mod menus or cheat injectors.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckGTAScriptHookArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var hookSet = new HashSet<string>(ScriptHookFiles, StringComparer.OrdinalIgnoreCase);

        foreach (var gameDir in GetGTAVGameDirs())
        {
            if (!Directory.Exists(gameDir)) continue;
            try
            {
                foreach (var file in Directory.EnumerateFiles(gameDir, "*.dll", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    if (hookSet.Contains(fn))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"ScriptHookV injection vector: {fn}",
                            Risk = RiskLevel.High,
                            Location = gameDir,
                            FileName = fn,
                            Reason = $"Script injection vector DLL found in GTA V game directory: '{fn}'. " +
                                     "ScriptHookV and proxy DLLs (dinput8.dll, dsound.dll, winmm.dll, version.dll) " +
                                     "are used to load ASI plugins including mod menus. These are cheat injection vector evidence.",
                            Detail = $"Full path: {file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        var scriptHookDotNetDir = Path.Combine(AppData, "ScriptHookVDotNet");
        if (Directory.Exists(scriptHookDotNetDir))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(scriptHookDotNetDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(scriptHookDotNetDir, "*.dll", SearchOption.AllDirectories)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);
                    var ext = Path.GetExtension(file);

                    if (ext.Equals(".dll", StringComparison.OrdinalIgnoreCase))
                    {
                        var cheatKeywords = new[]
                        {
                            "hack", "cheat", "menu", "aimbot", "esp", "godmode", "money", "inject"
                        };
                        if (cheatKeywords.Any(k => fn.Contains(k, StringComparison.OrdinalIgnoreCase)))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Suspicious DLL in ScriptHookVDotNet directory: {fn}",
                                Risk = RiskLevel.High,
                                Location = scriptHookDotNetDir,
                                FileName = fn,
                                Reason = "Suspicious DLL with cheat-related name found in ScriptHookVDotNet AppData directory. " +
                                         "ScriptHookVDotNet loads .NET DLLs for GTA V scripting and is a common injection vector.",
                                Detail = $"File: {file}",
                            });
                        }
                    }
                    else if (ext.Equals(".log", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            using var sr = new StreamReader(fs);
                            string content = await sr.ReadToEndAsync(ct);
                            var lower = content.ToLowerInvariant();
                            var cheatLogKeywords = new[]
                            {
                                "cheat", "hack", "money", "godmode", "aimbot", "esp", "menu loaded", "inject"
                            };
                            foreach (var kw in cheatLogKeywords)
                            {
                                if (lower.Contains(kw))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = "ScriptHookVDotNet log contains cheat keyword",
                                        Risk = RiskLevel.High,
                                        Location = scriptHookDotNetDir,
                                        FileName = fn,
                                        Reason = $"ScriptHookVDotNet log file contains cheat-related keyword '{kw}'. " +
                                                 "Log entries from injected mod menu scripts are captured in ScriptHookVDotNet logs.",
                                        Detail = $"Log file: {file} | Keyword: {kw}",
                                    });
                                    break;
                                }
                            }
                        }
                        catch (IOException) { }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckGTAModMenuLogs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        var logDirs = new List<string>
        {
            Path.Combine(AppData, "Rockstar Games", "GTA V"),
            Path.Combine(LocalAppData, "Rockstar Games", "GTA V"),
            Path.Combine(AppData, "Kiddions"),
            Path.Combine(AppData, "Eulen"),
            Path.Combine(AppData, "Cherax"),
            Path.Combine(AppData, "Stand"),
            Path.Combine(AppData, "2Take1"),
        };

        var patterns = GTAModMenuLogPatterns;

        foreach (var logDir in logDirs)
        {
            if (!Directory.Exists(logDir)) continue;
            try
            {
                foreach (var logFile in Directory.EnumerateFiles(logDir, "*.log", SearchOption.AllDirectories)
                    .Concat(Directory.EnumerateFiles(logDir, "*.txt", SearchOption.AllDirectories))
                    .Concat(Directory.EnumerateFiles(logDir, "*.json", SearchOption.AllDirectories)))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);
                        var lower = content.ToLowerInvariant();
                        foreach (var pattern in patterns)
                        {
                            if (lower.Contains(pattern.ToLowerInvariant()))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = "GTA V mod menu activity found in log file",
                                    Risk = RiskLevel.High,
                                    Location = logDir,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"GTA V log file contains mod menu activity indicator: '{pattern}'. " +
                                             "Log artifacts persist as forensic evidence of cheat tool usage even after uninstallation.",
                                    Detail = $"Log file: {logFile} | Pattern: {pattern}",
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }
    }, ct);

    private Task CheckRegistryForGTAModMenus(ScanContext ctx, CancellationToken ct) => Task.Run(() =>
    {
        CheckUserAssistForGTAMenus(ctx, ct);
        CheckMuiCacheForGTAMenus(ctx, ct);
        CheckRunKeysForGTAMenus(ctx, ct);
        CheckSoftwareKeysForGTAMenus(ctx, ct);
        CheckUninstallKeysForGTAMenus(ctx, ct);
    }, ct);

    private void CheckUserAssistForGTAMenus(ScanContext ctx, CancellationToken ct)
    {
        const string userAssistBase = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
        var rot13Names = ModMenuUserAssistNames;

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
                        var decoded = Rot13Decode(encodedName).ToLowerInvariant();

                        bool isMatch = rot13Names.Any(r => Rot13Decode(r).Equals(
                                           Path.GetFileName(decoded), StringComparison.OrdinalIgnoreCase))
                                    || new[]
                                    {
                                        "kiddion", "eulen", "cherax", "stand_gta", "midnight", "phantom_x",
                                        "phantomx", "2take1", "paragon_gta", "luna_gta", "impulse_gta",
                                        "gtav_menu", "gta_menu", "modmenu", "mod_menu", "menyoo",
                                        "yamyam", "nought", "ozarks", "nova_gta", "oshgun", "lambda_menu",
                                        "cheat_menu", "hack_menu", "gta5_menu", "gta5_cheat", "gta5_hack",
                                    }.Any(k => decoded.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (!isMatch) continue;

                        int runCount = 0;
                        DateTime? lastRun = null;
                        try
                        {
                            var data = countKey.GetValue(encodedName) as byte[];
                            if (data is { Length: >= 16 })
                            {
                                runCount = BitConverter.ToInt32(data, 4);
                                var fileTime = BitConverter.ToInt64(data, 8);
                                if (fileTime > 0) lastRun = DateTime.FromFileTimeUtc(fileTime);
                            }
                        }
                        catch { }

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"UserAssist: GTA V mod menu executed — {Path.GetFileName(decoded)}",
                            Risk = RiskLevel.High,
                            Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                            FileName = Path.GetFileName(decoded),
                            Reason = $"Windows UserAssist registry entry shows execution of GTA V mod menu tool: '{Path.GetFileName(decoded)}' " +
                                     $"({runCount}x run" +
                                     (lastRun.HasValue ? $", last seen {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                     "). UserAssist entries persist even after the executable is deleted.",
                            Detail = $"Decoded: {decoded} | Runs: {runCount} | Last: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unknown")}",
                        });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void CheckMuiCacheForGTAMenus(ScanContext ctx, CancellationToken ct)
    {
        const string muiCachePath = @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
        var menuNames = MuiCacheModMenuNames;

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(muiCachePath, writable: false);
            if (key is null) return;

            foreach (var valName in key.GetValueNames())
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementRegistryKeys();
                var lower = valName.ToLowerInvariant();
                var hit = menuNames.FirstOrDefault(m => lower.Contains(m.ToLowerInvariant()));
                if (hit is null) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"MUICache: GTA V mod menu execution trace — {hit}",
                    Risk = RiskLevel.High,
                    Location = $@"HKCU\{muiCachePath}",
                    FileName = Path.GetFileName(valName.Split('\0')[0]),
                    Reason = $"MUICache registry entry indicates execution of GTA V mod menu tool containing keyword '{hit}'. " +
                             "MUICache stores friendly names for recently launched executables and persists after deletion.",
                    Detail = $"Registry value: {valName}",
                });
            }
        }
        catch { }
    }

    private void CheckRunKeysForGTAMenus(ScanContext ctx, CancellationToken ct)
    {
        var runKeys = new[]
        {
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        };
        var gtaMenuKeywords = new[]
        {
            "kiddion", "eulen", "cherax", "stand", "midnight", "phantom_x", "phantomx",
            "2take1", "paragon", "luna", "impulse", "modmenu", "gta_menu", "gta5_menu",
            "menyoo", "yamyam", "nought", "ozarks", "nova_gta", "oshgun",
        };

        foreach (var keyPath in runKeys)
        {
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var key = hive.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    foreach (var valName in key.GetValueNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();
                        var valData = key.GetValue(valName)?.ToString() ?? string.Empty;
                        var combined = (valName + " " + valData).ToLowerInvariant();
                        var hit = gtaMenuKeywords.FirstOrDefault(k => combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                        if (hit is null) continue;

                        var hiveName = hive == Registry.CurrentUser ? "HKCU" : "HKLM";
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"GTA V mod menu auto-start registry entry: {valName}",
                            Risk = RiskLevel.High,
                            Location = $@"{hiveName}\{keyPath}",
                            FileName = Path.GetFileName(valData.Trim('"').Split(' ')[0]),
                            Reason = $"GTA V mod menu found in auto-start registry key. " +
                                     $"Value '{valName}' with data '{valData}' matches mod menu keyword '{hit}'. " +
                                     "Auto-start entries indicate persistent or scheduled mod menu execution.",
                            Detail = $"Key: {hiveName}\\{keyPath} | Value: {valName} | Data: {valData}",
                        });
                    }
                }
                catch { }
            }
        }
    }

    private void CheckSoftwareKeysForGTAMenus(ScanContext ctx, CancellationToken ct)
    {
        var modMenuSoftwareKeys = new[]
        {
            @"SOFTWARE\Kiddions", @"SOFTWARE\Kiddions Modest Menu",
            @"SOFTWARE\Eulen", @"SOFTWARE\Eulen Menu",
            @"SOFTWARE\Cherax", @"SOFTWARE\Cherax Menu",
            @"SOFTWARE\Stand", @"SOFTWARE\Stand GTA",
            @"SOFTWARE\2Take1", @"SOFTWARE\2Take1 Menu",
            @"SOFTWARE\Midnight Menu", @"SOFTWARE\PhantomX",
            @"SOFTWARE\Paragon GTA", @"SOFTWARE\Luna GTA",
            @"SOFTWARE\Impulse GTA", @"SOFTWARE\GTAModMenu",
            @"SOFTWARE\ModMenu", @"SOFTWARE\Menyoo",
        };

        foreach (var keyPath in modMenuSoftwareKeys)
        {
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var key = hive.OpenSubKey(keyPath, writable: false);
                    if (key is null) continue;

                    ctx.IncrementRegistryKeys();
                    var hiveName = hive == Registry.CurrentUser ? "HKCU" : "HKLM";
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"GTA V mod menu software registry key found: {keyPath}",
                        Risk = RiskLevel.High,
                        Location = $@"{hiveName}\{keyPath}",
                        Reason = $"GTA V mod menu specific software registry key detected: '{keyPath}'. " +
                                 "Mod menus often create registry keys for configuration, licensing or auto-start purposes.",
                        Detail = $"Registry key: {hiveName}\\{keyPath}",
                    });
                }
                catch { }
            }
        }
    }

    private void CheckUninstallKeysForGTAMenus(ScanContext ctx, CancellationToken ct)
    {
        const string uninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        const string uninstallPath32 = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
        var modMenuKeywords = new[]
        {
            "kiddion", "eulen", "cherax", "stand", "midnight", "phantom-x", "phantomx",
            "2take1", "paragon gta", "luna gta", "impulse gta", "gta mod menu",
            "gtav menu", "menyoo", "modmenu", "mod menu gta",
        };

        foreach (var uninstPath in new[] { uninstallPath, uninstallPath32 })
        {
            foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var baseKey = hive.OpenSubKey(uninstPath, writable: false);
                    if (baseKey is null) continue;

                    foreach (var subName in baseKey.GetSubKeyNames())
                    {
                        ct.ThrowIfCancellationRequested();
                        ctx.IncrementRegistryKeys();
                        try
                        {
                            using var subKey = baseKey.OpenSubKey(subName, writable: false);
                            var displayName = subKey?.GetValue("DisplayName")?.ToString() ?? string.Empty;
                            var publisher = subKey?.GetValue("Publisher")?.ToString() ?? string.Empty;
                            var combined = (displayName + " " + publisher + " " + subName).ToLowerInvariant();

                            var hit = modMenuKeywords.FirstOrDefault(k => combined.Contains(k, StringComparison.OrdinalIgnoreCase));
                            if (hit is null) continue;

                            var hiveName = hive == Registry.CurrentUser ? "HKCU" : "HKLM";
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"GTA V mod menu installer record found: {displayName}",
                                Risk = RiskLevel.High,
                                Location = $@"{hiveName}\{uninstPath}\{subName}",
                                Reason = $"GTA V mod menu installer entry found in Uninstall registry. " +
                                         $"Display name '{displayName}' matches mod menu keyword '{hit}'. " +
                                         "Uninstall entries persist as forensic evidence even after removal.",
                                Detail = $"DisplayName: {displayName} | Publisher: {publisher} | Key: {subName}",
                            });
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
    }

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
}
