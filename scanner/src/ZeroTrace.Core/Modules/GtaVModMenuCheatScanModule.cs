using System.Diagnostics;
using Microsoft.Win32;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class GtaVModMenuCheatScanModule : IScanModule
{
    public string Name => "GTA V Mod Menu / Cheat";
    public double Weight => 0.65;
    public int ParallelGroup => 4;

    private static readonly HashSet<string> KnownModMenuExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "menyoo.exe", "menyoopc.exe", "kiddion.exe", "kiddionsmb.exe", "kiddions_mb.exe",
        "modest_menu.exe", "simplegta.exe", "lambdamenu.exe", "lambda_menu.exe",
        "gtavcheats.exe", "online_cheats.exe", "gtao_cheats.exe", "orbital_menu.exe",
        "cherax.exe", "2take1.exe", "2take1menu.exe", "brute.exe", "brutemenu.exe",
        "midnight.exe", "midnight_menu.exe", "stand_menu.exe", "stand.exe",
        "eulen_gta.exe", "lynx_gta.exe", "wexternal.exe", "phantom_gta.exe", "nova_menu.exe"
    };

    private static readonly HashSet<string> KnownModMenuDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "menyoo.dll", "ScriptHookV.dll", "ScriptHookVDotNet.dll", "kiddion.dll",
        "lambda.dll", "orbital.dll", "cherax.dll", "2take1.dll", "stand.dll",
        "midnight.dll", "brute.dll"
    };

    private static readonly HashSet<string> AsiLoaderDllNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "dinput8.dll", "dsound.dll", "version.dll"
    };

    private static readonly string[] AsiLoaderLogFiles =
    {
        "ASILoader.log", "asiloader.log", "ScriptHookV.log", "ScriptHookVDotNet.log"
    };

    private static readonly string[] CheatAsiKeywords =
    {
        "menyoo", "lambda", "kiddion", "stand", "cherax", "orbital", "2take1", "brute",
        "midnight", "nova", "phantom", "trainer", "cheat", "hack", "menu", "godmode",
        "money", "modmenu"
    };

    private static readonly string[] KiddionConfigKeywords =
    {
        "aimbot", "godMode", "neverWanted", "moneyDrop", "vehicleSpawn", "teleport", "invisible"
    };

    private static readonly string[] GtaoCheatConfigKeywords =
    {
        "aimbot", "godmode", "noclip", "moneyloop", "vehiclespawn", "invisible",
        "neverWanted", "moneyDrop", "teleport"
    };

    private static readonly string[] GtaVInstallPaths =
    {
        @"C:\Program Files\Rockstar Games\Grand Theft Auto V",
        @"C:\Program Files (x86)\Rockstar Games\Grand Theft Auto V",
        @"D:\Grand Theft Auto V",
        @"C:\Program Files\Epic Games\GTAV"
    };

    private static readonly string[] PrefetchModMenuPatterns =
    {
        "MENYOO", "KIDDION", "LAMBDAMENU", "LAMBDA_MENU", "2TAKE1", "CHERAX",
        "ORBITAL", "STAND", "MIDNIGHT", "BRUTE", "KIDDIONSMB", "KIDDIONS_MB",
        "STAND_MENU", "NOVA_MENU", "PHANTOM_GTA", "ORBITAL_MENU", "BRUTEMENU",
        "MIDNIGHT_MENU", "SIMPLEGTA", "GTAVCHEATS", "ONLINE_CHEATS"
    };

    private static readonly string[] GtaVCommandlineAntiDetectFlags =
    {
        "-nocheatdetect", "-noanticheat", "--skipintro"
    };

    private static readonly string[] GtaVLogCheatKeywords =
    {
        "mod menu", "modmenu", "ScriptHook", "menyoo", "kiddion", "stand", "2take1",
        "cherax", "orbital", "lambda", "brute", "midnight"
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await ScanUserDirectoriesForModMenuExeAsync(ctx, ct);
        ctx.Report(0.15, "Mod Menu EXE", "Bekannte Mod-Menu-Executables gesucht");

        await ScanGtaVInstallDirectoriesAsync(ctx, ct);
        ctx.Report(0.32, "GTA V Verzeichnis", "GTA V Installationsverzeichnis geprueft");

        await ScanKiddionArtifactsAsync(ctx, ct);
        ctx.Report(0.44, "Kiddion Artefakte", "Kiddion's Modest Menu Artefakte geprueft");

        await Scan2Take1ArtifactsAsync(ctx, ct);
        ctx.Report(0.54, "2Take1 Artefakte", "2Take1 Menu Artefakte geprueft");

        await ScanStandMenuArtifactsAsync(ctx, ct);
        ctx.Report(0.62, "Stand Artefakte", "Stand Menu Artefakte geprueft");

        await ScanOtherMenuArtifactsAsync(ctx, ct);
        ctx.Report(0.70, "Andere Menus", "Weitere Mod-Menu-Artefakte geprueft");

        await ScanGtaoMoneyGlitchScriptsAsync(ctx, ct);
        ctx.Report(0.78, "Money-Glitch-Skripte", "GTAO-Money-Glitch-Skripte gesucht");

        ScanPrefetchArtifacts(ctx, ct);
        ctx.Report(0.85, "Prefetch", "Prefetch-Artefakte geprueft");

        await ScanGtaVModAccountArtifactsAsync(ctx, ct);
        ctx.Report(0.92, "Modded Account", "GTA V Modded-Account-Artefakte geprueft");

        ScanRegistryArtifacts(ctx, ct);
        ctx.Report(0.96, "Registry", "Registry-Artefakte geprueft");

        ScanRunningProcesses(ctx, ct);
        ctx.Report(1.0, "Prozesse", "Laufende Mod-Menu-Prozesse geprueft");
    }

    private async Task ScanUserDirectoriesForModMenuExeAsync(ScanContext ctx, CancellationToken ct)
    {
        var searchDirs = GetUserSearchDirectories();

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;

            string[] exeFiles = Array.Empty<string>();
            try { exeFiles = Directory.GetFiles(dir, "*.exe", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var file in exeFiles)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                if (!KnownModMenuExeNames.Contains(fileName)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Bekanntes GTA V Mod-Menu-Executable: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Die Datei '{fileName}' ist ein bekanntes GTA V Mod-Menu- oder " +
                             "Cheat-Tool. Solche Programme werden verwendet, um in GTA Online " +
                             "zu cheaten (Godmode, Money-Drop, Aimbot usw.).",
                    Detail = $"Gefunden in: {dir}"
                });
            }

            string[] dllFiles = Array.Empty<string>();
            try { dllFiles = Directory.GetFiles(dir, "*.dll", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { }
            catch { }

            foreach (var file in dllFiles)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var fileName = Path.GetFileName(file);
                if (!KnownModMenuDllNames.Contains(fileName)) continue;

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Bekannte GTA V Mod-Menu-DLL: {fileName}",
                    Risk = RiskLevel.High,
                    Location = file,
                    FileName = fileName,
                    Reason = $"Die DLL '{fileName}' ist eine bekannte GTA V Mod-Menu-Komponente. " +
                             "Diese DLLs werden in den GTA V Prozess geladen, um Cheat-Funktionen " +
                             "wie Godmode, Money-Drop und Aimbot zu aktivieren.",
                    Detail = $"Gefunden in: {dir}"
                });
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanGtaVInstallDirectoriesAsync(ScanContext ctx, CancellationToken ct)
    {
        foreach (var gtaDir in GtaVInstallPaths)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(gtaDir)) continue;

            await ScanGtaVRootForCheatDllsAsync(gtaDir, ctx, ct);
            ScanGtaVForAsiLoaderLogs(gtaDir, ctx);
            await ScanGtaVForCheatAsiFilesAsync(gtaDir, ctx, ct);
            await ScanGtaVScriptsDirectoryAsync(gtaDir, ctx, ct);
        }
    }

    private async Task ScanGtaVRootForCheatDllsAsync(string gtaDir, ScanContext ctx, CancellationToken ct)
    {
        string[] allDlls = Array.Empty<string>();
        try { allDlls = Directory.GetFiles(gtaDir, "*.dll"); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var dllPath in allDlls)
        {
            if (ct.IsCancellationRequested) break;
            ctx.IncrementFiles();

            var dllName = Path.GetFileName(dllPath);

            if (KnownModMenuDllNames.Contains(dllName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Mod-Menu-DLL im GTA V Verzeichnis: {dllName}",
                    Risk = RiskLevel.Critical,
                    Location = dllPath,
                    FileName = dllName,
                    Reason = $"Die bekannte Mod-Menu-DLL '{dllName}' befindet sich direkt im " +
                             "GTA V Installationsverzeichnis. Das Vorhandensein dieser DLL zeigt, " +
                             "dass das Mod-Menu aktiv in GTA V installiert ist.",
                    Detail = $"GTA V Verzeichnis: {gtaDir}"
                });
            }
            else if (AsiLoaderDllNames.Contains(dllName))
            {
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"ASI-Loader-DLL im GTA V Verzeichnis: {dllName}",
                    Risk = RiskLevel.High,
                    Location = dllPath,
                    FileName = dllName,
                    Reason = $"Die DLL '{dllName}' im GTA V Verzeichnis ist ein bekannter ASI-Loader " +
                             "(Mod-Loader). ASI-Loader werden verwendet, um ASI-Plugins (Mod-Menus) " +
                             "automatisch in GTA V zu laden. Legitime GTA V Installationen " +
                             "enthalten diese Datei nicht.",
                    Detail = $"GTA V Verzeichnis: {gtaDir}"
                });
            }
        }

        await Task.CompletedTask;
    }

    private void ScanGtaVForAsiLoaderLogs(string gtaDir, ScanContext ctx)
    {
        foreach (var logFileName in AsiLoaderLogFiles)
        {
            var logPath = Path.Combine(gtaDir, logFileName);
            if (!File.Exists(logPath)) continue;

            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"ASI-Loader-Log im GTA V Verzeichnis: {logFileName}",
                Risk = RiskLevel.High,
                Location = logPath,
                FileName = logFileName,
                Reason = $"Die Log-Datei '{logFileName}' beweist, dass ein ASI-Loader/ScriptHook " +
                         "in GTA V aktiv war. ASI-Loader sind Voraussetzung fuer das Laden von " +
                         "Mod-Menus und Cheat-Plugins in GTA V.",
                Detail = $"GTA V Verzeichnis: {gtaDir}"
            });
        }
    }

    private async Task ScanGtaVForCheatAsiFilesAsync(string gtaDir, ScanContext ctx, CancellationToken ct)
    {
        string[] asiFiles = Array.Empty<string>();
        try { asiFiles = Directory.GetFiles(gtaDir, "*.asi"); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var asiPath in asiFiles)
        {
            if (ct.IsCancellationRequested) break;
            ctx.IncrementFiles();

            var asiName = Path.GetFileNameWithoutExtension(asiPath).ToLowerInvariant();
            var matchedKeyword = CheatAsiKeywords
                .FirstOrDefault(k => asiName.Contains(k.ToLowerInvariant()));

            if (matchedKeyword != null)
            {
                var fileName = Path.GetFileName(asiPath);
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Cheat-ASI-Plugin im GTA V Verzeichnis: {fileName}",
                    Risk = RiskLevel.Critical,
                    Location = asiPath,
                    FileName = fileName,
                    Reason = $"Die ASI-Datei '{fileName}' hat einen Namen, der auf ein Mod-Menu " +
                             $"oder Cheat-Plugin hinweist (Schluesselbegriff: '{matchedKeyword}'). " +
                             "ASI-Dateien werden vom ASI-Loader direkt in GTA V geladen und " +
                             "ermöglichen Cheat-Funktionen wie Godmode, Money-Drop und ESP.",
                    Detail = $"Passender Schluesselbegriff: '{matchedKeyword}', GTA V: {gtaDir}"
                });
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanGtaVScriptsDirectoryAsync(string gtaDir, ScanContext ctx, CancellationToken ct)
    {
        var scriptsDir = Path.Combine(gtaDir, "scripts");
        if (!Directory.Exists(scriptsDir)) return;

        string[] scriptFiles = Array.Empty<string>();
        try { scriptFiles = Directory.GetFiles(scriptsDir, "*", SearchOption.AllDirectories); }
        catch (UnauthorizedAccessException) { return; }
        catch { return; }

        foreach (var scriptFile in scriptFiles)
        {
            if (ct.IsCancellationRequested) break;
            ctx.IncrementFiles();

            var scriptFileName = Path.GetFileName(scriptFile);
            var scriptNameLower = Path.GetFileNameWithoutExtension(scriptFile).ToLowerInvariant();
            var ext = Path.GetExtension(scriptFile).ToLowerInvariant();

            if (ext != ".dll" && ext != ".cs" && ext != ".asi") continue;

            var matchedKeyword = CheatAsiKeywords
                .FirstOrDefault(k => scriptNameLower.Contains(k.ToLowerInvariant()));

            if (matchedKeyword == null && !KnownModMenuDllNames.Contains(scriptFileName)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Cheat-Skript im GTA V scripts-Verzeichnis: {scriptFileName}",
                Risk = RiskLevel.Critical,
                Location = scriptFile,
                FileName = scriptFileName,
                Reason = $"Die Datei '{scriptFileName}' im GTA V scripts-Verzeichnis entspricht " +
                         "einem bekannten Cheat-Plugin oder Mod-Menu-Skript. " +
                         "Script-Hook-Skripte in diesem Verzeichnis werden beim Spielstart " +
                         "automatisch geladen.",
                Detail = matchedKeyword != null
                    ? $"Schluesselbegriff: '{matchedKeyword}'"
                    : "Bekannte Mod-Menu-DLL"
            });
        }

        await Task.CompletedTask;
    }

    private async Task ScanKiddionArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var kiddionDirs = new[]
        {
            Path.Combine(roamingAppData, "Kiddion's Modest Menu"),
            Path.Combine(localAppData, "Kiddion")
        };

        foreach (var kiddionDir in kiddionDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(kiddionDir)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Kiddion's Modest Menu Konfigurationsverzeichnis gefunden",
                Risk = RiskLevel.High,
                Location = kiddionDir,
                Reason = "Das AppData-Verzeichnis von Kiddion's Modest Menu wurde gefunden. " +
                         "Kiddion's Modest Menu ist das beliebteste GTA Online Cheat-Tool " +
                         "mit Godmode, Money-Drop und weiteren Funktionen.",
                Detail = $"Verzeichnis: {kiddionDir}"
            });

            var configPath = Path.Combine(kiddionDir, "config.json");
            if (File.Exists(configPath))
            {
                ctx.IncrementFiles();
                try
                {
                    string content;
                    using var sr = new StreamReader(configPath);
                    content = await sr.ReadToEndAsync();

                    var matchedKeywords = KiddionConfigKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchedKeywords.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "Kiddion Cheat-Konfiguration mit aktiven Cheat-Optionen",
                            Risk = RiskLevel.Critical,
                            Location = configPath,
                            FileName = "config.json",
                            Reason = "Die Kiddion-Konfigurationsdatei enthaelt aktivierte Cheat-Optionen: " +
                                     string.Join(", ", matchedKeywords) + ". " +
                                     "Diese Konfiguration belegt den aktiven Einsatz von Cheat-Funktionen " +
                                     "in GTA Online.",
                            Detail = $"Aktive Cheat-Optionen: {string.Join(", ", matchedKeywords)}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }

        ScanPrefetchForPattern(ctx, "KIDDION", "Kiddion's Modest Menu");
        ScanPrefetchForPattern(ctx, "KIDDIONSMB", "Kiddion's Modest Menu (kiddionsmb)");
    }

    private async Task Scan2Take1ArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var twoTake1Dir = Path.Combine(roamingAppData, "2Take1");

        if (Directory.Exists(twoTake1Dir))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "2Take1 Menu Konfigurationsverzeichnis gefunden",
                Risk = RiskLevel.High,
                Location = twoTake1Dir,
                Reason = "Das AppData-Verzeichnis von 2Take1 Menu wurde gefunden. " +
                         "2Take1 ist ein Abo-basiertes Premium-Cheat-Menu fuer GTA Online " +
                         "mit erweiterten Funktionen wie Aimbot, Godmode und Money-Loop.",
                Detail = $"Verzeichnis: {twoTake1Dir}"
            });

            var configFiles = new[] { "config.json", "settings.json" };
            foreach (var configFileName in configFiles)
            {
                if (ct.IsCancellationRequested) break;
                var configPath = Path.Combine(twoTake1Dir, configFileName);
                if (!File.Exists(configPath)) continue;

                ctx.IncrementFiles();
                try
                {
                    string content;
                    using var sr = new StreamReader(configPath);
                    content = await sr.ReadToEndAsync();

                    var matchedKeywords = GtaoCheatConfigKeywords
                        .Where(k => content.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchedKeywords.Count > 0)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = "2Take1 Konfiguration mit aktiven Cheat-Optionen",
                            Risk = RiskLevel.Critical,
                            Location = configPath,
                            FileName = configFileName,
                            Reason = "Die 2Take1-Konfigurationsdatei enthaelt aktive Cheat-Optionen: " +
                                     string.Join(", ", matchedKeywords) + ".",
                            Detail = $"Aktive Optionen: {string.Join(", ", matchedKeywords)}"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }

        try
        {
            using var twoTake1Key = Registry.CurrentUser.OpenSubKey(@"Software\2Take1");
            if (twoTake1Key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "2Take1 Menu in der Registry registriert",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\2Take1",
                    Reason = "2Take1 Menu hat Registry-Eintraege hinterlassen, die auf eine " +
                             "fruehre oder aktuelle Installation hinweisen.",
                    Detail = $"Schluessel: HKCU\\Software\\2Take1"
                });
            }
        }
        catch { }

        ScanPrefetchForPattern(ctx, "2TAKE1", "2Take1 Menu");
    }

    private async Task ScanStandMenuArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var standDir = Path.Combine(roamingAppData, "Stand");

        if (Directory.Exists(standDir))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Stand Menu Konfigurationsverzeichnis gefunden",
                Risk = RiskLevel.High,
                Location = standDir,
                Reason = "Das AppData-Verzeichnis von Stand Menu wurde gefunden. " +
                         "Stand ist ein Premium-Cheat-Menu fuer GTA Online mit umfangreichen " +
                         "Godmode-, ESP- und Modding-Funktionen.",
                Detail = $"Verzeichnis: {standDir}"
            });

            string[] standFiles = Array.Empty<string>();
            try { standFiles = Directory.GetFiles(standDir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { }
            catch { }

            foreach (var standFile in standFiles)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();
            }
        }

        foreach (var gtaDir in GtaVInstallPaths)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(gtaDir)) continue;

            var standDll = Path.Combine(gtaDir, "Stand.dll");
            if (!File.Exists(standDll)) continue;

            ctx.IncrementFiles();
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Stand.dll im GTA V Verzeichnis",
                Risk = RiskLevel.Critical,
                Location = standDll,
                FileName = "Stand.dll",
                Reason = "Stand.dll im GTA V Installationsverzeichnis beweist, dass Stand Menu " +
                         "aktiv in GTA V installiert ist und beim Spielstart geladen wird.",
                Detail = $"GTA V Verzeichnis: {gtaDir}"
            });
        }

        try
        {
            using var standKey = Registry.CurrentUser.OpenSubKey(@"Software\Stand");
            if (standKey != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "Stand Menu in der Registry registriert",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\Stand",
                    Reason = "Stand Menu hat Registry-Eintraege hinterlassen.",
                    Detail = "Schluessel: HKCU\\Software\\Stand"
                });
            }
        }
        catch { }

        ScanPrefetchForPattern(ctx, "STAND", "Stand Menu");

        await Task.CompletedTask;
    }

    private async Task ScanOtherMenuArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var menuAppDataDirs = new[]
        {
            ("Orbital", "Orbital Menu"),
            ("Cherax", "Cherax Menu"),
            ("Midnight", "Midnight Menu"),
            ("Brute", "Brute Menu"),
            ("Nova", "Nova Menu"),
            ("Phantom", "Phantom GTA")
        };

        foreach (var (dirName, menuName) in menuAppDataDirs)
        {
            if (ct.IsCancellationRequested) break;
            var menuDir = Path.Combine(roamingAppData, dirName);
            if (!Directory.Exists(menuDir)) continue;

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"{menuName} Konfigurationsverzeichnis gefunden",
                Risk = RiskLevel.High,
                Location = menuDir,
                Reason = $"Das AppData-Verzeichnis von '{menuName}' wurde gefunden. " +
                         $"'{menuName}' ist ein GTA Online Cheat-Menu mit Godmode, " +
                         "ESP und weiteren Cheat-Funktionen.",
                Detail = $"Verzeichnis: {menuDir}"
            });

            string[] menuFiles = Array.Empty<string>();
            try { menuFiles = Directory.GetFiles(menuDir, "*", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { }
            catch { }

            foreach (var menuFile in menuFiles)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();
            }
        }

        foreach (var gtaDir in GtaVInstallPaths)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(gtaDir)) continue;

            string[] gtaAsiFiles = Array.Empty<string>();
            try { gtaAsiFiles = Directory.GetFiles(gtaDir, "*.asi"); }
            catch (UnauthorizedAccessException) { continue; }
            catch { continue; }

            foreach (var asiFile in gtaAsiFiles)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                var asiNameLower = Path.GetFileNameWithoutExtension(asiFile).ToLowerInvariant();
                if (menuAppDataDirs.Any(m => asiNameLower.Contains(m.Item1.ToLowerInvariant())))
                {
                    var asiFileName = Path.GetFileName(asiFile);
                    var matchedMenu = menuAppDataDirs
                        .First(m => asiNameLower.Contains(m.Item1.ToLowerInvariant()));
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"{matchedMenu.Item2}-ASI im GTA V Verzeichnis: {asiFileName}",
                        Risk = RiskLevel.Critical,
                        Location = asiFile,
                        FileName = asiFileName,
                        Reason = $"Die ASI-Datei '{asiFileName}' im GTA V Verzeichnis gehört zu " +
                                 $"'{matchedMenu.Item2}' und wird beim Spielstart automatisch geladen.",
                        Detail = $"GTA V Verzeichnis: {gtaDir}"
                    });
                }
            }
        }

        await Task.CompletedTask;
    }

    private async Task ScanGtaoMoneyGlitchScriptsAsync(ScanContext ctx, CancellationToken ct)
    {
        var scriptKeywords = new[]
        {
            "MoneyDrop", "CasinoHack", "MoneyGlitch", "RP_Boost", "casino_cheat",
            "money_drop", "rp_boost", "gtaonline", "moneydrop"
        };

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var searchDirs = new[]
        {
            Path.Combine(userProfile, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
        };

        var scriptExtensions = new[] { "*.bat", "*.cmd", "*.ahk", "*.py", "*.ps1" };

        foreach (var dir in searchDirs)
        {
            if (ct.IsCancellationRequested) break;
            if (!Directory.Exists(dir)) continue;

            foreach (var ext in scriptExtensions)
            {
                string[] scriptFiles = Array.Empty<string>();
                try { scriptFiles = Directory.GetFiles(dir, ext, SearchOption.AllDirectories); }
                catch (UnauthorizedAccessException) { continue; }
                catch { continue; }

                foreach (var scriptFile in scriptFiles)
                {
                    if (ct.IsCancellationRequested) break;
                    ctx.IncrementFiles();

                    var scriptNameLower = Path.GetFileNameWithoutExtension(scriptFile).ToLowerInvariant();
                    var nameMatch = scriptKeywords
                        .FirstOrDefault(k => scriptNameLower.Contains(k.ToLowerInvariant()));

                    if (nameMatch != null)
                    {
                        var scriptFileName = Path.GetFileName(scriptFile);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"GTAO Money/Casino-Cheat-Skript: {scriptFileName}",
                            Risk = RiskLevel.High,
                            Location = scriptFile,
                            FileName = scriptFileName,
                            Reason = $"Das Skript '{scriptFileName}' hat einen Namen, der auf " +
                                     $"einen GTA Online Money-Glitch oder Casino-Hack hinweist " +
                                     $"(Schluesselbegriff: '{nameMatch}').",
                            Detail = $"Skript-Typ: {ext}, Schluesselbegriff: '{nameMatch}'"
                        });
                        continue;
                    }

                    try
                    {
                        string content;
                        using var sr = new StreamReader(scriptFile);
                        content = await sr.ReadToEndAsync();

                        var contentMatch = scriptKeywords
                            .FirstOrDefault(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));

                        if (contentMatch != null)
                        {
                            var scriptFileName = Path.GetFileName(scriptFile);
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Skript mit GTAO Cheat-Inhalt: {scriptFileName}",
                                Risk = RiskLevel.High,
                                Location = scriptFile,
                                FileName = scriptFileName,
                                Reason = $"Das Skript '{scriptFileName}' enthaelt GTA Online Cheat-Inhalt " +
                                         $"(Schluesselbegriff: '{contentMatch}'). " +
                                         "Solche Skripte werden fuer Money-Drops, Casino-Hacks " +
                                         "oder RP-Boosts in GTA Online eingesetzt.",
                                Detail = $"Inhaltlicher Schluesselbegriff: '{contentMatch}'"
                            });
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                    catch { }
                }
            }
        }
    }

    private void ScanPrefetchArtifacts(ScanContext ctx, CancellationToken ct)
    {
        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir)) return;

        string[] pfFiles = Array.Empty<string>();
        try { pfFiles = Directory.GetFiles(prefetchDir, "*.pf"); }
        catch { return; }

        foreach (var pfFile in pfFiles)
        {
            if (ct.IsCancellationRequested) break;

            var pfName = Path.GetFileNameWithoutExtension(pfFile).ToUpperInvariant();
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9 ? pfName[..dashIdx] : pfName;

            var matchedPattern = PrefetchModMenuPatterns
                .FirstOrDefault(p => exeName.StartsWith(p, StringComparison.OrdinalIgnoreCase) ||
                                     exeName.Contains(p, StringComparison.OrdinalIgnoreCase));

            if (matchedPattern == null) continue;

            var lastRun = DateTime.MinValue;
            try { lastRun = File.GetLastWriteTime(pfFile); } catch { }

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Prefetch: GTA V Mod-Menu ausgefuehrt ({exeName.ToLowerInvariant()}.exe)",
                Risk = RiskLevel.Medium,
                Location = pfFile,
                FileName = exeName.ToLowerInvariant() + ".exe",
                Reason = $"Die Prefetch-Datei '{pfName}' beweist, dass ein GTA V Mod-Menu oder " +
                         "Cheat-Tool ausgefuehrt wurde. Prefetch-Dateien bleiben als forensischer " +
                         "Beweis erhalten, auch wenn das Tool geloescht wurde.",
                Detail = lastRun != DateTime.MinValue
                    ? $"Zuletzt ausgefuehrt: {lastRun:yyyy-MM-dd HH:mm:ss}"
                    : null
            });
        }
    }

    private void ScanPrefetchForPattern(ScanContext ctx, string pattern, string menuName)
    {
        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir)) return;

        string[] pfFiles = Array.Empty<string>();
        try { pfFiles = Directory.GetFiles(prefetchDir, pattern + "*.pf"); }
        catch { return; }

        foreach (var pfFile in pfFiles)
        {
            var pfName = Path.GetFileNameWithoutExtension(pfFile);
            var lastRun = DateTime.MinValue;
            try { lastRun = File.GetLastWriteTime(pfFile); } catch { }

            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = $"Prefetch: {menuName} ausgefuehrt",
                Risk = RiskLevel.Medium,
                Location = pfFile,
                FileName = pfName.ToLowerInvariant() + ".exe",
                Reason = $"Die Prefetch-Datei bestätigt, dass '{menuName}' ausgefuehrt wurde.",
                Detail = lastRun != DateTime.MinValue
                    ? $"Zuletzt ausgefuehrt: {lastRun:yyyy-MM-dd HH:mm:ss}"
                    : null
            });
        }
    }

    private async Task ScanGtaVModAccountArtifactsAsync(ScanContext ctx, CancellationToken ct)
    {
        var roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var gtaVConfigDir = Path.Combine(roamingAppData, "Rockstar Games", "GTA V", "cfg");
        var gtaVAppDataDir = Path.Combine(roamingAppData, "Rockstar Games", "GTA V");

        var commandLinePath = Path.Combine(gtaVConfigDir, "commandline.txt");
        if (File.Exists(commandLinePath))
        {
            ctx.IncrementFiles();
            try
            {
                string content;
                using var sr = new StreamReader(commandLinePath);
                content = await sr.ReadToEndAsync();

                var matchedFlags = GtaVCommandlineAntiDetectFlags
                    .Where(f => content.Contains(f, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matchedFlags.Count >= 2)
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "GTA V commandline.txt mit Anti-Detection-Flags",
                        Risk = RiskLevel.Medium,
                        Location = commandLinePath,
                        FileName = "commandline.txt",
                        Reason = "Die GTA V commandline.txt enthaelt mehrere Flags, die von Cheat-Benutzern " +
                                 "eingesetzt werden, um die Anti-Cheat-Erkennung zu erschweren: " +
                                 string.Join(", ", matchedFlags),
                        Detail = $"Flags: {string.Join(", ", matchedFlags)}"
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch { }
        }

        if (Directory.Exists(gtaVAppDataDir))
        {
            string[] logFiles = Array.Empty<string>();
            try { logFiles = Directory.GetFiles(gtaVAppDataDir, "*.log", SearchOption.AllDirectories); }
            catch (UnauthorizedAccessException) { }
            catch { }

            foreach (var logFile in logFiles)
            {
                if (ct.IsCancellationRequested) break;
                ctx.IncrementFiles();

                try
                {
                    string content;
                    using var sr = new StreamReader(logFile);
                    content = await sr.ReadToEndAsync();

                    var matchedKeyword = GtaVLogCheatKeywords
                        .FirstOrDefault(k => content.Contains(k, StringComparison.OrdinalIgnoreCase));

                    if (matchedKeyword != null)
                    {
                        var logFileName = Path.GetFileName(logFile);
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"GTA V Log-Datei mit Mod-Menu-Bezug: {logFileName}",
                            Risk = RiskLevel.Medium,
                            Location = logFile,
                            FileName = logFileName,
                            Reason = $"Die GTA V Log-Datei '{logFileName}' enthaelt Hinweise auf " +
                                     $"ein Mod-Menu oder Cheat-Tool: '{matchedKeyword}'. " +
                                     "Mod-Menus hinterlassen haeufig Spuren in GTA V Log-Dateien.",
                            Detail = $"Schluesselbegriff: '{matchedKeyword}'"
                        });
                    }
                }
                catch (UnauthorizedAccessException) { }
                catch { }
            }
        }
    }

    private void ScanRegistryArtifacts(ScanContext ctx, CancellationToken ct)
    {
        try
        {
            using var socialClubKey = Registry.CurrentUser.OpenSubKey(
                @"Software\Rockstar Games\Social Club\Settings");
            if (socialClubKey != null)
            {
                ctx.IncrementRegistryKeys();
                var overlayValue = socialClubKey.GetValue("EnableInGameOverlay")?.ToString();
                if (overlayValue != null && (overlayValue == "0" ||
                    overlayValue.Equals("false", StringComparison.OrdinalIgnoreCase)))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = "Rockstar Social Club In-Game-Overlay deaktiviert",
                        Risk = RiskLevel.Medium,
                        Location = @"HKCU\Software\Rockstar Games\Social Club\Settings",
                        Reason = "Das Rockstar Social Club In-Game-Overlay ist deaktiviert. " +
                                 "Cheater deaktivieren das Overlay haeufig, um Konflikte mit " +
                                 "ihren Mod-Menus zu vermeiden oder um die Anti-Cheat-Erkennung " +
                                 "durch den Social Club zu erschweren.",
                        Detail = $"EnableInGameOverlay: {overlayValue}"
                    });
                }
            }
        }
        catch { }

        if (ct.IsCancellationRequested) return;

        try
        {
            using var scriptHookKey = Registry.CurrentUser.OpenSubKey(
                @"Software\ScriptHookV");
            if (scriptHookKey != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = "ScriptHookV Registry-Eintraege gefunden",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\ScriptHookV",
                    Reason = "ScriptHookV ist in der Registry registriert. ScriptHookV ist eine " +
                             "Voraussetzung fuer das Laden von Mod-Menus in GTA V. " +
                             "Legitime GTA V Nutzung erfordert kein ScriptHookV.",
                    Detail = "Schluessel: HKCU\\Software\\ScriptHookV"
                });
            }
        }
        catch { }
    }

    private void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        var processes = ctx.GetProcessSnapshot();

        foreach (var proc in processes)
        {
            if (ct.IsCancellationRequested) break;
            ctx.IncrementProcesses();

            try
            {
                var procExeName = proc.ProcessName + ".exe";
                if (!KnownModMenuExeNames.Contains(procExeName)) continue;

                var procPath = string.Empty;
                try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"GTA V Mod-Menu laeuft aktiv: {procExeName}",
                    Risk = RiskLevel.Critical,
                    Location = procPath.Length > 0 ? procPath : $"PID {proc.Id}",
                    FileName = procExeName,
                    Reason = $"Das GTA V Mod-Menu '{procExeName}' (PID {proc.Id}) ist aktuell aktiv. " +
                             "Ein laufendes Mod-Menu ist ein eindeutiges Zeichen fuer eine aktive " +
                             "Cheat-Sitzung in GTA V oder GTA Online.",
                    Detail = $"PID: {proc.Id}, Pfad: {(procPath.Length > 0 ? procPath : "unbekannt")}"
                });
            }
            catch { }
        }
    }

    private static IEnumerable<string> GetUserSearchDirectories()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var appDataRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var appDataLocal = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        var dirs = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(userProfile, "Downloads"),
            Path.GetTempPath(),
            appDataRoaming,
            appDataLocal,
            documents
        };

        foreach (var gtaDir in GtaVInstallPaths)
        {
            dirs.Add(gtaDir);
        }

        return dirs;
    }
}
