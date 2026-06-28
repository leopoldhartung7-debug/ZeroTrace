using System.IO;
using System.Text;
using Microsoft.Win32;
using ZeroTrace.Core.Models;
using ZeroTrace.Core.Engine;

namespace ZeroTrace.Core.Modules;

public sealed class CheatTrainerKeygenScanModule : IScanModule
{
    public string Name => "Cheat-Trainer-Keygen";
    public double Weight => 0.5;
    public int ParallelGroup => 4;

    private static readonly string[] WellKnownTrainerExeNames =
    {
        "gta5_trainer.exe", "rust_trainer.exe", "csgo_trainer.exe", "cs2_trainer.exe",
        "fortnite_trainer.exe", "warzone_trainer.exe", "apex_trainer.exe", "fivem_trainer.exe",
    };

    private static readonly string[] KeygenCrackExeNames =
    {
        "keygen.exe", "crack.exe", "activator.exe", "serial.exe",
        "offline_patch.exe", "lan_crack.exe", "bypass_drm.exe",
    };

    private static readonly string[] KeygenCrackTextFiles =
    {
        "serial.txt", "key.txt", "activation.txt", "crack.txt", "nfo.txt", "README.nfo",
    };

    private static readonly string[] NfoSceneKeywords =
    {
        "release", "team", "scene", "crack", "keygen", "serial", "protection: unprotected",
    };

    private static readonly string[] TrainerConfigFiles =
    {
        "trainer_config.json", "trainer_settings.ini", "hotkeys.ini",
    };

    private static readonly string[] TrainerConfigKeywords =
    {
        "health", "ammo", "money", "god_mode", "no_clip", "speed", "unlimited",
        "godmode", "noclip", "infinite", "invincible",
    };

    private static readonly string[] TrainerLogFiles =
    {
        "trainer.log", "trainer_log.txt",
    };

    private static readonly string[] WareziSitePatterns =
    {
        "skidrow.com", "fitgirl-repacks.site", "steamunlocked.net", "ocean-of-games.com",
        "igg-games.com", "cs.rin.ru", "gamecopyworld.com", "reloaded.club",
        "crackhub.site", "cracked-games.org", "gog-games.com",
    };

    private static readonly string[] WareziReleaseIndicatorExtensions =
    {
        ".skidrow", ".reloaded", ".codex", ".ali213",
    };

    private static readonly string[] MrAntiFunKeywords =
    {
        "mrantifun", "fearlessrevolution", "fearless", "wemod", "fling trainer",
    };

    private static readonly string[] RunningProcessKeywords =
    {
        "wemod", "wemod_helper", "keygen", "crack", "activator",
    };

    private static readonly string[] PrefetchPatterns =
    {
        "WEMOD", "TRAINER", "KEYGEN", "CRACK", "ACTIVATOR", "FLING", "MRANTIFUN",
    };

    private static readonly string[] GameProcessNames =
    {
        "gta5", "gtav", "rustclient", "csgo", "cs2", "fortnite", "warzone",
        "apexlegends", "fivem", "valorant", "overwatch", "destiny2",
        "fortniteclient-win64-shipping", "easyanticheat",
    };

    private static readonly string[] SearchBases = BuildSearchBases();

    private static string[] BuildSearchBases()
    {
        return new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
        };
    }

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        await Task.Run(() =>
        {
            ScanWeModArtifacts(ctx, ct);
            ScanFlingTrainerArtifacts(ctx, ct);
            ScanCheatHappensArtifacts(ctx, ct);
            ScanTrainerConfigFiles(ctx, ct);
            ScanKeygenCrackFiles(ctx, ct);
            ScanNfoWarezFiles(ctx, ct);
            ScanBrowserHistoryForWarezSites(ctx, ct);
            ScanGameActivationBypassArtifacts(ctx, ct);
            ScanRunningProcesses(ctx, ct);
            ScanPrefetchFiles(ctx, ct);
        }, ct);
    }

    private static void ScanWeModArtifacts(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var wemodDirs = new[]
        {
            Path.Combine(localAppData, "WeMod"),
            Path.Combine(appData, "WeMod"),
        };

        bool wemodInstalled = false;
        foreach (var dir in wemodDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;
            wemodInstalled = true;

            ctx.AddFinding(new Finding
            {
                Module = "Cheat-Trainer-Keygen",
                Title = $"WeMod Trainer-Platform installiert: {dir}",
                Risk = RiskLevel.Low,
                Location = dir,
                Reason = "WeMod ist eine Trainer-Platform. Legitime Verwendung moeglich, wird aber " +
                         "haeufig zum Cheaten in Multiplayer-Spielen genutzt. Bestaetigt durch AppData-Verzeichnis.",
                Detail = $"Dir={dir}",
            });

            try
            {
                foreach (var appVersionDir in Directory.GetDirectories(dir, "app-*"))
                {
                    ct.ThrowIfCancellationRequested();
                    var wemodExe = Path.Combine(appVersionDir, "WeMod.exe");
                    if (!File.Exists(wemodExe)) continue;
                    ctx.IncrementFiles();

                    try
                    {
                        var info = new FileInfo(wemodExe);
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Trainer-Keygen",
                            Title = $"WeMod.exe in App-Verzeichnis: {Path.GetFileName(appVersionDir)}",
                            Risk = RiskLevel.Medium,
                            Location = wemodExe,
                            FileName = "WeMod.exe",
                            Reason = $"WeMod Trainer-Executable in '{appVersionDir}' gefunden ({info.Length / 1024} KB). " +
                                     "WeMod injiziert Trainer-Code in Spielprozesse.",
                            Detail = $"Path={wemodExe} Size={info.Length}",
                        });
                    }
                    catch (IOException) { }

                    try
                    {
                        foreach (var jsonFile in Directory.GetFiles(appVersionDir, "*.json", SearchOption.TopDirectoryOnly))
                        {
                            ct.ThrowIfCancellationRequested();
                            ctx.IncrementFiles();

                            try
                            {
                                using var fs = new FileStream(jsonFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                string content = sr.ReadToEnd();
                                var lower = content.ToLowerInvariant();

                                if (lower.Contains("gameid") || lower.Contains("trainers") || lower.Contains("cheats"))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = "Cheat-Trainer-Keygen",
                                        Title = $"WeMod Spiel-Konfiguration: {Path.GetFileName(jsonFile)}",
                                        Risk = RiskLevel.Medium,
                                        Location = jsonFile,
                                        FileName = Path.GetFileName(jsonFile),
                                        Reason = $"WeMod-Konfigurationsdatei '{Path.GetFileName(jsonFile)}' enthaelt Spiel-/Trainer-Eintraege.",
                                        Detail = $"Path={jsonFile}",
                                    });
                                    break;
                                }
                            }
                            catch (IOException) { }
                        }
                    }
                    catch (UnauthorizedAccessException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }

        if (wemodInstalled)
        {
            try
            {
                using var wemodKey = Registry.CurrentUser.OpenSubKey(@"Software\WeMod");
                if (wemodKey != null)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = "Cheat-Trainer-Keygen",
                        Title = "WeMod Registry-Eintrag vorhanden",
                        Risk = RiskLevel.Low,
                        Location = @"HKCU\Software\WeMod",
                        Reason = "WeMod Registry-Schluessel bestaetigt Installation der Trainer-Platform.",
                        Detail = "RegKey=HKCU\\Software\\WeMod",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void ScanFlingTrainerArtifacts(ScanContext ctx, CancellationToken ct)
    {
        var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        foreach (var baseDir in new[] { desktopDir, downloadsDir })
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    var fnameLower = fname.ToLowerInvariant();

                    foreach (var knownTrainer in WellKnownTrainerExeNames)
                    {
                        if (!fnameLower.Equals(knownTrainer, StringComparison.OrdinalIgnoreCase)) continue;
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Trainer-Keygen",
                            Title = $"Bekannte Trainer-EXE: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"Bekannte Spiel-Trainer-EXE '{fname}' gefunden. Trainer modifizieren den Spielspeicher " +
                                     "direkt um God Mode, unendlich Munition, Geld etc. zu aktivieren.",
                            Detail = $"Path={file}",
                        });
                        break;
                    }

                    if (fnameLower.Contains("trainer", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Trainer-Keygen",
                            Title = $"EXE mit 'Trainer' im Dateinamen: {fname}",
                            Risk = RiskLevel.Medium,
                            Location = file,
                            FileName = fname,
                            Reason = $"Datei '{fname}' enthaelt 'Trainer' im Namen — typisches Muster fuer FLiNG/MrAntiFun-Trainer.",
                            Detail = $"Path={file}",
                        });
                    }

                    if (fnameLower.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            const int readBytes = 2048;
                            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                            var buf = new byte[Math.Min(readBytes, (int)fs.Length)];
                            var read = fs.Read(buf, 0, buf.Length);
                            var header = Encoding.ASCII.GetString(buf, 0, read) + Encoding.Unicode.GetString(buf, 0, read);
                            var headerLower = header.ToLowerInvariant();

                            foreach (var kw in MrAntiFunKeywords)
                            {
                                if (!headerLower.Contains(kw, StringComparison.OrdinalIgnoreCase)) continue;
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Cheat-Trainer-Keygen",
                                    Title = $"MrAntiFun/FLiNG/WeMod Trainer-EXE: {fname}",
                                    Risk = RiskLevel.High,
                                    Location = file,
                                    FileName = fname,
                                    Reason = $"Datei '{fname}' enthaelt Trainer-Hersteller-Keyword '{kw}' in den ersten 2KB " +
                                             "(Version/Beschreibung). Bekannte Trainer-Tool-Signatur.",
                                    Detail = $"Path={file} Keyword={kw}",
                                });
                                break;
                            }
                        }
                        catch (IOException) { }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void ScanCheatHappensArtifacts(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        var cheatHappensDirs = new[]
        {
            Path.Combine(programFiles, "Cheat Happens"),
            Path.Combine(programFilesX86, "Cheat Happens"),
            Path.Combine(appData, "Cheat Happens"),
        };

        foreach (var dir in cheatHappensDirs)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(dir)) continue;

            ctx.AddFinding(new Finding
            {
                Module = "Cheat-Trainer-Keygen",
                Title = $"Cheat Happens Trainer-Platform installiert",
                Risk = RiskLevel.High,
                Location = dir,
                Reason = "Cheat Happens ist eine Trainer-Platform die Spielspeicher-Manipulation anbietet. " +
                         "Installations-Verzeichnis gefunden.",
                Detail = $"Dir={dir}",
            });
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Cheat Happens");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = "Cheat-Trainer-Keygen",
                    Title = "Cheat Happens Registry-Eintrag",
                    Risk = RiskLevel.High,
                    Location = @"HKCU\Software\Cheat Happens",
                    Reason = "Cheat Happens Registry-Schluessel bestaetigt Installation.",
                    Detail = "RegKey=HKCU\\Software\\Cheat Happens",
                });
            }
        }
        catch (UnauthorizedAccessException) { }

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Cheat Happens");
            if (key != null)
            {
                ctx.IncrementRegistryKeys();
                ctx.AddFinding(new Finding
                {
                    Module = "Cheat-Trainer-Keygen",
                    Title = "Cheat Happens HKLM Registry-Eintrag",
                    Risk = RiskLevel.High,
                    Location = @"HKLM\SOFTWARE\Cheat Happens",
                    Reason = "Cheat Happens Registry-Schluessel in HKLM bestaetigt systemweite Installation.",
                    Detail = "RegKey=HKLM\\SOFTWARE\\Cheat Happens",
                });
            }
        }
        catch (UnauthorizedAccessException) { }
    }

    private static void ScanTrainerConfigFiles(ScanContext ctx, CancellationToken ct)
    {
        foreach (var baseDir in SearchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            foreach (var configName in TrainerConfigFiles)
            {
                var configPath = Path.Combine(baseDir, configName);
                if (!File.Exists(configPath)) continue;
                ctx.IncrementFiles();

                try
                {
                    using var fs = new FileStream(configPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    string content = sr.ReadToEnd();
                    var lower = content.ToLowerInvariant();

                    var foundKeywords = TrainerConfigKeywords
                        .Where(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (foundKeywords.Count < 1) continue;

                    ctx.AddFinding(new Finding
                    {
                        Module = "Cheat-Trainer-Keygen",
                        Title = $"Trainer-Konfigurationsdatei: {configName}",
                        Risk = RiskLevel.Medium,
                        Location = configPath,
                        FileName = configName,
                        Reason = $"Trainer-Konfigurationsdatei '{configName}' enthaelt Cheat-Feature-Schluessel: " +
                                 string.Join(", ", foundKeywords.Take(5)),
                        Detail = $"Path={configPath} Keywords={string.Join("|", foundKeywords.Take(8))}",
                    });
                }
                catch (IOException) { }
            }

            foreach (var logName in TrainerLogFiles)
            {
                var logPath = Path.Combine(baseDir, logName);
                if (!File.Exists(logPath)) continue;
                ctx.IncrementFiles();

                try
                {
                    const int maxBytes = 64 * 1024;
                    using var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var readStart = Math.Max(0, fs.Length - maxBytes);
                    fs.Seek(readStart, SeekOrigin.Begin);
                    var buf = new byte[Math.Min(maxBytes, fs.Length - readStart)];
                    var read = fs.Read(buf, 0, buf.Length);
                    var content = Encoding.UTF8.GetString(buf, 0, read).ToLowerInvariant();

                    if (content.Contains("activated", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("trainer", StringComparison.OrdinalIgnoreCase) ||
                        content.Contains("cheat", StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Trainer-Keygen",
                            Title = $"Trainer-Log-Datei gefunden: {logName}",
                            Risk = RiskLevel.Medium,
                            Location = logPath,
                            FileName = logName,
                            Reason = $"Trainer-Logdatei '{logName}' gefunden — beweist frueheren Trainer-Einsatz.",
                            Detail = $"Path={logPath}",
                        });
                    }
                }
                catch (IOException) { }
            }
        }
    }

    private static void ScanKeygenCrackFiles(ScanContext ctx, CancellationToken ct)
    {
        var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        foreach (var baseDir in new[] { desktopDir, downloadsDir })
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var file in Directory.GetFiles(baseDir, "*.exe", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();
                    var fname = Path.GetFileName(file);
                    var fnameLower = fname.ToLowerInvariant();

                    foreach (var knownName in KeygenCrackExeNames)
                    {
                        if (fnameLower.Equals(knownName, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Cheat-Trainer-Keygen",
                                Title = $"Keygen/Crack-EXE: {fname}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fname,
                                Reason = $"Bekannte Keygen/Crack-EXE '{fname}' auf Desktop/Downloads gefunden. " +
                                         "Solche Tools werden im Cheat-Oekosystem eingesetzt und umgehen Software-Schutz.",
                                Detail = $"Path={file}",
                            });
                            break;
                        }
                    }

                    bool isKeygenPattern = fnameLower.StartsWith("keygen_") ||
                                          fnameLower.EndsWith("_keygen.exe") ||
                                          fnameLower.EndsWith("_crack.exe") ||
                                          fnameLower.StartsWith("crack_") ||
                                          fnameLower.StartsWith("patch_") ||
                                          fnameLower.EndsWith("_activator.exe") ||
                                          fnameLower.StartsWith("activator_") ||
                                          fnameLower.EndsWith("_serial_generator.exe");

                    if (isKeygenPattern)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Trainer-Keygen",
                            Title = $"Keygen/Crack-Muster im Dateinamen: {fname}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fname,
                            Reason = $"Datei '{fname}' entspricht typischen Keygen/Crack/Aktivator-Namensmustern auf Desktop/Downloads.",
                            Detail = $"Path={file}",
                        });
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            try
            {
                foreach (var textFileName in KeygenCrackTextFiles)
                {
                    var textPath = Path.Combine(baseDir, textFileName);
                    if (!File.Exists(textPath)) continue;
                    ctx.IncrementFiles();

                    ctx.AddFinding(new Finding
                    {
                        Module = "Cheat-Trainer-Keygen",
                        Title = $"Crack/Keygen Text-Datei: {textFileName}",
                        Risk = RiskLevel.High,
                        Location = textPath,
                        FileName = textFileName,
                        Reason = $"Datei '{textFileName}' auf Desktop/Downloads gefunden. " +
                                 "Typisches Crack/Keygen/Warez-Artefakt.",
                        Detail = $"Path={textPath}",
                    });
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }

            try
            {
                foreach (var regFile in Directory.GetFiles(baseDir, "*.reg", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        using var fs = new FileStream(regFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = sr.ReadToEnd();
                        var lower = content.ToLowerInvariant();

                        bool hasSteamCrack = lower.Contains("steam") && lower.Contains("crack");
                        bool hasActivationBypass = lower.Contains("activation") && lower.Contains("bypass");
                        bool hasDrmDisable = lower.Contains("drm") && lower.Contains("disable");

                        if (hasSteamCrack || hasActivationBypass || hasDrmDisable)
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = "Cheat-Trainer-Keygen",
                                Title = $"REG-Datei mit DRM-Bypass-Inhalt: {Path.GetFileName(regFile)}",
                                Risk = RiskLevel.High,
                                Location = regFile,
                                FileName = Path.GetFileName(regFile),
                                Reason = $"REG-Datei '{Path.GetFileName(regFile)}' enthaelt DRM/Activation-Bypass-Eintraege. " +
                                         "Deutet auf Software-Piraterie-Aktivitaet hin.",
                                Detail = $"Path={regFile} SteamCrack={hasSteamCrack} ActBypass={hasActivationBypass} DrmDisable={hasDrmDisable}",
                            });
                        }
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void ScanNfoWarezFiles(ScanContext ctx, CancellationToken ct)
    {
        var desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var downloadsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");

        foreach (var baseDir in new[] { desktopDir, downloadsDir })
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            try
            {
                foreach (var nfoFile in Directory.GetFiles(baseDir, "*.nfo", SearchOption.TopDirectoryOnly))
                {
                    ct.ThrowIfCancellationRequested();
                    ctx.IncrementFiles();

                    try
                    {
                        using var fs = new FileStream(nfoFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = sr.ReadToEnd();
                        var lower = content.ToLowerInvariant();

                        var matchedKeywords = NfoSceneKeywords
                            .Where(k => lower.Contains(k, StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        if (matchedKeywords.Count < 2) continue;

                        ctx.AddFinding(new Finding
                        {
                            Module = "Cheat-Trainer-Keygen",
                            Title = $"Warez-Scene NFO-Datei: {Path.GetFileName(nfoFile)}",
                            Risk = RiskLevel.High,
                            Location = nfoFile,
                            FileName = Path.GetFileName(nfoFile),
                            Reason = $"NFO-Datei '{Path.GetFileName(nfoFile)}' enthaelt Warez-Scene-Schluessel: " +
                                     string.Join(", ", matchedKeywords) + ". " +
                                     "NFO-Dateien sind Begleitdateien von gecrakten/gepiraten Software-Releases.",
                            Detail = $"Path={nfoFile} Keywords={string.Join("|", matchedKeywords)}",
                        });
                    }
                    catch (IOException) { }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void ScanBrowserHistoryForWarezSites(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var browserHistoryFiles = new List<string>();

        var chromePaths = new[]
        {
            Path.Combine(localAppData, "Google", "Chrome", "User Data", "Default", "History"),
            Path.Combine(localAppData, "Google", "Chrome", "User Data", "Profile 1", "History"),
        };
        var edgePaths = new[]
        {
            Path.Combine(localAppData, "Microsoft", "Edge", "User Data", "Default", "History"),
        };
        var firefoxProfilesBase = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");
        var bravePaths = new[]
        {
            Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History"),
        };

        browserHistoryFiles.AddRange(chromePaths);
        browserHistoryFiles.AddRange(edgePaths);
        browserHistoryFiles.AddRange(bravePaths);

        if (Directory.Exists(firefoxProfilesBase))
        {
            try
            {
                foreach (var profileDir in Directory.GetDirectories(firefoxProfilesBase))
                {
                    var placesDb = Path.Combine(profileDir, "places.sqlite");
                    if (File.Exists(placesDb))
                        browserHistoryFiles.Add(placesDb);
                }
            }
            catch (UnauthorizedAccessException) { }
        }

        var foundWarezDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var historyFile in browserHistoryFiles)
        {
            ct.ThrowIfCancellationRequested();
            if (!File.Exists(historyFile)) continue;
            ctx.IncrementFiles();

            try
            {
                using var fs = new FileStream(historyFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                string content = sr.ReadToEnd();
                var lower = content.ToLowerInvariant();

                foreach (var domain in WareziSitePatterns)
                {
                    if (lower.Contains(domain, StringComparison.OrdinalIgnoreCase))
                        foundWarezDomains.Add(domain);
                }
            }
            catch (IOException) { }
        }

        foreach (var domain in foundWarezDomains)
        {
            ctx.AddFinding(new Finding
            {
                Module = "Cheat-Trainer-Keygen",
                Title = $"Browsing-History: Warez/Piracy-Seite besucht: {domain}",
                Risk = RiskLevel.Medium,
                Location = "Browser-History",
                Reason = $"Browser-History enthaelt Besuch auf bekannter Warez/Piracy-Seite '{domain}'. " +
                         "Diese Seiten verteilen gecrackte Spiele, Trainer und Cheat-Tools.",
                Detail = $"Domain={domain}",
            });
        }
    }

    private static void ScanGameActivationBypassArtifacts(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var steamEmuIndicators = new[]
        {
            "steam_emu.ini", "cream_api.ini", "goldberg_steam_emu.ini", "CreamAPI.ini",
            "SmokeAPI.ini", "Koaloader.ini",
        };

        foreach (var baseDir in SearchBases)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(baseDir)) continue;

            foreach (var iniName in steamEmuIndicators)
            {
                var iniPath = Path.Combine(baseDir, iniName);
                if (!File.Exists(iniPath)) continue;
                ctx.IncrementFiles();

                ctx.AddFinding(new Finding
                {
                    Module = "Cheat-Trainer-Keygen",
                    Title = $"Steam-Emulator-Konfiguration: {iniName}",
                    Risk = RiskLevel.Low,
                    Location = iniPath,
                    FileName = iniName,
                    Reason = $"Steam-Emulator-Konfigurationsdatei '{iniName}' in BenutzerVerzeichnis gefunden. " +
                             "Indikator fuer Piraterie/DRM-Bypass-Toolset.",
                    Detail = $"Path={iniPath}",
                });
            }
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var steamLibraries = new[]
        {
            Path.Combine(programFiles, "Steam", "steamapps", "common"),
            Path.Combine(programFilesX86, "Steam", "steamapps", "common"),
        };

        foreach (var libraryDir in steamLibraries)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(libraryDir)) continue;

            try
            {
                foreach (var gameDir in Directory.GetDirectories(libraryDir))
                {
                    ct.ThrowIfCancellationRequested();

                    foreach (var ext in WareziReleaseIndicatorExtensions)
                    {
                        try
                        {
                            var indicatorFiles = Directory.GetFiles(gameDir, "*" + ext, SearchOption.TopDirectoryOnly);
                            foreach (var indFile in indicatorFiles)
                            {
                                ctx.IncrementFiles();
                                ctx.AddFinding(new Finding
                                {
                                    Module = "Cheat-Trainer-Keygen",
                                    Title = $"Warez-Release-Indikator in Spiel-Verzeichnis: {Path.GetFileName(indFile)}",
                                    Risk = RiskLevel.High,
                                    Location = indFile,
                                    FileName = Path.GetFileName(indFile),
                                    Reason = $"Warez-Scene-Release-Indikator '{Path.GetFileName(indFile)}' (Ext: {ext}) " +
                                             $"in Steam-Spielverzeichnis '{Path.GetFileName(gameDir)}' gefunden. " +
                                             "Beweist gecrackte/gepirante Spielinstallation.",
                                    Detail = $"Path={indFile} GameDir={Path.GetFileName(gameDir)}",
                                });
                            }
                        }
                        catch (UnauthorizedAccessException) { }
                        catch (IOException) { }
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static void ScanRunningProcesses(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var procs = ctx.GetProcessSnapshot();

        bool gameRunning = false;
        var activeTrainerProcesses = new List<(string Name, int Id, string Path)>();

        foreach (var proc in procs)
        {
            ct.ThrowIfCancellationRequested();
            ctx.IncrementProcesses();

            var pname = proc.ProcessName;
            var pnameLower = pname.ToLowerInvariant();
            var pnameExe = pnameLower + ".exe";

            foreach (var gameExe in GameProcessNames)
            {
                if (pnameLower.Equals(gameExe, StringComparison.OrdinalIgnoreCase))
                {
                    gameRunning = true;
                    break;
                }
            }

            bool isKnownTrainerProcess = RunningProcessKeywords.Any(kw =>
                pnameLower.Contains(kw, StringComparison.OrdinalIgnoreCase));

            bool isTrainerByName = pnameLower.Contains("trainer", StringComparison.OrdinalIgnoreCase);

            if (isKnownTrainerProcess || isTrainerByName)
            {
                string procPath = string.Empty;
                try { procPath = proc.MainModule?.FileName ?? string.Empty; } catch { }
                activeTrainerProcesses.Add((pname, proc.Id, procPath));
            }
        }

        foreach (var (name, id, path) in activeTrainerProcesses)
        {
            var nameLower = name.ToLowerInvariant();
            bool isWemod = nameLower.Contains("wemod");
            bool isKeygenCrack = nameLower.Contains("keygen") || nameLower.Contains("crack") ||
                                  nameLower.Contains("activator");

            var risk = (isKeygenCrack || gameRunning) ? RiskLevel.High : RiskLevel.Medium;

            var reason = isWemod
                ? $"WeMod Trainer-Platform-Prozess '{name}' aktiv{(gameRunning ? " — Spiel laeuft gleichzeitig" : "")}."
                : isKeygenCrack
                    ? $"Keygen/Crack/Aktivator-Prozess '{name}' aktiv."
                    : $"Trainer-Prozess '{name}' aktiv{(gameRunning ? " — Spiel laeuft gleichzeitig (Trainer-Cheating moeglich)" : "")}.";

            ctx.AddFinding(new Finding
            {
                Module = "Cheat-Trainer-Keygen",
                Title = $"Trainer/Keygen-Prozess aktiv: {name}",
                Risk = risk,
                Location = path,
                FileName = name + ".exe",
                Reason = reason,
                Detail = $"PID={id} Path={path} GameRunning={gameRunning}",
            });
        }
    }

    private static void ScanPrefetchFiles(ScanContext ctx, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var prefetchDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");

        if (!Directory.Exists(prefetchDir)) return;

        try
        {
            foreach (var pf in Directory.GetFiles(prefetchDir, "*.pf", SearchOption.TopDirectoryOnly))
            {
                ct.ThrowIfCancellationRequested();
                ctx.IncrementFiles();
                var pfName = Path.GetFileName(pf).ToUpperInvariant();

                foreach (var pattern in PrefetchPatterns)
                {
                    if (!pfName.StartsWith(pattern, StringComparison.OrdinalIgnoreCase)) continue;

                    bool isWemod = pattern.Equals("WEMOD", StringComparison.OrdinalIgnoreCase);
                    var risk = isWemod ? RiskLevel.Medium : RiskLevel.High;

                    ctx.AddFinding(new Finding
                    {
                        Module = "Cheat-Trainer-Keygen",
                        Title = $"Trainer/Keygen-Prefetch: {Path.GetFileName(pf)}",
                        Risk = risk,
                        Location = pf,
                        FileName = Path.GetFileName(pf),
                        Reason = $"Windows-Prefetch-Datei '{Path.GetFileName(pf)}' beweist frueheres Ausfuehren " +
                                 $"eines Trainer/Keygen/Crack-Tools (Muster: {pattern}).",
                        Detail = $"PrefetchFile={pf} Pattern={pattern}",
                    });
                    break;
                }
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
    }
}
