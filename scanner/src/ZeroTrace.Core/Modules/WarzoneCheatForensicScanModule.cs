using Microsoft.Win32;
using System.Text;
using ZeroTrace.Core.Engine;
using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Modules;

public sealed class WarzoneCheatForensicScanModule : IScanModule
{
    public string Name => "Warzone-Cheat-Forensik";
    public double Weight => 1.1;
    public int ParallelGroup => 4;

    private static readonly string[] CheatFilePatterns =
    {
        "warzone_hack", "warzone_cheat", "mw_aimbot", "cod_esp",
        "warzone_esp", "warzone_bypass", "ricochet_bypass", "aimware_warzone",
        "wallhack_wz", "wz_aimbot", "wz_esp", "cod_hack",
        "mw2_cheat", "mwii_cheat",
    };

    private static readonly string[] KernelDriverNames =
    {
        "warzone_driver.sys", "cod_hack.sys", "ricochet_bypass.dll",
        "kernel_bypass_ricochet.sys", "ricochet_hook.dll",
        "mw_driver.sys", "cod_kernel.sys", "wz_bypass.sys",
        "ricochet_spoof.sys", "cod_bypass.sys",
    };

    private static readonly string[] SuspiciousDllNames =
    {
        "ricochet_bypass.dll", "ricochet_hook.dll", "cod_hook.dll",
        "wz_inject.dll", "mw_inject.dll", "cod_spoof.dll",
        "warzone_inject.dll", "wz_bypass.dll", "cod_overlay.dll",
        "mw_overlay.dll", "wz_memory.dll", "cod_memory.dll",
        "ricochet_patch.dll", "aimware_wz.dll", "mw_esp.dll",
    };

    private static readonly string[] LogKeywords =
    {
        "warzone hack", "cod aimbot", "warzone esp", "ricochet bypass",
        "wz wallhack", "mw cheat", "aimbot warzone", "cod hack",
        "wz cheat", "warzone aimbot", "mw2 hack", "mwii hack",
        "cod wallhack", "ricochet bypass", "anti-ricochet",
        "warzone undetected", "cod undetected",
    };

    private static readonly string[] DiscordKeywords =
    {
        "warzone hack", "wz esp", "wz aimbot", "ricochet bypass",
        "cod cheat", "mw2 hack", "warzone cheat", "cod esp",
        "mw aimbot", "wz wallhack", "warzone bypass",
        "ricochet bypass", "cod hack",
    };

    private static readonly string[] KnownCheatToolNames =
    {
        "aimclub", "interium", "phantom overlay", "soft aim warzone",
        "wzsoft", "triggerbot cod", "eac bypass cod", "ricochet bypass",
        "engineowning warzone", "wzhack", "cod soft aim",
        "warzone softaim", "phantom overlay wz", "aimclub wz",
        "interium wz", "wzsoft loader",
    };

    private static readonly string[] RegistryCheatPaths =
    {
        @"Software\WarzoneCheat",
        @"Software\CODHack",
        @"Software\WZHack",
        @"Software\WarzoneAimbot",
        @"Software\CODAimbot",
        @"Software\RicochetBypass",
        @"Software\WZBypass",
        @"Software\CODBypass",
        @"Software\WarzoneESP",
        @"Software\WZESP",
        @"Software\CODESPHack",
        @"Software\AimClub",
        @"Software\Interium",
        @"Software\PhantomOverlay",
        @"Software\WZSoft",
        @"Software\SoftAimWarzone",
    };

    private static readonly string[] RegistryInstallerPaths =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WarzoneCheat",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CODHack",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AimClub",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Interium",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PhantomOverlay",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WZSoft",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RicochetBypass",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WarzoneCheat",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\CODHack",
    };

    private static readonly string[] PrefetchCheatExeNames =
    {
        "warzone_hack", "warzone_cheat", "wz_aimbot", "wz_esp",
        "cod_hack", "mw_aimbot", "cod_esp", "ricochet_bypass",
        "warzone_bypass", "aimware_wz", "aimclub_wz", "interium_wz",
        "phantomoverlay", "wzsoft", "softaim_wz", "triggerbot_cod",
        "mw2_cheat", "mwii_cheat", "warzone_loader", "cod_loader",
    };

    private static readonly string[] UserAssistCheatKeywords =
    {
        "warzone_hack", "warzone_cheat", "wz_aimbot", "wz_esp",
        "cod_hack", "mw_aimbot", "ricochet_bypass", "aimclub",
        "interium", "phantomoverlay", "wzsoft", "softaim_wz",
        "triggerbot_cod", "mw2_cheat", "mwii_cheat", "warzone_loader",
        "warzone_bypass", "cod_bypass", "cod_loader", "wz_bypass",
    };

    private static readonly string[] SuspiciousScriptKeywords =
    {
        "warzone", "call of duty", "ricochet", "cod bypass",
        "modern warfare", "mw2", "mwii", "mw3",
    };

    private static readonly string[] CheatEngineSaveExtensions =
    {
        ".ct", ".cetrainer",
    };

    private static readonly string[] WarzoneProcessDumpKeywords =
    {
        "ModernWarfare", "cod.exe", "warzone", "cod_mp", "mw2",
        "mwii", "mw3", "cod_iw8", "cod_iw9",
    };

    private static readonly string[] CodGameDirNames =
    {
        "Call of Duty",
        "Call of Duty Modern Warfare",
        "Call of Duty Modern Warfare II",
        "Call of Duty Modern Warfare III",
        "Call of Duty Warzone",
    };

    public async Task RunAsync(ScanContext ctx, CancellationToken ct)
    {
        ctx.Report(0.0, Name, "Starte Warzone-Cheat-Forensik-Scan...");

        await Task.WhenAll(
            CheckCheatFilesOnDisk(ctx, ct),
            CheckCodGameDirectories(ctx, ct),
            CheckKernelDriverArtifacts(ctx, ct),
            CheckRegistryArtifacts(ctx, ct),
            CheckPrefetchArtifacts(ctx, ct),
            CheckUserAssistArtifacts(ctx, ct),
            CheckLogFileArtifacts(ctx, ct),
            CheckDiscordArtifacts(ctx, ct),
            CheckSuspiciousScripts(ctx, ct),
            CheckMemoryDumpArtifacts(ctx, ct),
            CheckCheatEngineTables(ctx, ct),
            CheckDriverServiceArtifacts(ctx, ct),
            CheckTempAndDownloadDirs(ctx, ct),
            CheckRecycleBinArtifacts(ctx, ct)
        );

        ctx.Report(1.0, Name, "Warzone-Cheat-Forensik-Scan abgeschlossen");
    }

    private Task CheckCheatFilesOnDisk(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();
        var searchRoots = new List<string>();

        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var temp = Path.GetTempPath();
        var downloads = Path.Combine(userProfile, "Downloads");
        var documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

        searchRoots.Add(desktop);
        searchRoots.Add(downloads);
        searchRoots.Add(documents);
        searchRoots.Add(temp);
        searchRoots.Add(localAppData);
        searchRoots.Add(appData);

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                foreach (var pattern in CheatFilePatterns)
                {
                    if (fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Warzone-Cheat-Datei gefunden: {fileName}",
                            Risk = RiskLevel.High,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Datei '{fileName}' entspricht dem bekannten Warzone-Cheat-Dateinamen-Muster '{pattern}'. " +
                                     "Dies ist ein forensisches Artefakt eines Call of Duty Warzone Cheat-Tools.",
                            Detail = $"Muster: {pattern} | Pfad: {file}"
                        });
                        break;
                    }
                }
            }

            string[] subDirs;
            try
            {
                subDirs = Directory.GetDirectories(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var subDir in subDirs)
            {
                if (ct.IsCancellationRequested) return;
                var dirName = Path.GetFileName(subDir);

                foreach (var tool in KnownCheatToolNames)
                {
                    if (dirName.Contains(tool, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Warzone-Cheat-Verzeichnis: {dirName}",
                            Risk = RiskLevel.High,
                            Location = subDir,
                            FileName = dirName,
                            Reason = $"Verzeichnis '{dirName}' entspricht dem bekannten Warzone-Cheat-Tool '{tool}'. " +
                                     "Cheat-Tools hinterlassen haeufig Verzeichnis-Artefakte auch nach der Deinstallation.",
                            Detail = $"Tool: {tool} | Pfad: {subDir}"
                        });
                        break;
                    }
                }

                string[] subFiles;
                try
                {
                    subFiles = Directory.GetFiles(subDir, "*", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in subFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fileName = Path.GetFileName(file);

                    foreach (var pattern in CheatFilePatterns)
                    {
                        if (fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Warzone-Cheat-Datei in Unterverzeichnis: {fileName}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fileName,
                                Reason = $"Datei '{fileName}' in Unterverzeichnis '{dirName}' entspricht dem Warzone-Cheat-Muster '{pattern}'. " +
                                         "Forensisches Artefakt eines COD Warzone Cheat-Tools.",
                                Detail = $"Muster: {pattern} | Pfad: {file}"
                            });
                            break;
                        }
                    }
                }
            }
        }
    }, ct);

    private Task CheckCodGameDirectories(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var gameDirCandidates = new List<string>();

        foreach (var baseDir in new[] { programFiles, programFilesX86 })
        {
            foreach (var gameName in CodGameDirNames)
            {
                var candidate = Path.Combine(baseDir, gameName);
                if (Directory.Exists(candidate))
                    gameDirCandidates.Add(candidate);

                var activisionCandidate = Path.Combine(baseDir, "Activision", gameName);
                if (Directory.Exists(activisionCandidate))
                    gameDirCandidates.Add(activisionCandidate);

                var battlenetCandidate = Path.Combine(baseDir, "Battle.net", gameName);
                if (Directory.Exists(battlenetCandidate))
                    gameDirCandidates.Add(battlenetCandidate);
            }
        }

        var battlenetAppsDir = Path.Combine(programFiles, "Battle.net");
        if (Directory.Exists(battlenetAppsDir))
            gameDirCandidates.Add(battlenetAppsDir);

        var steamAppsDir = Path.Combine(programFiles, "Steam", "steamapps", "common");
        if (Directory.Exists(steamAppsDir))
        {
            try
            {
                foreach (var dir in Directory.GetDirectories(steamAppsDir))
                {
                    var dName = Path.GetFileName(dir);
                    if (dName.Contains("Call of Duty", StringComparison.OrdinalIgnoreCase) ||
                        dName.Contains("Modern Warfare", StringComparison.OrdinalIgnoreCase) ||
                        dName.Contains("Warzone", StringComparison.OrdinalIgnoreCase))
                    {
                        gameDirCandidates.Add(dir);
                    }
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        foreach (var gameDir in gameDirCandidates)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(gameDir)) continue;

            string[] files;
            try
            {
                files = Directory.GetFiles(gameDir, "*.dll", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var file in files)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fileName = Path.GetFileName(file);

                foreach (var suspDll in SuspiciousDllNames)
                {
                    if (fileName.Equals(suspDll, StringComparison.OrdinalIgnoreCase) ||
                        fileName.Contains(suspDll.Replace(".dll", ""), StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtige DLL im COD-Spielverzeichnis: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Verdaechtige DLL '{fileName}' im Call of Duty Spielverzeichnis gefunden. " +
                                     $"Entspricht bekanntem Warzone-Cheat-DLL-Muster '{suspDll}'. " +
                                     "Cheat-DLLs werden oft direkt in das Spielverzeichnis injiziert.",
                            Detail = $"Spielverzeichnis: {gameDir} | DLL: {fileName}"
                        });
                        break;
                    }
                }

                foreach (var pattern in CheatFilePatterns)
                {
                    if (fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat-Datei im COD-Verzeichnis: {fileName}",
                            Risk = RiskLevel.Critical,
                            Location = file,
                            FileName = fileName,
                            Reason = $"Cheat-Datei '{fileName}' direkt im Call of Duty Spielverzeichnis gefunden. " +
                                     $"Muster '{pattern}' stimmt mit bekannten Warzone-Cheat-Artefakten ueberein.",
                            Detail = $"Spielverzeichnis: {gameDir}"
                        });
                        break;
                    }
                }
            }

            string[] sysFiles;
            try
            {
                sysFiles = Directory.GetFiles(gameDir, "*.sys", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var sysFile in sysFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(sysFile);

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Kernel-Treiber-Datei im COD-Spielverzeichnis: {fn}",
                    Risk = RiskLevel.Critical,
                    Location = sysFile,
                    FileName = fn,
                    Reason = $"Kernel-Treiberdatei (.sys) '{fn}' direkt im Call of Duty Spielverzeichnis gefunden. " +
                             "Legitime Spieldateien verwenden keine Kernel-Treiber im Spielordner. " +
                             "Dies ist ein starkes Indiz fuer einen Kernel-Level-Cheat.",
                    Detail = $"Spielverzeichnis: {gameDir}"
                });
            }

            var logDir = Path.Combine(gameDir, "logs");
            if (Directory.Exists(logDir))
            {
                string[] logFiles;
                try
                {
                    logFiles = Directory.GetFiles(logDir, "*.log", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var logFile in logFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    try
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        string content = await sr.ReadToEndAsync(ct);

                        foreach (var keyword in LogKeywords)
                        {
                            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Cheat-Schluesselbegriff in COD-Spiellog: {keyword}",
                                    Risk = RiskLevel.High,
                                    Location = logFile,
                                    FileName = Path.GetFileName(logFile),
                                    Reason = $"COD-Spiellog-Datei '{Path.GetFileName(logFile)}' enthaelt den Cheat-Schluesselbegriff '{keyword}'. " +
                                             "Dies kann auf einen aktiven oder ehemaligen Warzone-Cheat hinweisen.",
                                    Detail = $"Keyword: {keyword} | Log: {logFile}"
                                });
                                break;
                            }
                        }
                    }
                    catch (IOException) { }
                }
            }
        }
    }, ct);

    private Task CheckKernelDriverArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var driversDir = Path.Combine(system32, "drivers");

        if (Directory.Exists(driversDir))
        {
            string[] driverFiles;
            try
            {
                driverFiles = Directory.GetFiles(driversDir, "*.sys", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException)
            {
                driverFiles = Array.Empty<string>();
            }

            foreach (var driverFile in driverFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();
                var fn = Path.GetFileName(driverFile);

                foreach (var knownDriver in KernelDriverNames)
                {
                    if (fn.Equals(knownDriver, StringComparison.OrdinalIgnoreCase) ||
                        fn.Contains(knownDriver.Replace(".sys", ""), StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Warzone-Cheat-Kernel-Treiber in System32: {fn}",
                            Risk = RiskLevel.Critical,
                            Location = driverFile,
                            FileName = fn,
                            Reason = $"Kernel-Treiber '{fn}' in System32\\drivers entspricht bekanntem COD/Warzone-Cheat-Treiber-Muster '{knownDriver}'. " +
                                     "Kernel-Level-Cheats umgehen Anti-Cheat-Systeme durch direkten Kernel-Zugriff.",
                            Detail = $"Bekannter Treiber: {knownDriver} | Pfad: {driverFile}"
                        });
                        break;
                    }
                }

                foreach (var pattern in CheatFilePatterns)
                {
                    if (fn.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiger Kernel-Treiber (COD-Muster): {fn}",
                            Risk = RiskLevel.Critical,
                            Location = driverFile,
                            FileName = fn,
                            Reason = $"Kernel-Treiber '{fn}' enthaelt Warzone-Cheat-Schluesselbegriff '{pattern}'. " +
                                     "Cheat-Kernel-Treiber koennen Ricochet-Anti-Cheat umgehen.",
                            Detail = $"Muster: {pattern} | Pfad: {driverFile}"
                        });
                        break;
                    }
                }
            }
        }

        var tempDir = Path.GetTempPath();
        string[] tempFiles;
        try
        {
            tempFiles = Directory.GetFiles(tempDir, "*.sys", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException)
        {
            tempFiles = Array.Empty<string>();
        }

        foreach (var tempFile in tempFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fn = Path.GetFileName(tempFile);

            foreach (var knownDriver in KernelDriverNames)
            {
                if (fn.Contains(knownDriver.Replace(".sys", ""), StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Warzone-Cheat-Treiber im Temp-Verzeichnis: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = tempFile,
                        FileName = fn,
                        Reason = $"Kernel-Treiber '{fn}' im temporaeren Verzeichnis entspricht bekanntem COD-Cheat-Treiber '{knownDriver}'. " +
                                 "Cheat-Loader entpacken Treiber oft in Temp-Ordner vor der Installation.",
                        Detail = $"Bekannter Treiber: {knownDriver}"
                    });
                    break;
                }
            }
        }

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services", writable: false);
            if (servicesKey is not null)
            {
                foreach (var svcName in servicesKey.GetSubKeyNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    bool matchesCheat = false;
                    foreach (var driver in KernelDriverNames)
                    {
                        var driverBase = driver.Replace(".sys", "").Replace(".dll", "");
                        if (svcName.Contains(driverBase, StringComparison.OrdinalIgnoreCase))
                        {
                            matchesCheat = true;
                            break;
                        }
                    }

                    if (!matchesCheat)
                    {
                        foreach (var pattern in CheatFilePatterns)
                        {
                            if (svcName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                matchesCheat = true;
                                break;
                            }
                        }
                    }

                    if (!matchesCheat) continue;

                    try
                    {
                        using var svcKey = servicesKey.OpenSubKey(svcName, writable: false);
                        if (svcKey is null) continue;

                        var imagePath = svcKey.GetValue("ImagePath") as string ?? "";
                        var svcType = svcKey.GetValue("Type") as int? ?? 0;

                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Warzone-Cheat-Dienst in Registry: {svcName}",
                            Risk = RiskLevel.Critical,
                            Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                            Reason = $"Windows-Dienst '{svcName}' entspricht einem bekannten COD/Warzone Cheat-Kernel-Treiber. " +
                                     $"Dienst-Typ: {svcType}. Kernel-Treiber-Dienste (Typ 1) koennen Ricochet umgehen.",
                            Detail = $"ImagePath: {imagePath} | Type: {svcType}"
                        });
                    }
                    catch { }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckRegistryArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        foreach (var regPath in RegistryCheatPaths)
        {
            if (ct.IsCancellationRequested) return;

            try
            {
                using var hkcuKey = Registry.CurrentUser.OpenSubKey(regPath, writable: false);
                if (hkcuKey is not null)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Warzone-Cheat-Registry-Schluessel: {Path.GetFileName(regPath)}",
                        Risk = RiskLevel.High,
                        Location = $@"HKCU\{regPath}",
                        Reason = $"Registry-Schluessel 'HKCU\\{regPath}' deutet auf ein installiertes Warzone-Cheat-Tool hin. " +
                                 "Cheat-Tools schreiben Konfigurationsdaten und Lizenzinformationen in die Registry.",
                        Detail = $"Registry-Pfad: HKCU\\{regPath}"
                    });
                }
            }
            catch { }

            try
            {
                using var hklmKey = Registry.LocalMachine.OpenSubKey(regPath, writable: false);
                if (hklmKey is not null)
                {
                    ctx.IncrementRegistryKeys();
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Warzone-Cheat-Registry-Schluessel (HKLM): {Path.GetFileName(regPath)}",
                        Risk = RiskLevel.High,
                        Location = $@"HKLM\{regPath}",
                        Reason = $"Registry-Schluessel 'HKLM\\{regPath}' deutet auf ein systemweit installiertes Warzone-Cheat-Tool hin.",
                        Detail = $"Registry-Pfad: HKLM\\{regPath}"
                    });
                }
            }
            catch { }
        }

        foreach (var installerPath in RegistryInstallerPaths)
        {
            if (ct.IsCancellationRequested) return;

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(installerPath, writable: false);
                if (key is null) continue;

                ctx.IncrementRegistryKeys();
                var displayName = key.GetValue("DisplayName") as string ?? Path.GetFileName(installerPath);
                var installDate = key.GetValue("InstallDate") as string ?? "";

                ctx.AddFinding(new Finding
                {
                    Module = Name,
                    Title = $"Warzone-Cheat-Installer-Eintrag: {displayName}",
                    Risk = RiskLevel.High,
                    Location = $@"HKLM\{installerPath}",
                    Reason = $"Deinstallations-Eintrag '{displayName}' in der Registry deutet auf Installation eines Warzone-Cheat-Tools hin. " +
                             "Solche Eintraege bleiben oft auch nach der Deinstallation erhalten.",
                    Detail = $"DisplayName: {displayName} | InstallDate: {installDate}"
                });
            }
            catch { }
        }

        try
        {
            var muiCachePath = @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
            using var muiKey = Registry.CurrentUser.OpenSubKey(muiCachePath, writable: false);
            if (muiKey is not null)
            {
                foreach (var valueName in muiKey.GetValueNames())
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementRegistryKeys();

                    foreach (var pattern in CheatFilePatterns)
                    {
                        if (valueName.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            var displayName = muiKey.GetValue(valueName) as string ?? "";
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Warzone-Cheat in MUICache: {Path.GetFileName(valueName)}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{muiCachePath}",
                                Reason = $"MUICache-Eintrag deutet auf Ausfuehrung eines Warzone-Cheat-Programms hin: '{valueName}'. " +
                                         "MUICache speichert Programmtitel ausgefuehrter Anwendungen.",
                                Detail = $"Wert: {valueName} | Anzeigename: {displayName}"
                            });
                            break;
                        }
                    }

                    foreach (var tool in KnownCheatToolNames)
                    {
                        if (valueName.Contains(tool, StringComparison.OrdinalIgnoreCase))
                        {
                            var displayName = muiKey.GetValue(valueName) as string ?? "";
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Bekanntes Warzone-Cheat-Tool in MUICache: {tool}",
                                Risk = RiskLevel.High,
                                Location = $@"HKCU\{muiCachePath}",
                                Reason = $"MUICache-Eintrag '{valueName}' entspricht dem bekannten Warzone-Cheat-Tool '{tool}'. " +
                                         "Das Tool wurde auf diesem System ausgefuehrt.",
                                Detail = $"Tool: {tool} | Wert: {valueName} | Anzeigename: {displayName}"
                            });
                            break;
                        }
                    }
                }
            }
        }
        catch { }
    }, ct);

    private Task CheckPrefetchArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        const string prefetchDir = @"C:\Windows\Prefetch";
        if (!Directory.Exists(prefetchDir)) return;

        string[] pfFiles;
        try
        {
            pfFiles = Directory.GetFiles(prefetchDir, "*.pf");
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var pfFile in pfFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var pfName = Path.GetFileNameWithoutExtension(pfFile);
            var dashIdx = pfName.LastIndexOf('-');
            var exeName = dashIdx > 0 && pfName.Length - dashIdx == 9
                ? pfName[..dashIdx]
                : pfName;

            foreach (var cheatExe in PrefetchCheatExeNames)
            {
                if (exeName.Contains(cheatExe, StringComparison.OrdinalIgnoreCase))
                {
                    DateTime? lastRun = null;
                    try { lastRun = File.GetLastWriteTime(pfFile); } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Warzone-Cheat-Prefetch: {exeName}.exe",
                        Risk = RiskLevel.High,
                        Location = pfFile,
                        FileName = exeName + ".exe",
                        Reason = $"Prefetch-Datei '{pfName}.pf' belegt die Ausfuehrung von '{exeName}.exe', " +
                                 $"welches dem Warzone-Cheat-Muster '{cheatExe}' entspricht. " +
                                 "Prefetch-Eintraege bleiben auch nach dem Loeschen der ausfuehrbaren Datei erhalten.",
                        Detail = lastRun.HasValue
                            ? $"Prefetch-Datum: {lastRun.Value:yyyy-MM-dd HH:mm:ss} | Muster: {cheatExe}"
                            : $"Muster: {cheatExe}"
                    });
                    break;
                }
            }

            foreach (var tool in KnownCheatToolNames)
            {
                var toolNorm = tool.Replace(" ", "_").Replace(" ", "");
                if (exeName.Contains(toolNorm, StringComparison.OrdinalIgnoreCase) ||
                    exeName.Contains(tool.Replace(" ", ""), StringComparison.OrdinalIgnoreCase))
                {
                    DateTime? lastRun = null;
                    try { lastRun = File.GetLastWriteTime(pfFile); } catch { }

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Bekanntes Warzone-Cheat-Tool in Prefetch: {exeName}",
                        Risk = RiskLevel.High,
                        Location = pfFile,
                        FileName = exeName + ".exe",
                        Reason = $"Prefetch-Eintrag '{exeName}' entspricht dem bekannten Warzone-Cheat-Tool '{tool}'. " +
                                 "Die ausfuehrbare Datei wurde auf diesem System gestartet.",
                        Detail = lastRun.HasValue
                            ? $"Tool: {tool} | Datum: {lastRun.Value:yyyy-MM-dd HH:mm:ss}"
                            : $"Tool: {tool}"
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckUserAssistArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        const string userAssistBase = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

        try
        {
            using var baseKey = Registry.CurrentUser.OpenSubKey(userAssistBase, writable: false);
            if (baseKey is null) return;

            foreach (var guidName in baseKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;

                try
                {
                    using var countKey = baseKey.OpenSubKey($@"{guidName}\Count", writable: false);
                    if (countKey is null) continue;

                    foreach (var encodedName in countKey.GetValueNames())
                    {
                        if (ct.IsCancellationRequested) return;
                        ctx.IncrementRegistryKeys();

                        var decoded = Rot13Decode(encodedName).ToLowerInvariant();

                        bool matched = false;
                        foreach (var keyword in UserAssistCheatKeywords)
                        {
                            if (decoded.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                            {
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
                                    Title = $"Warzone-Cheat in UserAssist: {keyword}",
                                    Risk = RiskLevel.High,
                                    Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                    FileName = Path.GetFileName(decoded),
                                    Reason = $"UserAssist-Eintrag belegt die Ausfuehrung von '{Path.GetFileName(decoded)}' " +
                                             $"({runCount}x ausgefuehrt" +
                                             (lastRun.HasValue ? $", zuletzt {lastRun.Value:yyyy-MM-dd HH:mm} UTC" : "") +
                                             $"). Warzone-Cheat-Schluesselbegriff: '{keyword}'. " +
                                             "UserAssist-Eintraege persistieren auch nach dem Loeschen der Datei.",
                                    Detail = $"Dekodiert: {decoded} | Ausfuehrungen: {runCount} | " +
                                             $"Zuletzt: {(lastRun.HasValue ? lastRun.Value.ToString("O") : "unbekannt")}"
                                });
                                matched = true;
                                break;
                            }
                        }

                        if (!matched)
                        {
                            foreach (var tool in KnownCheatToolNames)
                            {
                                var toolNorm = tool.Replace(" ", "").ToLowerInvariant();
                                if (decoded.Contains(toolNorm, StringComparison.OrdinalIgnoreCase))
                                {
                                    ctx.AddFinding(new Finding
                                    {
                                        Module = Name,
                                        Title = $"Bekanntes Warzone-Cheat-Tool in UserAssist: {tool}",
                                        Risk = RiskLevel.High,
                                        Location = $@"HKCU\{userAssistBase}\{guidName}\Count",
                                        FileName = Path.GetFileName(decoded),
                                        Reason = $"UserAssist-Eintrag '{Path.GetFileName(decoded)}' entspricht dem bekannten Warzone-Cheat-Tool '{tool}'. " +
                                                 "Das Tool wurde auf diesem System ausgefuehrt.",
                                        Detail = $"Tool: {tool} | Dekodiert: {decoded}"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }, ct);

    private Task CheckLogFileArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var logSearchRoots = new List<string>();
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var temp = Path.GetTempPath();

        logSearchRoots.Add(localAppData);
        logSearchRoots.Add(appData);
        logSearchRoots.Add(temp);
        logSearchRoots.Add(Path.Combine(userProfile, "Documents", "Call of Duty"));
        logSearchRoots.Add(Path.Combine(userProfile, "Documents", "Call of Duty Modern Warfare"));
        logSearchRoots.Add(Path.Combine(userProfile, "Documents", "Call of Duty Modern Warfare II"));
        logSearchRoots.Add(Path.Combine(userProfile, "Documents", "Call of Duty Modern Warfare III"));
        logSearchRoots.Add(Path.Combine(localAppData, "Activision"));
        logSearchRoots.Add(Path.Combine(localAppData, "Battle.net"));

        foreach (var root in logSearchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            string[] logFiles;
            try
            {
                logFiles = Directory.GetFiles(root, "*.log", SearchOption.AllDirectories);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var logFile in logFiles)
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementFiles();

                FileInfo fi;
                try { fi = new FileInfo(logFile); } catch { continue; }
                if (fi.Length > 10 * 1024 * 1024) continue;

                string content;
                try
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var sr = new StreamReader(fs);
                    content = await sr.ReadToEndAsync(ct);
                }
                catch (IOException) { continue; }

                foreach (var keyword in LogKeywords)
                {
                    if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Warzone-Cheat-Schluesselbegriff in Log: {keyword}",
                            Risk = RiskLevel.Medium,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"Log-Datei '{Path.GetFileName(logFile)}' enthaelt Warzone-Cheat-Schluesselbegriff '{keyword}'. " +
                                     "Dies kann auf die Nutzung oder Installation eines Warzone-Cheats hinweisen.",
                            Detail = $"Keyword: {keyword} | Datei: {logFile}"
                        });
                        break;
                    }
                }

                foreach (var tool in KnownCheatToolNames)
                {
                    if (content.Contains(tool, StringComparison.OrdinalIgnoreCase))
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Warzone-Cheat-Tool in Log erwaehnt: {tool}",
                            Risk = RiskLevel.Medium,
                            Location = logFile,
                            FileName = Path.GetFileName(logFile),
                            Reason = $"Log-Datei '{Path.GetFileName(logFile)}' erwaehnt das bekannte Warzone-Cheat-Tool '{tool}'. " +
                                     "Cheat-Loader und -Injektoren schreiben oft Log-Dateien.",
                            Detail = $"Tool: {tool} | Datei: {logFile}"
                        });
                        break;
                    }
                }
            }
        }
    }, ct);

    private Task CheckDiscordArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var discordClients = new[] { "discord", "discordptb", "discordcanary" };

        foreach (var client in discordClients)
        {
            if (ct.IsCancellationRequested) return;

            var discordRoot = Path.Combine(roaming, client);
            if (!Directory.Exists(discordRoot)) continue;

            var searchDirs = new[]
            {
                Path.Combine(discordRoot, "Local Storage", "leveldb"),
                Path.Combine(discordRoot, "Cache", "Cache_Data"),
                Path.Combine(discordRoot, "Cache"),
                Path.Combine(discordRoot, "Session Storage"),
            };

            foreach (var searchDir in searchDirs)
            {
                if (ct.IsCancellationRequested) return;
                if (!Directory.Exists(searchDir)) continue;

                string[] cacheFiles;
                try
                {
                    cacheFiles = Directory.GetFiles(searchDir);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var cacheFile in cacheFiles.Take(100))
                {
                    if (ct.IsCancellationRequested) return;

                    FileInfo fi;
                    try { fi = new FileInfo(cacheFile); } catch { continue; }
                    if (fi.Length > 8 * 1024 * 1024) continue;

                    byte[] bytes;
                    try { bytes = await File.ReadAllBytesAsync(cacheFile, ct); }
                    catch (IOException) { continue; }

                    var text = Encoding.GetEncoding("ISO-8859-1").GetString(bytes);

                    foreach (var keyword in DiscordKeywords)
                    {
                        if (text.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Warzone-Cheat-Schluesselbegriff im Discord-Cache: {keyword}",
                                Risk = RiskLevel.Medium,
                                Location = cacheFile,
                                FileName = Path.GetFileName(cacheFile),
                                Reason = $"Discord-Cache-Datei enthaelt den Warzone-Cheat-Schluesselbegriff '{keyword}'. " +
                                         $"Discord-Client: {client}. " +
                                         "Dies kann auf Mitgliedschaft in Warzone-Cheat-Servern oder Cheat-Diskussionen hinweisen.",
                                Detail = $"Keyword: {keyword} | Client: {client} | Cache: {searchDir}"
                            });
                            break;
                        }
                    }
                }
            }
        }
    }, ct);

    private Task CheckSuspiciousScripts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var searchRoots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
        };

        var scriptExtensions = new[] { ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf" };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            foreach (var ext in scriptExtensions)
            {
                string[] scriptFiles;
                try
                {
                    scriptFiles = Directory.GetFiles(root, $"*{ext}", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var scriptFile in scriptFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();

                    var fn = Path.GetFileName(scriptFile);

                    bool nameMatch = false;
                    foreach (var pattern in CheatFilePatterns)
                    {
                        if (fn.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Warzone-Cheat-Skript (Name): {fn}",
                                Risk = RiskLevel.High,
                                Location = scriptFile,
                                FileName = fn,
                                Reason = $"Skriptdatei '{fn}' entspricht dem Warzone-Cheat-Namensmuster '{pattern}'. " +
                                         "Cheat-Tools verwenden Batch- und PowerShell-Skripte zur Installation und Umgehung.",
                                Detail = $"Muster: {pattern} | Erweiterung: {ext}"
                            });
                            nameMatch = true;
                            break;
                        }
                    }

                    if (nameMatch) continue;

                    FileInfo fi;
                    try { fi = new FileInfo(scriptFile); } catch { continue; }
                    if (fi.Length > 2 * 1024 * 1024) continue;

                    string content;
                    try
                    {
                        using var fs = new FileStream(scriptFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        using var sr = new StreamReader(fs);
                        content = await sr.ReadToEndAsync(ct);
                    }
                    catch (IOException) { continue; }

                    bool hasCodRef = false;
                    foreach (var codKeyword in SuspiciousScriptKeywords)
                    {
                        if (content.Contains(codKeyword, StringComparison.OrdinalIgnoreCase))
                        {
                            hasCodRef = true;
                            break;
                        }
                    }

                    if (!hasCodRef) continue;

                    bool hasCheatKeyword = false;
                    string? matchedCheatKw = null;
                    foreach (var cheatKw in new[] { "bypass", "inject", "hack", "cheat", "esp", "aimbot", "spoof", "patch" })
                    {
                        if (content.Contains(cheatKw, StringComparison.OrdinalIgnoreCase))
                        {
                            hasCheatKeyword = true;
                            matchedCheatKw = cheatKw;
                            break;
                        }
                    }

                    if (hasCheatKeyword)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Verdaechtiges Skript mit COD/Warzone- und Cheat-Begriffen: {fn}",
                            Risk = RiskLevel.Medium,
                            Location = scriptFile,
                            FileName = fn,
                            Reason = $"Skriptdatei '{fn}' enthaelt sowohl COD/Warzone-Verweise als auch den Cheat-Begriff '{matchedCheatKw}'. " +
                                     "Suspicious scripts targeting Warzone directories may be cheat installers or bypass tools.",
                            Detail = $"Cheat-Begriff: {matchedCheatKw} | Skript: {scriptFile}"
                        });
                    }
                }
            }
        }
    }, ct);

    private Task CheckMemoryDumpArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var searchRoots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        var dumpExtensions = new[] { "*.dmp", "*.mdmp", "*.dump" };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            foreach (var ext in dumpExtensions)
            {
                string[] dumpFiles;
                try
                {
                    dumpFiles = Directory.GetFiles(root, ext, SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var dumpFile in dumpFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(dumpFile);

                    bool matchesCod = false;
                    foreach (var procKw in WarzoneProcessDumpKeywords)
                    {
                        if (fn.Contains(procKw, StringComparison.OrdinalIgnoreCase))
                        {
                            matchesCod = true;
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"COD/Warzone-Prozess-Dump: {fn}",
                                Risk = RiskLevel.High,
                                Location = dumpFile,
                                FileName = fn,
                                Reason = $"Speicher-Dump-Datei '{fn}' enthaelt den COD/Warzone-Prozessnamen '{procKw}'. " +
                                         "Cheat-Tools erstellen oft Speicher-Dumps von Spielprozessen um Offsets und Adressen zu extrahieren.",
                                Detail = $"Prozess-Keyword: {procKw} | Dump: {dumpFile}"
                            });
                            break;
                        }
                    }

                    if (!matchesCod)
                    {
                        foreach (var pattern in CheatFilePatterns)
                        {
                            if (fn.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                ctx.AddFinding(new Finding
                                {
                                    Module = Name,
                                    Title = $"Cheat-bezogener Speicher-Dump: {fn}",
                                    Risk = RiskLevel.High,
                                    Location = dumpFile,
                                    FileName = fn,
                                    Reason = $"Speicher-Dump '{fn}' entspricht dem Warzone-Cheat-Muster '{pattern}'. " +
                                             "Moegliches Artefakt einer Cheat-Tool-Analyse oder Entwicklung.",
                                    Detail = $"Muster: {pattern}"
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
    }, ct);

    private Task CheckCheatEngineTables(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var searchRoots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Cheat Engine"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "My Cheat Tables"),
        };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            foreach (var ext in CheatEngineSaveExtensions)
            {
                string[] ctFiles;
                try
                {
                    ctFiles = Directory.GetFiles(root, $"*{ext}", SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var ctFile in ctFiles)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(ctFile);

                    bool isCodTable = false;
                    foreach (var procKw in WarzoneProcessDumpKeywords)
                    {
                        if (fn.Contains(procKw, StringComparison.OrdinalIgnoreCase))
                        {
                            isCodTable = true;
                            break;
                        }
                    }

                    if (!isCodTable)
                    {
                        foreach (var pattern in CheatFilePatterns)
                        {
                            if (fn.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                            {
                                isCodTable = true;
                                break;
                            }
                        }
                    }

                    if (!isCodTable)
                    {
                        FileInfo fi;
                        try { fi = new FileInfo(ctFile); } catch { continue; }
                        if (fi.Length < 5 * 1024 * 1024)
                        {
                            string content;
                            try
                            {
                                using var fs = new FileStream(ctFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                using var sr = new StreamReader(fs);
                                content = await sr.ReadToEndAsync(ct);
                            }
                            catch (IOException) { continue; }

                            foreach (var procKw in WarzoneProcessDumpKeywords)
                            {
                                if (content.Contains(procKw, StringComparison.OrdinalIgnoreCase))
                                {
                                    isCodTable = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (isCodTable)
                    {
                        ctx.AddFinding(new Finding
                        {
                            Module = Name,
                            Title = $"Cheat-Engine-Tabelle fuer COD/Warzone: {fn}",
                            Risk = RiskLevel.High,
                            Location = ctFile,
                            FileName = fn,
                            Reason = $"Cheat-Engine-Tabelle '{fn}' ist mit einem Call of Duty / Warzone-Prozess verknuepft. " +
                                     "Cheat-Engine-Tabellen enthalten Speicheradressen und Cheat-Codes fuer Spiele.",
                            Detail = $"Erweiterung: {ext} | Pfad: {ctFile}"
                        });
                    }
                }
            }
        }

        var ceDocPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Cheat Engine");
        if (Directory.Exists(ceDocPath))
        {
            ctx.AddFinding(new Finding
            {
                Module = Name,
                Title = "Cheat-Engine-Dokumentenordner gefunden",
                Risk = RiskLevel.Medium,
                Location = ceDocPath,
                Reason = "Der Cheat-Engine-Dokumentenordner existiert. Cheat-Engine wird haeufig verwendet " +
                         "um Spielprozesse wie Call of Duty Warzone zu manipulieren.",
                Detail = $"Pfad: {ceDocPath}"
            });
        }
    }, ct);

    private Task CheckDriverServiceArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var ricochetBypassIndicators = new[]
        {
            "ricochet_bypass", "ricochet_hook", "ricochet_patch",
            "ricochet_spoof", "anti_ricochet", "ricochet_kill",
            "cod_bypass", "wz_bypass", "warzone_bypass",
            "kernel_bypass_ricochet", "ricochet_kvm",
        };

        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services", writable: false);
            if (servicesKey is null) return;

            foreach (var svcName in servicesKey.GetSubKeyNames())
            {
                if (ct.IsCancellationRequested) return;
                ctx.IncrementRegistryKeys();

                bool isRicochetBypass = false;
                string? matchedIndicator = null;

                foreach (var indicator in ricochetBypassIndicators)
                {
                    if (svcName.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                    {
                        isRicochetBypass = true;
                        matchedIndicator = indicator;
                        break;
                    }
                }

                if (!isRicochetBypass) continue;

                try
                {
                    using var svcKey = servicesKey.OpenSubKey(svcName, writable: false);
                    if (svcKey is null) continue;

                    var imagePath = svcKey.GetValue("ImagePath") as string ?? "";
                    var startType = svcKey.GetValue("Start") as int? ?? -1;
                    var svcType = svcKey.GetValue("Type") as int? ?? 0;

                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Ricochet-Bypass-Dienst in Registry: {svcName}",
                        Risk = RiskLevel.Critical,
                        Location = $@"HKLM\SYSTEM\CurrentControlSet\Services\{svcName}",
                        Reason = $"Windows-Dienst '{svcName}' entspricht einem bekannten Ricochet Anti-Cheat Bypass-Tool (Indikator: '{matchedIndicator}'). " +
                                 $"Starttyp: {startType}, Dienst-Typ: {svcType}. " +
                                 "Ricochet-Bypass-Dienste erlauben Cheats trotz aktivem Anti-Cheat.",
                        Detail = $"ImagePath: {imagePath} | StartType: {startType} | Type: {svcType}"
                    });
                }
                catch { }
            }
        }
        catch { }

        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var driversDir = Path.Combine(system32, "drivers");
        if (!Directory.Exists(driversDir)) return;

        string[] driverFiles;
        try
        {
            driverFiles = Directory.GetFiles(driversDir, "*.sys");
        }
        catch (UnauthorizedAccessException) { return; }
        catch (IOException) { return; }

        foreach (var driverFile in driverFiles)
        {
            if (ct.IsCancellationRequested) return;
            ctx.IncrementFiles();
            var fn = Path.GetFileName(driverFile);

            foreach (var indicator in ricochetBypassIndicators)
            {
                if (fn.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                {
                    ctx.AddFinding(new Finding
                    {
                        Module = Name,
                        Title = $"Ricochet-Bypass-Treiber in System32: {fn}",
                        Risk = RiskLevel.Critical,
                        Location = driverFile,
                        FileName = fn,
                        Reason = $"Kernel-Treiber '{fn}' entspricht dem Ricochet-Bypass-Indikator '{indicator}'. " +
                                 "Dieser Treiber ermoeglicht das Umgehen des Ricochet-Anti-Cheat-Systems.",
                        Detail = $"Indikator: {indicator} | Pfad: {driverFile}"
                    });
                    break;
                }
            }
        }
    }, ct);

    private Task CheckTempAndDownloadDirs(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        var searchRoots = new[]
        {
            Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
        };

        var executableExtensions = new[] { "*.exe", "*.dll", "*.sys", "*.zip", "*.rar", "*.7z" };

        foreach (var root in searchRoots)
        {
            if (ct.IsCancellationRequested) return;
            if (!Directory.Exists(root)) continue;

            foreach (var ext in executableExtensions)
            {
                string[] files;
                try
                {
                    files = Directory.GetFiles(root, ext, SearchOption.TopDirectoryOnly);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var file in files)
                {
                    if (ct.IsCancellationRequested) return;
                    ctx.IncrementFiles();
                    var fn = Path.GetFileName(file);

                    foreach (var pattern in CheatFilePatterns)
                    {
                        if (fn.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Warzone-Cheat-Datei in Temp/Downloads: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Datei '{fn}' in Temp- oder Download-Verzeichnis entspricht dem Warzone-Cheat-Muster '{pattern}'. " +
                                         "Cheat-Tools werden oft heruntergeladen und in temporaere Ordner entpackt.",
                                Detail = $"Muster: {pattern} | Ordner: {root}"
                            });
                            break;
                        }
                    }

                    foreach (var tool in KnownCheatToolNames)
                    {
                        var toolNorm = tool.Replace(" ", "_");
                        if (fn.Contains(tool, StringComparison.OrdinalIgnoreCase) ||
                            fn.Contains(toolNorm, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Warzone-Cheat-Tool in Temp/Downloads: {fn}",
                                Risk = RiskLevel.High,
                                Location = file,
                                FileName = fn,
                                Reason = $"Datei '{fn}' entspricht dem bekannten Warzone-Cheat-Tool '{tool}' und wurde in einem temporaeren Verzeichnis gefunden. " +
                                         "Cheat-Loader werden typischerweise heruntergeladen und temporaer gespeichert.",
                                Detail = $"Tool: {tool} | Ordner: {root}"
                            });
                            break;
                        }
                    }
                }
            }
        }
    }, ct);

    private Task CheckRecycleBinArtifacts(ScanContext ctx, CancellationToken ct) => Task.Run(async () =>
    {
        await Task.Yield();

        foreach (var drive in GetFixedDrives())
        {
            if (ct.IsCancellationRequested) return;

            var recycleBinPath = Path.Combine(drive, "$Recycle.Bin");
            if (!Directory.Exists(recycleBinPath)) continue;

            string[] sidDirs;
            try
            {
                sidDirs = Directory.GetDirectories(recycleBinPath);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (IOException) { continue; }

            foreach (var sidDir in sidDirs)
            {
                if (ct.IsCancellationRequested) return;

                string[] metaFiles;
                try
                {
                    metaFiles = Directory.GetFiles(sidDir, "$I*");
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (IOException) { continue; }

                foreach (var metaFile in metaFiles)
                {
                    if (ct.IsCancellationRequested) return;

                    var (origPath, deletedTime) = ParseRecycleBinMeta(metaFile);
                    if (string.IsNullOrEmpty(origPath)) continue;

                    var fileName = SafeGetFileName(origPath!);

                    foreach (var pattern in CheatFilePatterns)
                    {
                        if (fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                            origPath!.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Warzone-Cheat-Datei im Papierkorb: {fileName}",
                                Risk = RiskLevel.High,
                                Location = origPath!,
                                FileName = fileName,
                                Reason = $"Geloeschte Datei '{fileName}' im Papierkorb entspricht dem Warzone-Cheat-Muster '{pattern}'. " +
                                         (deletedTime is not null ? $"Geloescht am: {deletedTime}. " : "") +
                                         "Die Datei ist moeglicherweise wiederherstellbar.",
                                Detail = $"Originalname: {origPath} | Papierkorb: {sidDir}"
                            });
                            break;
                        }
                    }

                    foreach (var tool in KnownCheatToolNames)
                    {
                        if (fileName.Contains(tool, StringComparison.OrdinalIgnoreCase) ||
                            origPath!.Contains(tool, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx.AddFinding(new Finding
                            {
                                Module = Name,
                                Title = $"Bekanntes Warzone-Cheat-Tool im Papierkorb: {fileName}",
                                Risk = RiskLevel.High,
                                Location = origPath!,
                                FileName = fileName,
                                Reason = $"Geloeschte Datei '{fileName}' im Papierkorb entspricht dem bekannten Warzone-Cheat-Tool '{tool}'. " +
                                         (deletedTime is not null ? $"Geloescht am: {deletedTime}." : ""),
                                Detail = $"Tool: {tool} | Original: {origPath}"
                            });
                            break;
                        }
                    }
                }
            }
        }
    }, ct);

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

    private static (string? path, string? deletedTime) ParseRecycleBinMeta(string metaPath)
    {
        try
        {
            var bytes = File.ReadAllBytes(metaPath);
            if (bytes.Length < 28) return (null, null);

            string? deletedTime = null;
            try
            {
                long ft = BitConverter.ToInt64(bytes, 16);
                if (ft > 0) deletedTime = DateTime.FromFileTime(ft).ToString("yyyy-MM-dd HH:mm");
            }
            catch { }

            long version = BitConverter.ToInt64(bytes, 0);
            string path;
            if (version == 2)
            {
                int nameLen = BitConverter.ToInt32(bytes, 24);
                int byteLen = Math.Max(0, (nameLen - 1) * 2);
                if (28 + byteLen > bytes.Length) byteLen = Math.Max(0, bytes.Length - 28);
                path = Encoding.Unicode.GetString(bytes, 28, byteLen);
            }
            else
            {
                int len = Math.Min(520, bytes.Length - 24);
                path = Encoding.Unicode.GetString(bytes, 24, len).TrimEnd('\0');
            }

            return (string.IsNullOrWhiteSpace(path) ? null : path, deletedTime);
        }
        catch { return (null, null); }
    }

    private static IEnumerable<string> GetFixedDrives()
    {
        DriveInfo[] drives;
        try { drives = DriveInfo.GetDrives(); }
        catch { yield break; }

        foreach (var drive in drives)
        {
            string? root = null;
            try
            {
                if (drive.DriveType == DriveType.Fixed && drive.IsReady)
                    root = drive.RootDirectory.FullName;
            }
            catch { }

            if (root is not null) yield return root;
        }
    }

    private static string SafeGetFileName(string path)
    {
        try { return Path.GetFileName(path.TrimEnd('\\', '/')); }
        catch { return path; }
    }
}
